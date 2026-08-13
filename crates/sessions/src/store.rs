//! Manages session state on disk.

use std::{
    collections::BTreeMap,
    io::ErrorKind::{AlreadyExists, NotFound},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use paths::{DaemonAbsPath, DaemonRelPath, sub_path};

use crate::{Record, SessionId};

/// Describes the session object yielded by [`Loader`].
pub trait SessionObject: Sized + Send + Clone + 'static + std::fmt::Debug {
    type Key: SessionKey;

    fn record(&self) -> &Record;
    fn refresh_from_record(&mut self, r: Record);

    fn key(&self) -> &Self::Key;
    fn workspace_path(&self) -> DaemonAbsPath;
    fn home_path(&self) -> DaemonAbsPath;
    fn cache_path(&self) -> DaemonAbsPath;
    /// Directory the daemon stages the client-uploaded
    /// composition patches into, ready for the launcher to
    /// materialize into the sandbox home. Each entry is stored
    /// under the patch's sandbox-home-relative destination path.
    fn patches_path(&self) -> DaemonAbsPath;
    /// Directory the daemon stages the client-uploaded external
    /// lifecycle-hook scripts into. Each entry is stored under the
    /// path [`staged_script_path`] derives from its hook's source, so
    /// the daemon can find a script again from the composition alone.
    ///
    /// Deliberately not under [`patches_path`](Self::patches_path):
    /// the whole patch tree is copied into the sandbox home when the
    /// session finalizes, and hook scripts are not dotfiles.
    ///
    /// [`staged_script_path`]: crate::core::lifecyclehook::staged_script_path
    fn hooks_path(&self) -> DaemonAbsPath;
}

/// Describes the primary key a [`Loader`] uses to reference
/// sessions.
pub trait SessionKey: Sized + Send + 'static + std::fmt::Debug + Clone + Eq + Ord {
    /// Returns the ID of the session.
    fn id(&self) -> &SessionId;
}

/// A type which can load sessions.
pub trait Loader {
    type Key: SessionKey;
    type Object: SessionObject<Key = Self::Key>;

    /// Lists all sessions known to this loader, by key.
    fn keys(&self) -> impl Iterator<Item = Self::Key>;

    /// Gets a session.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `key` is stale — its short is gone from the index, or
    ///   has been re-allocated to a different session (same semantics as
    ///   [`Self::save`]). Prevents reading an unrelated session's record.
    /// - Other I/O errors if the backing record cannot be read or deserialized.
    fn get(&self, key: &Self::Key) -> Result<Self::Object, std::io::Error>;

    /// Returns a lookup key corresponding to the given session ID, if
    /// a session with that ID is known.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the backing record cannot be read or
    /// deserialized.
    fn find_by_id(&self, id: &SessionId) -> Result<Option<Self::Key>, std::io::Error>;

    /// Returns a lookup key corresponding to the given session name, if
    /// a session with that name is known.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the backing record cannot be read or
    /// deserialized.
    fn find_by_name<S: AsRef<str>>(&self, name: S) -> Result<Option<Self::Key>, std::io::Error>;

    /// Creates a session using the given record.
    ///
    /// The id within the given record is ignored, and the
    /// actual ID is returned.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the session directory, record, or index
    /// cannot be written.
    fn create(&mut self, record: Record) -> Result<Self::Key, std::io::Error>;

    /// Overwrites the session at `key` with the given record.
    ///
    /// The record's `id` must match `key.id()` — id is the primary
    /// key, never changes after [`Self::create`]. Other fields
    /// (`name`, `status`, `policy`, `attrs`, …) are written verbatim;
    /// the store does not enforce state-machine transitions (e.g.
    /// `Pending` → `Active`), that policy belongs in higher layers.
    ///
    /// If `record.name` differs from the on-disk name, the name
    /// index is remapped; a name collision with a *different* session
    /// surfaces as `AlreadyExists`.
    ///
    /// # Errors
    ///
    /// - `InvalidInput` if `record.id != key.id()`.
    /// - `NotFound` if `key` is stale — its short is no longer in the
    ///   index (e.g. the session was deleted after the caller obtained
    ///   the key). Prevents silent resurrection of removed sessions.
    /// - `AlreadyExists` if `record.name` is taken by a different session.
    /// - Other I/O errors from writing the record or flushing the index.
    fn save(&mut self, key: &Self::Key, record: &Record) -> Result<(), std::io::Error>;

    /// Renames the session with the given key.
    ///
    /// Sugar for `get` → mutate `name` → [`Self::save`]; see `save`
    /// for the underlying write semantics.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the session directory, record, or index
    /// cannot be written.
    /// - `NotFound` if `key` is stale (same as [`Self::save`]); the
    ///   internal `get` may also surface `NotFound` when the record
    ///   file is gone.
    /// - `AlreadyExists` if a *different* session already has the
    ///   requested name; renaming to the session's current name is a
    ///   no-op.
    fn rename(&mut self, key: &Self::Key, new_name: String) -> Result<(), std::io::Error>;

    /// Deletes the session with the given key, dropping its index entries and
    /// removing its on-disk directory tree (record, workspace, home, cache).
    ///
    /// Crash-safe: if the daemon dies mid-call, the next loader open
    /// (e.g. [`DiskLoader::new`]) reaps the half-deleted session dir,
    /// so a missing index entry is the only persistent visible effect
    /// of a successful or partial delete.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `key` is stale — its short is gone from the index, or
    ///   has been re-allocated to a different session (same semantics as
    ///   [`Self::save`]). Prevents destroying an unrelated session. A missing
    ///   *directory tree* for a still-indexed key is not an error.
    /// - Other I/O errors if the record cannot be read or the index cannot be
    ///   flushed.
    fn delete(&mut self, key: &Self::Key) -> Result<(), std::io::Error>;

    /// Loads the persisted composition snapshot for the session at
    /// `key`, if one exists. Returns `Ok(None)` when the sidecar is
    /// absent (a session that predates the sidecar, or whose
    /// composition was never assembled). A corrupt or unreadable
    /// sidecar surfaces as an error so the caller can log it and
    /// decide on a fallback.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `key` is stale (same semantics as [`Self::save`]).
    /// - I/O or deserialization errors if the sidecar exists but
    ///   cannot be read or parsed.
    fn load_composition(
        &self,
        key: &Self::Key,
    ) -> Result<Option<crate::core::compose::Composition>, std::io::Error>;

    /// Atomically persists the composition snapshot for the session
    /// at `key` (tmp + rename, same crash-safety as [`Self::save`]).
    /// Called at composition-assembly time so a restart can re-apply
    /// the exact composition that was approved at `min session activate` time.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `key` is stale (same semantics as [`Self::save`]).
    /// - I/O or serialization errors if the sidecar cannot be written.
    fn store_composition(
        &self,
        key: &Self::Key,
        composition: &crate::core::compose::Composition,
    ) -> Result<(), std::io::Error>;
}

/// The concrete key used to identify sessions from [`DiskLoader`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiskSessionKey {
    session_id: SessionId,
    dir_key: DaemonRelPath,
}

impl SessionKey for DiskSessionKey {
    fn id(&self) -> &SessionId {
        &self.session_id
    }
}

/// The concrete session object from [`DiskLoader`].
#[derive(Debug, Clone)]
pub struct DiskSession {
    key: DiskSessionKey,
    minimal_state_dir: DaemonAbsPath,
    record: Record,
}

impl DiskSession {
    fn root_path(&self) -> DaemonAbsPath {
        sub_path!(self.minimal_state_dir, "sessions")
            .join(&DaemonRelPath::try_new(&self.key.dir_key).unwrap())
    }
}

impl SessionObject for DiskSession {
    type Key = DiskSessionKey;

    fn record(&self) -> &Record {
        &self.record
    }
    fn refresh_from_record(&mut self, r: Record) {
        let id = self.record.id;
        self.record = r;
        self.record.id = id; // ID must never change
    }

    fn key(&self) -> &DiskSessionKey {
        &self.key
    }
    fn workspace_path(&self) -> DaemonAbsPath {
        sub_path!(self.root_path(), "tree")
    }
    fn home_path(&self) -> DaemonAbsPath {
        sub_path!(self.root_path(), "home")
    }
    fn cache_path(&self) -> DaemonAbsPath {
        sub_path!(self.root_path(), "cache")
    }
    fn patches_path(&self) -> DaemonAbsPath {
        sub_path!(self.root_path(), "patches")
    }
    fn hooks_path(&self) -> DaemonAbsPath {
        sub_path!(self.root_path(), "hooks")
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Index {
    short_to_id: BTreeMap<String, SessionId>,
    name_to_id: BTreeMap<String, SessionId>,
}

impl Index {
    pub fn insert(&mut self, short: String, id: SessionId, name: Option<String>) {
        self.short_to_id.insert(short, id);
        if let Some(name) = name {
            self.name_to_id.insert(name, id);
        }
    }

    /// Removes a session's entries from both the short and name indexes.
    pub fn remove(&mut self, short: &str, name: Option<&str>) {
        self.short_to_id.remove(short);
        if let Some(name) = name {
            self.name_to_id.remove(name);
        }
    }

    /// Iterates over all (shortname, session id) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SessionId)> {
        self.short_to_id.iter()
    }

    /// Returns the session ID corresponding to the given session name, if known.
    pub fn find_by_name<S: AsRef<str>>(&self, name: S) -> Option<&SessionId> {
        self.name_to_id.get(name.as_ref())
    }

    /// Returns the session ID corresponding to the given short name, if known.
    pub fn find_by_short<S: AsRef<str>>(&self, name: S) -> Option<&SessionId> {
        self.short_to_id.get(name.as_ref())
    }

    /// Returns the short corresponding to the given session ID, if known.
    pub fn short_by_id(&self, id: &SessionId) -> Option<&String> {
        self.short_to_id
            .iter()
            .find(|(_short, iter_id)| *iter_id == id)
            .map(|(short, _)| short)
    }

    /// Returns the name corresponding to the given session ID, if it has one.
    pub fn name_by_id(&self, id: &SessionId) -> Option<&String> {
        self.name_to_id
            .iter()
            .find(|(_name, iter_id)| *iter_id == id)
            .map(|(name, _)| name)
    }
}

/// Pass B's per-entry decision. `Skip` for transient I/O errors;
/// `DropMissing` for `NotFound` and unparseable records.
enum ReconcileFix {
    DropMissing,
    Skip {
        reason: std::io::Error,
    },
    UpdateName {
        old_name: Option<String>,
        new_name: Option<String>,
    },
}

/// Prefix for delete-tombstone marker files, placed alongside
/// (not inside) the target session dir.
const TOMBSTONE_PREFIX: &str = ".deleting-";

/// Build the tombstone marker file name for a given short.
fn tombstone_name(short: &str) -> String {
    format!("{TOMBSTONE_PREFIX}{short}")
}

/// True when `short` matches `DiskLoader::create`'s format: exactly
/// 5 lowercase hex characters. Tombstone reaping refuses any other
/// shape to bound `remove_dir_all` to intended session dirs.
fn is_valid_short(short: &str) -> bool {
    short.len() == 5
        && short
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Read `record_file` and compare its name against `index_name` to
/// decide what pass B should do with this index entry. Returns `None`
/// when the record exists, parses, and agrees with the index.
fn classify_record_for_reconcile(
    record_file: &camino::Utf8Path,
    index_name: Option<String>,
) -> Option<ReconcileFix> {
    let file = match std::fs::File::open(record_file) {
        Ok(f) => f,
        Err(e) if e.kind() == NotFound => return Some(ReconcileFix::DropMissing),
        // Transient I/O failure: leave the entry alone, retry next startup.
        Err(reason) => return Some(ReconcileFix::Skip { reason }),
    };
    // Distinguish I/O failure (transient — skip, retry next startup) from
    // syntactic/data corruption (definitive — DropMissing so the index
    // doesn't keep pointing at unreadable content).
    let record: Record = match serde_json_lenient::from_reader(file) {
        Ok(r) => r,
        Err(e) if e.is_io() => return Some(ReconcileFix::Skip { reason: e.into() }),
        Err(_) => return Some(ReconcileFix::DropMissing),
    };
    if record.name == index_name {
        return None;
    }
    Some(ReconcileFix::UpdateName {
        old_name: index_name,
        new_name: record.name,
    })
}

/// Enumerate the immediate session subdirectories under `sessions_dir`.
/// Missing dir is treated as empty (the parent `DiskLoader::new` has
/// already ensured the dir exists, but a race during init is harmless).
fn enumerate_session_dirs(
    sessions_dir: &camino::Utf8Path,
) -> Result<Vec<(String, std::path::PathBuf)>, std::io::Error> {
    match std::fs::read_dir(sessions_dir) {
        Ok(rd) => Ok(rd
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                Some((name, e.path()))
            })
            .collect()),
        Err(e) if e.kind() == NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// A loader of session state based on <minimal-state-dir>/sessions.
///
/// ./index.json maps short directory names to session UUIDs. Typically
/// short directory names are the last few characters of the UUID, but
/// thats not a guarantee.
///
/// ./<short-dir-name>/record.json is the session record.
pub struct DiskLoader {
    minimal_dir: DaemonAbsPath,
    /// Keeps track of a mapping from shortname to UUID, as well as name to UUID.
    /// Always kept up to date.
    index: Index,
}

impl DiskLoader {
    /// Open (or initialize) a disk-backed session store rooted at
    /// `<minimal_dir>/sessions`, running a self-heal pass so
    /// [`Loader::create`], [`Loader::rename`], and [`Loader::delete`]
    /// tolerate a daemon crash at any point.
    ///
    /// Self-heal runs three passes: tombstone reap (finish deletes
    /// interrupted mid-flight), index-vs-record reconciliation
    /// (records are source of truth for name), and orphan re-index
    /// (add sessions whose records parse but aren't indexed).
    ///
    /// # Errors
    ///
    /// I/O error if the sessions directory can't be created or
    /// `index.json` can't be read.
    pub fn new(minimal_dir: DaemonAbsPath) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(minimal_dir.as_utf8_path().join("sessions"))?;
        let index_file = minimal_dir.as_utf8_path().join("sessions/index.json");
        let index = if std::fs::exists(&index_file)? {
            serde_json_lenient::from_reader(std::fs::File::open(index_file)?)?
        } else {
            Index::default()
        };

        let mut this = Self { minimal_dir, index };
        if this.self_heal()? {
            this.flush_index()?;
        }
        Ok(this)
    }

    /// Reconcile in-memory index state with on-disk record state.
    /// Returns `true` if any change was made (caller should flush).
    fn self_heal(&mut self) -> Result<bool, std::io::Error> {
        let sessions_dir = self.minimal_dir.as_utf8_path().join("sessions");

        let mut changed = false;
        let reaped = self.heal_reap_tombstones(&sessions_dir, &mut changed)?;
        // Enumerate session dirs *after* pass A so the orphan re-index in
        // pass C doesn't see dirs we just removed.
        let session_dirs = enumerate_session_dirs(&sessions_dir)?;
        self.heal_reconcile_index(&sessions_dir, &mut changed);
        self.heal_reindex_orphans(&session_dirs, &reaped, &mut changed);
        Ok(changed)
    }

    /// Pass A: reap any session dir whose external `.deleting-<short>`
    /// tombstone is present in `sessions_dir`. Removes the dir,
    /// then the marker (so a retry on a subsequent crash converges).
    /// Drops any matching index entry. Returns the set of shorts
    /// successfully reaped so pass C skips them.
    fn heal_reap_tombstones(
        &mut self,
        sessions_dir: &camino::Utf8Path,
        changed: &mut bool,
    ) -> Result<std::collections::HashSet<String>, std::io::Error> {
        let mut reaped = std::collections::HashSet::new();
        let entries = match std::fs::read_dir(sessions_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == NotFound => return Ok(reaped),
            Err(e) => return Err(e),
        };
        for entry in entries.filter_map(Result::ok) {
            // Tombstones are always regular files. Skipping non-files
            // here means a hand-created directory like `.deleting-foo`
            // doesn't get processed (which would warn-loop forever on
            // the `remove_file` of a directory).
            if !entry.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let Ok(fname) = entry.file_name().into_string() else {
                continue;
            };
            let Some(short) = fname.strip_prefix(TOMBSTONE_PREFIX) else {
                continue;
            };
            // Refuse to act on hand-crafted markers whose suffix doesn't
            // match the create()-produced short format. Without this,
            // `.deleting-` (empty), `.deleting-..`, etc. would redirect
            // `remove_dir_all` to the parent or sessions dir itself.
            if !is_valid_short(short) {
                tracing::warn!(
                    short = %short,
                    "tombstone marker with malformed short suffix; refusing to act on it",
                );
                continue;
            }
            let short = short.to_owned();
            // Record the short as tombstoned *before* any cleanup attempt.
            // Pass C consults this set to decide whether to re-index, so
            // even if `remove_dir_all` fails this cycle, the still-present
            // `record.json` won't be silently "undeleted" by pass C.
            // Failure paths below preserve this state.
            reaped.insert(short.clone());
            let doomed_dir = sessions_dir.join(&short);
            tracing::info!(short = %short, "reaping tombstoned session dir");
            match std::fs::remove_dir_all(doomed_dir.as_std_path()) {
                Ok(()) => {}
                Err(e) if e.kind() == NotFound => {}
                Err(e) => {
                    tracing::warn!(
                        short = %short,
                        error = %e,
                        "failed to reap tombstoned session dir; leaving marker for next startup",
                    );
                    // `reaped` already has this short — pass C will skip it.
                    continue;
                }
            }
            // Remove the tombstone marker last so a crash above leaves
            // the marker on disk for the next startup to retry.
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == NotFound => {}
                Err(e) => {
                    tracing::warn!(
                        short = %short,
                        error = %e,
                        "failed to remove tombstone marker; leaving for next startup",
                    );
                    // `reaped` already has this short — pass C will skip it.
                    continue;
                }
            }
            // An index entry may linger if delete crashed before flushing
            // the index. The record is gone, so look up the name from the
            // current in-memory index.
            if let Some(id) = self.index.short_to_id.get(&short).copied() {
                let name = self.index.name_by_id(&id).cloned();
                self.index.remove(&short, name.as_deref());
                *changed = true;
            }
        }
        Ok(reaped)
    }

    /// Pass B: reconcile each index entry against its record.json.
    /// The record is the source of truth — drop entries whose record
    /// is missing/unparseable; update name mappings when the record's
    /// `name` differs from the index's name for that id (rename-crash
    /// recovery).
    fn heal_reconcile_index(&mut self, sessions_dir: &camino::Utf8Path, changed: &mut bool) {
        let fixes: Vec<(String, SessionId, ReconcileFix)> = self
            .index
            .iter()
            .filter_map(|(short, id)| {
                let record_file = sessions_dir.join(short).join("record.json");
                let fix = classify_record_for_reconcile(
                    &record_file,
                    self.index.name_by_id(id).cloned(),
                )?;
                Some((short.clone(), *id, fix))
            })
            .collect();
        for (short, id, fix) in fixes {
            match fix {
                ReconcileFix::DropMissing => {
                    tracing::info!(
                        short = %short,
                        id = %id,
                        "dropping dangling index entry (record.json missing or unparseable)",
                    );
                    let name = self.index.name_by_id(&id).cloned();
                    self.index.remove(&short, name.as_deref());
                    *changed = true;
                }
                ReconcileFix::Skip { reason } => {
                    // The record may be readable on a future startup;
                    // leave the index entry alone for now.
                    tracing::warn!(
                        short = %short,
                        id = %id,
                        error = %reason,
                        "could not read record.json for reconcile; leaving index entry as-is",
                    );
                }
                ReconcileFix::UpdateName { old_name, new_name } => {
                    tracing::info!(
                        short = %short,
                        id = %id,
                        old_name = ?old_name,
                        new_name = ?new_name,
                        "reconciling index entry's name with record.json (rename-crash recovery)",
                    );
                    if let Some(old) = &old_name {
                        self.index.name_to_id.remove(old);
                    }
                    if let Some(new) = new_name {
                        self.index.name_to_id.insert(new, id);
                    }
                    *changed = true;
                }
            }
        }
    }

    /// Pass C: re-index orphan records (record.json present, no index
    /// entry, not already reaped). Orphans whose `name` collides with
    /// an existing index entry are skipped and logged.
    fn heal_reindex_orphans(
        &mut self,
        session_dirs: &[(String, std::path::PathBuf)],
        reaped: &std::collections::HashSet<String>,
        changed: &mut bool,
    ) {
        for (short, path) in session_dirs {
            if reaped.contains(short) || self.index.short_to_id.contains_key(short) {
                continue;
            }
            let record_file = path.join("record.json");
            let record: Record = match std::fs::File::open(&record_file)
                .and_then(|f| serde_json_lenient::from_reader(f).map_err(std::io::Error::from))
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        short = %short,
                        error = %e,
                        "found orphan session dir but record.json is missing or unparseable; \
                         leaving for manual triage",
                    );
                    continue;
                }
            };
            if self.index.short_by_id(&record.id).is_some() {
                tracing::warn!(
                    short = %short,
                    id = %record.id,
                    "orphan record's id collides with an existing index entry; \
                     leaving orphan unindexed for manual triage",
                );
                continue;
            }
            if let Some(name) = &record.name
                && self.index.name_to_id.contains_key(name)
            {
                tracing::warn!(
                    short = %short,
                    name = %name,
                    "orphan record's name collides with an existing index entry; \
                     leaving orphan unindexed for manual triage",
                );
                continue;
            }
            tracing::info!(
                short = %short,
                id = %record.id,
                "re-indexing orphan session record",
            );
            self.index.insert(short.clone(), record.id, record.name);
            *changed = true;
        }
    }

    /// Writes the in-memory index back to disk.
    ///
    /// The write is staged into a sibling temp file and then atomically
    /// renamed into place, so a crash mid-write can never leave a partially
    /// serialized `index.json` behind.
    fn flush_index(&self) -> Result<(), std::io::Error> {
        let sessions_dir = self.minimal_dir.as_utf8_path().join("sessions");
        let index_file = sessions_dir.join("index.json");
        let tmp_file = sessions_dir.join("index.json.tmp");

        let file = std::fs::File::create(&tmp_file)?;
        serde_json_lenient::to_writer(&file, &self.index)?;
        file.sync_all()?;
        drop(file);

        #[cfg(target_os = "linux")]
        common::renameat2::renameat2_cwd(tmp_file.as_std_path(), index_file.as_std_path(), 0)?;
        #[cfg(not(target_os = "linux"))]
        std::fs::rename(&tmp_file, &index_file)?;

        Ok(())
    }

    /// Writes the given session record to disk.
    ///
    /// The write is staged into a sibling temp file and then atomically
    /// renamed into place, so a crash mid-write can never leave a partially
    /// serialized `record.json` behind.
    fn write_record(&mut self, short: &String, record: &Record) -> Result<(), std::io::Error> {
        let session_dir = self.minimal_dir.as_utf8_path().join("sessions").join(short);
        std::fs::create_dir_all(&session_dir)?;
        let record_file = session_dir.join("record.json");
        let tmp_file = session_dir.join("record.json.tmp");

        let file = std::fs::File::create(&tmp_file)?;
        serde_json_lenient::to_writer(&file, &record)?;
        file.sync_all()?;
        drop(file);

        #[cfg(target_os = "linux")]
        common::renameat2::renameat2_cwd(tmp_file.as_std_path(), record_file.as_std_path(), 0)?;
        #[cfg(not(target_os = "linux"))]
        std::fs::rename(&tmp_file, &record_file)?;

        Ok(())
    }

    /// Resolve `key` to its live short directory name, or `NotFound` if the
    /// key is stale.
    ///
    /// A [`DiskSessionKey`] can outlive the session it names — a caller may
    /// hold a key (or a `SessionRecordHandle`) across a concurrent delete. A
    /// stale key is refused two ways:
    ///
    /// - its short is no longer in the index (the session was deleted), or
    /// - its short is present but now maps to a *different* id. The short is
    ///   the UUID's last 5 hex chars (20 bits) and is re-allocatable after a
    ///   delete, so a freed short can be handed to a new session.
    ///
    /// The id-strict second check is what stops a stale key from addressing
    /// the unrelated session that inherited its short — without it, [`get`]
    /// would read, and [`delete`] would destroy, the wrong session.
    ///
    /// [`get`]: Loader::get
    /// [`delete`]: Loader::delete
    fn live_short(&self, key: &DiskSessionKey) -> Result<String, std::io::Error> {
        let short = key.dir_key.to_string();
        match self.index.short_to_id.get(&short) {
            Some(stored_id) if stored_id == key.id() => Ok(short),
            _ => Err(std::io::Error::new(
                NotFound,
                format!(
                    "no session with key (short `{short}`, id `{}`) \
                     is present in the index",
                    key.id(),
                ),
            )),
        }
    }
}

/// Reject a session name that would break a downstream output contract.
///
/// `complete-session-str` emits one `value<TAB>description` line per session
/// and the `min ls` table renders the name verbatim; a control character —
/// tab or newline in particular — splits one row into several, and an empty
/// or whitespace-padded name is useless as an addressable handle. Enforced
/// here beside the name-collision check so both name writers (`create` for
/// `activate --name`, `save` for `rename`) share one gate.
fn validate_session_name(name: &str) -> Result<(), std::io::Error> {
    let invalid = |msg: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid session name: {msg}"),
        )
    };
    if name.trim().is_empty() {
        return Err(invalid("must not be empty or whitespace"));
    }
    if name.trim() != name {
        return Err(invalid("must not have leading or trailing whitespace"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("must not contain control characters"));
    }
    Ok(())
}

impl Loader for DiskLoader {
    type Key = DiskSessionKey;
    type Object = DiskSession;

    fn create(&mut self, mut record: Record) -> Result<Self::Key, std::io::Error> {
        if let Some(name) = &record.name {
            validate_session_name(name)?;
            if self.index.name_to_id.contains_key(name) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("a session with name `{name}` already exists"),
                ));
            }
        }

        let uuid = Uuid::now_v7();
        record.id = SessionId(uuid);

        let uuid_str = uuid.simple().to_string();
        let mut short = uuid_str[uuid_str.len() - 5..].to_string();
        // We got unlucky and the short name collided, 20 bits of entropy
        // so rare but very possible. Increment the short name past
        // any collisions in this case.
        while self.index.find_by_short(&short).is_some() {
            let n = u32::from_str_radix(&short, 16)
                .expect("short dir name is always 5 hex chars from a UUID suffix");
            short = format!("{:05x}", n.wrapping_add(1));
        }

        self.write_record(&short, &record)?;

        self.index
            .insert(short.clone(), SessionId(uuid), record.name);
        self.flush_index()?;

        Ok(DiskSessionKey {
            session_id: SessionId(uuid),
            dir_key: DaemonRelPath::try_new(short).unwrap(),
        })
    }

    fn keys(&self) -> impl Iterator<Item = Self::Key> {
        self.index.iter().map(|(short, id)| Self::Key {
            session_id: *id,
            dir_key: DaemonRelPath::try_new(short).unwrap(),
        })
    }

    fn find_by_id(&self, id: &SessionId) -> Result<Option<Self::Key>, std::io::Error> {
        Ok(self.index.short_by_id(id).map(|short| Self::Key {
            dir_key: DaemonRelPath::try_new(short).unwrap(),
            session_id: *id,
        }))
    }
    fn find_by_name<S: AsRef<str>>(&self, name: S) -> Result<Option<Self::Key>, std::io::Error> {
        match self.index.find_by_name(name) {
            Some(uuid) => self.find_by_id(uuid),
            None => Ok(None),
        }
    }

    fn get(&self, key: &Self::Key) -> Result<Self::Object, std::io::Error> {
        // Refuse a stale key (session deleted, or its short re-allocated to a
        // different session) with `NotFound` rather than reading the wrong
        // record. See `live_short`.
        let short = self.live_short(key)?;
        let record_file = self
            .minimal_dir
            .as_utf8_path()
            .join("sessions")
            .join(&short)
            .join("record.json");
        let record: Record = serde_json_lenient::from_reader(std::fs::File::open(record_file)?)?;
        Ok(DiskSession {
            minimal_state_dir: self.minimal_dir.clone(),
            key: key.clone(),
            record,
        })
    }

    fn save(&mut self, key: &Self::Key, record: &Record) -> Result<(), std::io::Error> {
        // The id is the primary key — `save` overwrites the row, it
        // doesn't move it. Mismatched ids would corrupt the index.
        if record.id != *key.id() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "save: record id {} does not match key id {}",
                    record.id,
                    key.id(),
                ),
            ));
        }

        // Refuse to save against a stale key — one the index has dropped, or
        // whose short has since been re-allocated to a different session — so
        // a stale caller can't overwrite the session that inherited the short.
        // See `live_short`.
        let short = self.live_short(key)?;
        let id = *key.id();

        let old_name = self.index.name_by_id(&id).cloned();
        let new_name = record.name.clone();

        // Validate a newly-assigned name at the character level before the
        // uniqueness check. Gate on an actual change so re-saving an unchanged
        // record (e.g. a status promotion) never re-validates a name.
        if old_name != new_name
            && let Some(name) = &new_name
        {
            validate_session_name(name)?;
        }

        // Collision check: if the new name belongs to a *different*
        // session, refuse. Same-id same-name is a no-op, not a collision.
        if let Some(name) = &new_name
            && let Some(other_id) = self.index.find_by_name(name).copied()
            && other_id != id
        {
            return Err(std::io::Error::new(
                AlreadyExists,
                format!("a session with the name `{name}` already exists"),
            ));
        }

        // Atomic record write (temp + renameat2).
        self.write_record(&short, record)?;

        // Only mutate the in-memory index after the on-disk write succeeds.
        if old_name != new_name {
            if let Some(old) = &old_name {
                self.index.name_to_id.remove(old);
            }
            if let Some(new) = new_name {
                self.index.name_to_id.insert(new, id);
            }
            self.flush_index()?;
        }

        Ok(())
    }

    fn rename(&mut self, key: &Self::Key, new_name: String) -> Result<(), std::io::Error> {
        let mut record = self.get(key)?.record;
        record.name = Some(new_name);
        self.save(key, &record)
    }

    fn delete(&mut self, key: &Self::Key) -> Result<(), std::io::Error> {
        // Refuse a stale key up front: without the id-strict check, a key
        // whose short was re-allocated after its own session was deleted would
        // deindex and `remove_dir_all` the *unrelated* session that inherited
        // the short. `live_short` returns `NotFound` in that case.
        let short = self.live_short(key)?;
        // Discover the name index entry from the index itself, not by reading
        // the record: index cleanup must not depend on the on-disk tree still
        // existing, or a half-deleted session (dir gone, index entries left)
        // could never be scrubbed.
        let name = self.index.name_by_id(key.id()).cloned();

        let sessions_root = self.minimal_dir.as_utf8_path().join("sessions");
        let session_dir = sessions_root.join(&short);
        let tombstone = sessions_root.join(tombstone_name(&short));

        // Write a tombstone marker into the *parent* (sessions/) dir before
        // doing anything else. Putting it outside the session dir means
        // `remove_dir_all` below can't race the marker's existence — the
        // marker survives until we explicitly remove it last. This lets
        // `DiskLoader::new` distinguish a crashed-mid-delete dir (reap it,
        // even if `remove_dir_all` partially completed) from a
        // crashed-mid-create orphan record (re-index it).
        //
        // A NotFound here would mean `sessions_root` itself is gone, which
        // is a loader-invariant violation; let it propagate.
        std::fs::write(&tombstone, b"")?;

        // Drop the index entries and flush before touching the filesystem: the
        // index is the source of truth for `keys()`, so removing it first means
        // a crash mid-delete can only ever orphan a directory (invisible and
        // harmless), never leave a key pointing at a removed tree.
        self.index.remove(&short, name.as_deref());
        self.flush_index()?;

        match std::fs::remove_dir_all(&session_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == NotFound => {}
            Err(e) => return Err(e),
        }

        // Tombstone removed last: any prior crash leaves it on disk for
        // `DiskLoader::new` to re-drive the reap idempotently.
        match std::fs::remove_file(&tombstone) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn load_composition(
        &self,
        key: &Self::Key,
    ) -> Result<Option<crate::core::compose::Composition>, std::io::Error> {
        let short = self.live_short(key)?;
        let path = self
            .minimal_dir
            .as_utf8_path()
            .join("sessions")
            .join(&short)
            .join("composition.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let wire: crate::wire::request::WireComposition =
                    serde_json_lenient::from_slice(&bytes).map_err(|e| {
                        std::io::Error::other(format!(
                            "parsing composition snapshot at {}: {e}",
                            path.as_str()
                        ))
                    })?;
                crate::core::compose::Composition::try_from(wire)
                    .map(Some)
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "reconstructing composition from snapshot at {}: {e}",
                            path.as_str()
                        ))
                    })
            }
            Err(e) if e.kind() == NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn store_composition(
        &self,
        key: &Self::Key,
        composition: &crate::core::compose::Composition,
    ) -> Result<(), std::io::Error> {
        let short = self.live_short(key)?;
        let session_dir = self
            .minimal_dir
            .as_utf8_path()
            .join("sessions")
            .join(&short);
        std::fs::create_dir_all(&session_dir)?;
        let dest = session_dir.join("composition.json");
        let tmp = session_dir.join("composition.json.tmp");

        let wire = crate::wire::request::WireComposition::from(composition);
        let json = serde_json_lenient::to_vec_pretty(&wire)
            .map_err(|e| std::io::Error::other(format!("serializing composition snapshot: {e}")))?;
        std::fs::write(&tmp, &json)?;

        #[cfg(target_os = "linux")]
        common::renameat2::renameat2_cwd(tmp.as_std_path(), dest.as_std_path(), 0)?;
        #[cfg(not(target_os = "linux"))]
        std::fs::rename(&tmp, &dest)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionStatus;
    use paths::HostAbsPath;
    use std::{collections::BTreeSet, io::ErrorKind};
    use tempfile::TempDir;

    fn loader_dir(tmp: &TempDir) -> DaemonAbsPath {
        DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap()
    }

    fn sample_record() -> Record {
        Record {
            id: SessionId::nil(),
            name: Some("my-session".to_string()),
            username: Some("alice".to_string()),
            project_path: HostAbsPath::try_new("/home/alice/proj").unwrap(),
            // An OwnIp session carrying a non-default policy, so the round-trip
            // tests prove a configured policy — the live source for the
            // GetSessionPolicy RPC — survives a disk round-trip, not just the
            // all-`None` default.
            network: crate::NetworkMode::OwnIp,
            policy: crate::SessionPolicy::new(
                Some(crate::EgressPolicy {
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    allow_protocols: None,
                }),
                None,
            ),
            status: SessionStatus::default(),
            // Deliberately the non-default (`--no-hooks`): `true` is the
            // serde default, so a fixture using it would round-trip
            // green even if the field were dropped on write.
            hooks_enabled: false,
            attrs: [("color".to_string(), "blue".to_string())]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn create_then_get_round_trips_record_contents() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let input = sample_record();
        let key = loader.create(input.clone()).unwrap();
        let got = loader.get(&key).unwrap();

        // The id is reassigned by the loader, but every other field
        // is the caller's to control and must survive a round-trip.
        assert_eq!(got.record().name, input.name);
        assert_eq!(got.record().username, input.username);
        assert_eq!(got.record().project_path, input.project_path);
        assert_eq!(got.record().attrs, input.attrs);
        // The configured network mode and policy must survive too: Record.policy
        // is the authoritative source the GetSessionPolicy RPC reads back.
        assert_eq!(got.record().network, input.network);
        assert_eq!(got.record().policy, input.policy);
        // Likewise `--no-hooks`: the attach, detach, and destroy
        // transitions read this back off disk, long after the flag that
        // set it is gone.
        assert_eq!(got.record().hooks_enabled, input.hooks_enabled);
        assert!(!got.record().hooks_enabled);

        // Check find_by_id as well.
        assert_eq!(
            loader.find_by_id(&got.record.id).unwrap().as_ref(),
            Some(&key)
        );
        // Check find_by_name as well.
        assert_eq!(
            loader.find_by_name(got.record.name.unwrap()).unwrap(),
            Some(key)
        );
    }

    #[test]
    fn create_assigns_a_fresh_id_and_key_uuid_matches_stored_record() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let mut input = sample_record();
        input.id = SessionId::nil();
        let key = loader.create(input).unwrap();

        assert_ne!(key.id().0, Uuid::nil(), "create must overwrite caller id");
        let stored = loader.get(&key).unwrap();
        assert_eq!(&stored.record().id, key.id());
    }

    #[test]
    fn create_errors_on_non_unique_name() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        loader.create(sample_record()).unwrap();
        assert_eq!(
            loader.create(sample_record()).err().map(|e| e.kind()),
            Some(ErrorKind::AlreadyExists)
        );
    }

    #[test]
    fn validate_session_name_accepts_ordinary_names() {
        assert!(validate_session_name("debug-qa").is_ok());
        assert!(validate_session_name("my session").is_ok());
    }

    #[test]
    fn validate_session_name_rejects_empty_whitespace_and_control_chars() {
        for bad in ["", "   ", " leading", "trailing ", "a\tb", "x\ny"] {
            assert_eq!(
                validate_session_name(bad).err().map(|e| e.kind()),
                Some(ErrorKind::InvalidInput),
                "expected `{bad:?}` to be rejected",
            );
        }
    }

    #[test]
    fn create_rejects_a_control_character_name() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let mut record = sample_record();
        record.name = Some("a\tb".to_string());
        assert_eq!(
            loader.create(record).err().map(|e| e.kind()),
            Some(ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn rename_rejects_a_control_character_name_and_keeps_the_old_one() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        // The production rename path flows through `save`, so this exercises
        // the same gate the daemon's rename does.
        let key = loader.create(sample_record()).unwrap();
        assert_eq!(
            loader
                .rename(&key, "x\ny".to_string())
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::InvalidInput)
        );
        assert_eq!(
            loader.get(&key).unwrap().record().name.as_deref(),
            Some("my-session"),
            "a rejected rename must leave the original name intact"
        );
    }

    #[test]
    fn list_yields_a_key_for_every_created_session() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let created: BTreeSet<SessionId> = (0..5)
            .map(|i| {
                *loader
                    .create({
                        let mut record = sample_record();
                        record.name = Some(format!("session-{i}"));
                        record
                    })
                    .unwrap()
                    .id()
            })
            .collect();
        let listed: BTreeSet<SessionId> = loader.keys().map(|k| *k.id()).collect();

        assert_eq!(listed, created);
    }

    #[test]
    fn sessions_survive_loader_reinit_on_the_same_directory() {
        let tmp = TempDir::new().unwrap();

        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();
        let original = loader.create(sample_record()).unwrap();
        drop(loader);

        let reloaded = DiskLoader::new(loader_dir(&tmp)).unwrap();
        let key = reloaded
            .keys()
            .find(|k| k.id() == original.id())
            .expect("previously-created session should be visible after reinit");
        let stored = reloaded.get(&key).unwrap();
        assert_eq!(&stored.record().id, original.id());
        assert_eq!(stored.record().name.as_deref(), Some("my-session"));
    }

    #[test]
    fn rename_updates_the_on_disk_record() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        loader.rename(&key, "renamed".to_string()).unwrap();

        // The record read back from disk reflects the new name.
        assert_eq!(
            loader.get(&key).unwrap().record().name.as_deref(),
            Some("renamed")
        );
    }

    #[test]
    fn rename_remaps_the_name_index() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        loader.rename(&key, "renamed".to_string()).unwrap();

        // The new name resolves to the session...
        assert_eq!(loader.find_by_name("renamed").unwrap(), Some(key));
        // ...and the old name no longer resolves to anything.
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
    }

    #[test]
    fn rename_leaves_the_id_and_key_unchanged() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let id = *key.id();
        loader.rename(&key, "renamed".to_string()).unwrap();

        // Renaming touches only the name; the id and short key are stable.
        assert_eq!(loader.find_by_id(&id).unwrap().as_ref(), Some(&key));
        assert_eq!(&loader.get(&key).unwrap().record().id, &id);
    }

    #[test]
    fn rename_persists_across_loader_reinit() {
        let tmp = TempDir::new().unwrap();

        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();
        let key = loader.create(sample_record()).unwrap();
        loader.rename(&key, "renamed".to_string()).unwrap();
        drop(loader);

        // Both the record write and the index flush must survive a reload.
        let reloaded = DiskLoader::new(loader_dir(&tmp)).unwrap();
        assert_eq!(
            reloaded.get(&key).unwrap().record().name.as_deref(),
            Some("renamed")
        );
        assert_eq!(reloaded.find_by_name("renamed").unwrap(), Some(key));
        assert_eq!(reloaded.find_by_name("my-session").unwrap(), None);
    }

    #[test]
    fn rename_errors_when_the_target_name_is_taken() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let first = loader.create(sample_record()).unwrap();
        loader
            .create({
                let mut record = sample_record();
                record.name = Some("other".to_string());
                record
            })
            .unwrap();

        // "other" is already taken, so renaming the first session onto it fails.
        assert_eq!(
            loader
                .rename(&first, "other".to_string())
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::AlreadyExists)
        );
        // The failed rename left the original name intact.
        assert_eq!(loader.find_by_name("my-session").unwrap(), Some(first));
    }

    #[test]
    fn delete_removes_record_and_index_entries() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let dir = tmp.path().join("sessions").join(&key.dir_key);
        assert!(dir.exists(), "session dir should exist before delete");

        loader.delete(&key).unwrap();

        // The on-disk tree is gone, and neither lookup resolves any more.
        assert!(!dir.exists(), "session dir should be removed after delete");
        assert_eq!(loader.find_by_id(key.id()).unwrap(), None);
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
        assert!(
            loader.keys().next().is_none(),
            "keys() should be empty after the only session is deleted"
        );
    }

    #[test]
    fn delete_scrubs_index_when_directory_is_already_missing() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();

        // Simulate a half-deleted session: the directory tree is gone but the
        // index entries remain. delete() must still succeed (a missing tree is
        // not an error) and scrub the stale index entries.
        let dir = tmp.path().join("sessions").join(&key.dir_key);
        std::fs::remove_dir_all(&dir).unwrap();

        loader.delete(&key).unwrap();

        assert_eq!(loader.find_by_id(key.id()).unwrap(), None);
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
        assert!(
            loader.keys().next().is_none(),
            "stale index entries should be removed even with the dir missing"
        );
    }

    #[test]
    fn delete_frees_the_name_for_reuse() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        loader.delete(&key).unwrap();

        // The name index entry was dropped, so the same name can be taken again.
        loader.create(sample_record()).unwrap();
    }

    #[test]
    fn delete_persists_across_loader_reinit() {
        let tmp = TempDir::new().unwrap();

        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();
        let key = loader.create(sample_record()).unwrap();
        loader.delete(&key).unwrap();
        drop(loader);

        // The index flush survived the reload: the session stays gone.
        let reloaded = DiskLoader::new(loader_dir(&tmp)).unwrap();
        assert_eq!(reloaded.find_by_id(key.id()).unwrap(), None);
        assert!(reloaded.keys().next().is_none());
    }

    #[test]
    fn rename_names_a_previously_unnamed_session() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader
            .create({
                let mut record = sample_record();
                record.name = None;
                record
            })
            .unwrap();
        loader.rename(&key, "now-named".to_string()).unwrap();

        assert_eq!(
            loader.get(&key).unwrap().record().name.as_deref(),
            Some("now-named")
        );
        assert_eq!(loader.find_by_name("now-named").unwrap(), Some(key));
    }

    // =================================================================
    // Loader::save
    // =================================================================

    #[test]
    fn save_overwrites_existing_record() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let mut updated = loader.get(&key).unwrap().record().clone();
        updated.attrs.insert("color".into(), "red".into());
        updated.username = Some("bob".into());

        loader.save(&key, &updated).unwrap();

        let reread = loader.get(&key).unwrap();
        assert_eq!(
            reread.record().attrs.get("color").map(String::as_str),
            Some("red")
        );
        assert_eq!(reread.record().username.as_deref(), Some("bob"));
    }

    #[test]
    fn save_promotes_pending_to_active() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader
            .create({
                let mut r = sample_record();
                r.status = SessionStatus::Pending;
                r
            })
            .unwrap();
        let mut promoted = loader.get(&key).unwrap().record().clone();
        promoted.status = SessionStatus::Active;
        loader.save(&key, &promoted).unwrap();

        assert_eq!(
            loader.get(&key).unwrap().record().status,
            SessionStatus::Active,
        );
    }

    #[test]
    fn save_can_change_name_and_updates_index() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let mut updated = loader.get(&key).unwrap().record().clone();
        updated.name = Some("renamed".into());
        loader.save(&key, &updated).unwrap();

        assert_eq!(loader.find_by_name("renamed").unwrap(), Some(key.clone()));
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
    }

    #[test]
    fn save_rejects_id_change() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        // Snapshot the whole stored record so a future refactor that
        // accidentally moves a side effect above the id check would
        // be caught — not just the id field.
        let before = loader.get(&key).unwrap().record().clone();

        let mut tampered = before.clone();
        tampered.id = SessionId(uuid::Uuid::from_u128(0xCAFE_BABE));
        tampered.username = Some("intruder".into());

        let err = loader.save(&key, &tampered).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        let after = loader.get(&key).unwrap().record().clone();
        assert_eq!(after, before, "failed save must not mutate any field");
    }

    #[test]
    fn save_rejects_name_collision() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let first = loader.create(sample_record()).unwrap();
        let second = loader
            .create({
                let mut r = sample_record();
                r.name = Some("other".into());
                r
            })
            .unwrap();

        // Try to save `first` claiming "other" — already taken by `second`.
        let mut conflict = loader.get(&first).unwrap().record().clone();
        conflict.name = Some("other".into());
        let err = loader.save(&first, &conflict).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);

        // Index untouched.
        assert_eq!(loader.find_by_name("my-session").unwrap(), Some(first));
        assert_eq!(loader.find_by_name("other").unwrap(), Some(second));
    }

    /// Saving a record whose name equals the current on-disk name is a
    /// no-op for the index — not a self-collision. This is the same
    /// reason `find_by_name(current).is_some()` isn't a valid
    /// collision check.
    #[test]
    fn save_with_same_name_is_not_a_collision() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let record = loader.get(&key).unwrap().record().clone();
        loader.save(&key, &record).unwrap();

        assert_eq!(loader.find_by_name("my-session").unwrap(), Some(key));
    }

    /// Saving against a stale key — for a session that's been
    /// deleted — must refuse, not resurrect the session by
    /// re-creating its on-disk dir + record.json.
    #[test]
    fn save_against_stale_key_after_delete_errors_with_not_found() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let record = loader.get(&key).unwrap().record().clone();
        loader.delete(&key).unwrap();

        let err = loader.save(&key, &record).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        // No resurrection: id still unknown to the loader.
        assert_eq!(loader.find_by_id(key.id()).unwrap(), None);
    }

    /// Saving against a stale key whose short has been *reused* by a
    /// different session must refuse — otherwise the stale caller
    /// would overwrite the new session's record.json. The check is
    /// id-strict, not just short-presence-strict.
    #[test]
    fn save_against_stale_key_with_reused_short_errors_with_not_found() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let stale_key = loader.create(sample_record()).unwrap();
        let stale_id = *stale_key.id();
        let stale_short = stale_key.dir_key.to_string();
        let stale_record = loader.get(&stale_key).unwrap().record().clone();
        loader.delete(&stale_key).unwrap();
        drop(loader);

        // Simulate UUIDv7-suffix collision: another session "reuses"
        // the same short, but with a different id. We can't make
        // `create` reliably collide, so we craft the on-disk state
        // directly: a new session dir at the freed short with a
        // freshly-minted record id, then surface it to the loader by
        // re-opening (self-heal picks it up as an orphan).
        let new_id = SessionId(uuid::Uuid::from_u128(0xFACE_FEED));
        assert_ne!(new_id, stale_id, "test setup: ids must differ");
        let sessions_dir = loader_dir(&tmp).as_utf8_path().join("sessions");
        let dir = sessions_dir.join(&stale_short);
        std::fs::create_dir_all(dir.as_std_path()).unwrap();
        let mut new_record = sample_record();
        new_record.id = new_id;
        new_record.name = Some("squatter".into());
        std::fs::write(
            dir.join("record.json").as_std_path(),
            serde_json_lenient::to_vec(&new_record).unwrap(),
        )
        .unwrap();

        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();
        // The new session is in the index under the reused short.
        assert_eq!(
            loader.index.short_to_id.get(&stale_short).copied(),
            Some(new_id),
        );

        // Stale-key save must refuse: id mismatch, not just short presence.
        let err = loader.save(&stale_key, &stale_record).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        // The squatting session's record on disk is untouched.
        let reread: Record = serde_json_lenient::from_reader(
            std::fs::File::open(dir.join("record.json").as_std_path()).unwrap(),
        )
        .unwrap();
        assert_eq!(reread.id, new_id);
        assert_eq!(reread.name.as_deref(), Some("squatter"));
    }

    /// Saving a record with `name = None` removes the name mapping
    /// without disturbing the short index.
    #[test]
    fn save_can_clear_name() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        let mut anonymized = loader.get(&key).unwrap().record().clone();
        anonymized.name = None;
        loader.save(&key, &anonymized).unwrap();

        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
        // Session still reachable by id.
        assert_eq!(loader.find_by_id(key.id()).unwrap(), Some(key));
    }

    // =================================================================
    // Stale-key rejection on get / delete (id-strict, mirrors save)
    // =================================================================

    /// `get` against a stale key — for a session that's been deleted — must
    /// refuse with `NotFound` rather than trying to read a now-absent record.
    #[test]
    fn get_against_stale_key_after_delete_errors_with_not_found() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let key = loader.create(sample_record()).unwrap();
        loader.delete(&key).unwrap();

        let err = loader.get(&key).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// Plant the "reused short" scenario: create a session, delete it (freeing
    /// its short), then write a *different* session (distinct id, name
    /// "squatter") straight onto disk at the freed short and re-open the loader
    /// so self-heal indexes it as an orphan. Returns the reopened loader, the
    /// now-stale key of the deleted session, and the new session's id + short.
    fn reused_short_scenario(tmp: &TempDir) -> (DiskLoader, DiskSessionKey, SessionId, String) {
        let mut loader = DiskLoader::new(loader_dir(tmp)).unwrap();
        let stale_key = loader.create(sample_record()).unwrap();
        let stale_short = stale_key.dir_key.to_string();
        loader.delete(&stale_key).unwrap();
        drop(loader);

        // We can't make `create` reliably collide on the 20-bit short, so we
        // craft the on-disk state directly at the freed short.
        let new_id = SessionId(uuid::Uuid::from_u128(0xFACE_FEED));
        assert_ne!(new_id, *stale_key.id(), "test setup: ids must differ");
        let dir = loader_dir(tmp)
            .as_utf8_path()
            .join("sessions")
            .join(&stale_short);
        std::fs::create_dir_all(dir.as_std_path()).unwrap();
        let mut new_record = sample_record();
        new_record.id = new_id;
        new_record.name = Some("squatter".into());
        std::fs::write(
            dir.join("record.json").as_std_path(),
            serde_json_lenient::to_vec(&new_record).unwrap(),
        )
        .unwrap();

        let loader = DiskLoader::new(loader_dir(tmp)).unwrap();
        assert_eq!(
            loader.index.short_to_id.get(&stale_short).copied(),
            Some(new_id),
            "test setup: the new session should own the reused short",
        );
        (loader, stale_key, new_id, stale_short)
    }

    /// `get` against a stale key whose short has been *reused* by a different
    /// session must refuse — otherwise a stale caller reads the unrelated
    /// session's record. The check is id-strict, not just short-presence.
    #[test]
    fn get_against_stale_key_with_reused_short_errors_with_not_found() {
        let tmp = TempDir::new().unwrap();
        let (loader, stale_key, _new_id, _short) = reused_short_scenario(&tmp);

        let err = loader.get(&stale_key).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// `delete` against a stale key whose short was reused must refuse and
    /// leave the session that inherited the short fully intact — its index
    /// entry, its `record.json`, and its dir. Without the id-strict guard the
    /// stale delete would deindex and `remove_dir_all` the wrong session.
    #[test]
    fn delete_against_stale_key_with_reused_short_leaves_new_session_intact() {
        let tmp = TempDir::new().unwrap();
        let (mut loader, stale_key, new_id, stale_short) = reused_short_scenario(&tmp);

        let err = loader.delete(&stale_key).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);

        // The squatting session is untouched: still indexed, record readable,
        // dir on disk.
        let new_key = loader
            .find_by_id(&new_id)
            .unwrap()
            .expect("the reused-short session must remain indexed");
        assert_eq!(
            loader.get(&new_key).unwrap().record().name.as_deref(),
            Some("squatter"),
        );
        assert!(
            session_dir_path(&loader_dir(&tmp), &stale_short).exists(),
            "the reused-short session's dir must not be removed",
        );
    }

    // =================================================================
    // self-heal on DiskLoader::new
    // =================================================================
    //
    // Each crash scenario is simulated by direct filesystem
    // manipulation — we never go through the Loader API to corrupt
    // state, because the API guarantees consistency. We're testing
    // the on-disk recovery.

    fn short_of(key: &DiskSessionKey) -> String {
        key.dir_key.to_string()
    }

    fn session_dir_path(loader_root: &DaemonAbsPath, short: &str) -> std::path::PathBuf {
        loader_root
            .as_utf8_path()
            .join("sessions")
            .join(short)
            .as_std_path()
            .to_path_buf()
    }

    fn read_index_bytes(loader_root: &DaemonAbsPath) -> Vec<u8> {
        let p = loader_root.as_utf8_path().join("sessions/index.json");
        std::fs::read(p.as_std_path()).unwrap()
    }

    fn tombstone_path(loader_root: &DaemonAbsPath, short: &str) -> std::path::PathBuf {
        loader_root
            .as_utf8_path()
            .join("sessions")
            .join(tombstone_name(short))
            .as_std_path()
            .to_path_buf()
    }

    #[test]
    fn self_heal_on_clean_state_is_noop() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        loader.create(sample_record()).unwrap();
        drop(loader);

        let before = read_index_bytes(&root);
        // Re-opening over a consistent state must not touch index.json.
        let _ = DiskLoader::new(root.clone()).unwrap();
        let after = read_index_bytes(&root);
        assert_eq!(before, after, "index.json was rewritten on a clean state");
    }

    #[test]
    fn self_heal_reaps_tombstoned_dir() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        let id = *key.id();
        drop(loader);

        // Simulate a crash mid-delete: tombstone present (in the
        // *parent* sessions dir, not inside the session dir),
        // index entry still there, dir still there.
        let dir = session_dir_path(&root, &short);
        let marker = tombstone_path(&root, &short);
        std::fs::write(&marker, b"").unwrap();

        let loader = DiskLoader::new(root).unwrap();
        assert!(!dir.exists(), "tombstoned dir should have been reaped");
        assert!(
            !marker.exists(),
            "tombstone marker should have been removed"
        );
        assert_eq!(loader.find_by_id(&id).unwrap(), None);
    }

    #[test]
    fn self_heal_drops_dangling_index_entry() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        let id = *key.id();
        drop(loader);

        // Simulate a half-deleted session WITHOUT a tombstone: the
        // session dir was removed but the index entry remained
        // (e.g. someone hand-deleted the dir).
        std::fs::remove_dir_all(session_dir_path(&root, &short)).unwrap();

        let loader = DiskLoader::new(root).unwrap();
        assert_eq!(loader.find_by_id(&id).unwrap(), None);
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
    }

    #[test]
    fn self_heal_reindexes_orphan_record() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        let id = *key.id();
        drop(loader);

        // Simulate a crash mid-create: record.json on disk, but the
        // index doesn't know about it. We rewrite the index to a
        // default empty Index.
        let sessions_dir = root.as_utf8_path().join("sessions");
        let empty = serde_json_lenient::to_vec(&Index::default()).unwrap();
        std::fs::write(sessions_dir.join("index.json").as_std_path(), empty).unwrap();

        let loader = DiskLoader::new(root).unwrap();
        // The orphan was re-indexed: it's reachable by id and name.
        let key2 = loader.find_by_id(&id).unwrap().expect("re-indexed");
        assert_eq!(short_of(&key2), short);
        assert_eq!(loader.find_by_name("my-session").unwrap(), Some(key2),);
    }

    #[test]
    fn self_heal_skips_orphan_with_name_collision() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        // First session: created normally, claims "my-session".
        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let a_key = loader.create(sample_record()).unwrap();
        let a_id = *a_key.id();
        drop(loader);

        // Manually plant an orphan session in a sibling dir that ALSO
        // claims name = "my-session", with a distinct id so the ids
        // don't collide. The short is intentionally NOT in the format
        // `create()` produces (5 lowercase hex chars), so the test
        // can never collide with the real session's dir even on an
        // unlucky UUIDv7 suffix.
        let orphan_short = "zzzzz";
        let orphan_dir = root.as_utf8_path().join("sessions").join(orphan_short);
        std::fs::create_dir_all(orphan_dir.as_std_path()).unwrap();
        let mut orphan_record = sample_record();
        orphan_record.id = SessionId(uuid::Uuid::from_u128(0xDEAD_BEEF));
        let record_file = orphan_dir.join("record.json");
        let buf = serde_json_lenient::to_vec(&orphan_record).unwrap();
        std::fs::write(record_file.as_std_path(), buf).unwrap();

        let loader = DiskLoader::new(root.clone()).unwrap();
        // The original (indexed) session still resolves; the orphan is
        // not in the index.
        assert_eq!(loader.find_by_id(&a_id).unwrap(), Some(a_key));
        assert_eq!(loader.find_by_id(&orphan_record.id).unwrap(), None);
        // The orphan dir is left on disk for manual triage.
        assert!(
            session_dir_path(&root, orphan_short).exists(),
            "orphan dir should be preserved for triage",
        );
    }

    #[test]
    fn self_heal_recovers_from_rename_crash() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        drop(loader);

        // Simulate a crash mid-rename: record.json has the NEW name,
        // index.json still has the OLD name.
        let dir = session_dir_path(&root, &short);
        let record_file = dir.join("record.json");
        let buf = std::fs::read(&record_file).unwrap();
        let mut record: Record = serde_json_lenient::from_slice(&buf).unwrap();
        record.name = Some("after-rename".to_string());
        std::fs::write(&record_file, serde_json_lenient::to_vec(&record).unwrap()).unwrap();

        let loader = DiskLoader::new(root).unwrap();
        // The index is reconciled: the new name resolves, the old one
        // does not.
        let resolved = loader.find_by_name("after-rename").unwrap();
        assert!(resolved.is_some(), "new name should resolve");
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
    }

    #[test]
    fn self_heal_handles_tombstone_with_lingering_index_entry() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        let id = *key.id();
        drop(loader);

        // Crash mid-delete BEFORE the index flush: tombstone on disk
        // (in the parent sessions dir), index entry still present,
        // dir intact.
        let dir = session_dir_path(&root, &short);
        std::fs::write(tombstone_path(&root, &short), b"").unwrap();

        let loader = DiskLoader::new(root.clone()).unwrap();
        // Pass A reaps the dir AND clears the index entry; pass B has
        // nothing to do for this short.
        assert!(!dir.exists(), "dir should be reaped");
        assert_eq!(loader.find_by_id(&id).unwrap(), None);
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
    }

    /// Simulates `remove_dir_all` having partially completed before a
    /// crash: with the *external* tombstone design, the marker is in
    /// the parent dir and `remove_dir_all` never touches it. Even if
    /// `record.json` (the file that would otherwise let pass C
    /// re-index the dir as an orphan) is still on disk, the marker
    /// drives a deterministic reap.
    #[test]
    fn self_heal_reaps_even_when_record_still_present_during_partial_remove() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        let id = *key.id();
        drop(loader);

        // Drop the index entry to simulate "delete had flushed the
        // index" — but DO leave the dir + record.json on disk to
        // simulate "remove_dir_all crashed mid-walk". The external
        // tombstone is also present.
        let sessions_dir = root.as_utf8_path().join("sessions");
        let empty = serde_json_lenient::to_vec(&Index::default()).unwrap();
        std::fs::write(sessions_dir.join("index.json").as_std_path(), empty).unwrap();
        let dir = session_dir_path(&root, &short);
        std::fs::write(tombstone_path(&root, &short), b"").unwrap();
        assert!(
            dir.join("record.json").exists(),
            "record.json should still be present (simulating partial remove_dir_all)",
        );

        let loader = DiskLoader::new(root).unwrap();
        // Pass A reaps the dir even though record.json was still there.
        // Pass C is consequently not tempted to "undelete" the orphan.
        assert!(!dir.exists(), "dir should be reaped");
        assert_eq!(loader.find_by_id(&id).unwrap(), None);
        assert_eq!(loader.find_by_name("my-session").unwrap(), None);
    }

    /// Regression guard for the marker location: `delete()` must put
    /// the tombstone in the *parent* sessions/ dir (so it survives
    /// `remove_dir_all`). After a successful delete, the marker must
    /// be cleaned up too.
    #[test]
    fn delete_writes_external_tombstone_and_cleans_it_up() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key = loader.create(sample_record()).unwrap();
        let short = short_of(&key);
        let marker = tombstone_path(&root, &short);
        let inside = session_dir_path(&root, &short).join(".deleting");

        loader.delete(&key).unwrap();

        // After a successful delete, neither location should have a
        // marker — the external one was removed at the end of delete,
        // and the internal one was never written.
        assert!(!marker.exists(), "external tombstone should be cleaned up");
        assert!(
            !inside.exists(),
            "no tombstone should ever be placed inside the session dir",
        );
    }

    /// Pass A's `NotFound` branch: a tombstone for a short whose session
    /// dir is already gone (e.g. someone hand-deleted it after the
    /// marker was written but before self-heal ran).
    #[test]
    fn self_heal_reaps_orphan_tombstone_without_session_dir() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        // Manually plant a tombstone marker pointing at a short that
        // doesn't exist as a dir. The short matches the
        // create()-produced format (5 lowercase hex) so `is_valid_short`
        // accepts it.
        let _ = DiskLoader::new(root.clone()).unwrap();
        let orphan_short = "abcde";
        let marker = tombstone_path(&root, orphan_short);
        std::fs::write(&marker, b"").unwrap();
        assert!(
            !session_dir_path(&root, orphan_short).exists(),
            "test setup: orphan session dir must not exist",
        );

        let _loader = DiskLoader::new(root).unwrap();
        assert!(
            !marker.exists(),
            "orphan tombstone should be cleaned up by self-heal",
        );
    }

    /// Self-heal must reap every tombstone in one pass, not just the
    /// first one it encounters.
    #[test]
    fn self_heal_reaps_multiple_tombstones_in_one_pass() {
        let tmp = TempDir::new().unwrap();
        let root = loader_dir(&tmp);

        let mut loader = DiskLoader::new(root.clone()).unwrap();
        let key_a = loader.create(sample_record()).unwrap();
        let key_b = loader
            .create({
                let mut r = sample_record();
                r.name = Some("other".into());
                r
            })
            .unwrap();
        drop(loader);

        let marker_a = tombstone_path(&root, &short_of(&key_a));
        let marker_b = tombstone_path(&root, &short_of(&key_b));
        std::fs::write(&marker_a, b"").unwrap();
        std::fs::write(&marker_b, b"").unwrap();

        let loader = DiskLoader::new(root.clone()).unwrap();

        assert!(!marker_a.exists(), "marker A should be cleaned up");
        assert!(!marker_b.exists(), "marker B should be cleaned up");
        assert!(
            !session_dir_path(&root, &short_of(&key_a)).exists(),
            "session A dir should be reaped",
        );
        assert!(
            !session_dir_path(&root, &short_of(&key_b)).exists(),
            "session B dir should be reaped",
        );
        assert_eq!(loader.find_by_id(key_a.id()).unwrap(), None);
        assert_eq!(loader.find_by_id(key_b.id()).unwrap(), None);
    }
}
