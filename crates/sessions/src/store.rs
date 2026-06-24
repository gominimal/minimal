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
    /// Returns an I/O error if the backing record cannot be read or
    /// deserialized.
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

    /// Renames the session with the given key.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the session directory, record, or index
    /// cannot be written.
    /// `AlreadyExists` is returned if a session with that name already exists.
    fn rename(&mut self, key: &Self::Key, new_name: String) -> Result<(), std::io::Error>;

    /// Deletes the session with the given key, dropping its index entries and
    /// removing its on-disk directory tree (record, workspace, home, cache).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the record cannot be read or the index cannot be
    /// flushed. A missing directory tree is not an error.
    fn delete(&mut self, key: &Self::Key) -> Result<(), std::io::Error>;
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
    /// Opens (or initializes) a disk-backed session store rooted at
    /// `<minimal_dir>/sessions`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the sessions directory cannot be created or
    /// the existing `index.json` cannot be read.
    pub fn new(minimal_dir: DaemonAbsPath) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(minimal_dir.as_utf8_path().join("sessions"))?;
        let index_file = minimal_dir.as_utf8_path().join("sessions/index.json");
        let index = if std::fs::exists(&index_file)? {
            serde_json::from_reader(std::fs::File::open(index_file)?)?
        } else {
            Index::default()
        };

        Ok(Self { minimal_dir, index })
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
        serde_json::to_writer(&file, &self.index)?;
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
        serde_json::to_writer(&file, &record)?;
        file.sync_all()?;
        drop(file);

        #[cfg(target_os = "linux")]
        common::renameat2::renameat2_cwd(tmp_file.as_std_path(), record_file.as_std_path(), 0)?;
        #[cfg(not(target_os = "linux"))]
        std::fs::rename(&tmp_file, &record_file)?;

        Ok(())
    }
}

impl Loader for DiskLoader {
    type Key = DiskSessionKey;
    type Object = DiskSession;

    fn create(&mut self, mut record: Record) -> Result<Self::Key, std::io::Error> {
        if let Some(name) = &record.name
            && self.index.name_to_id.contains_key(name)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("a session with name `{name}` already exists"),
            ));
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
        assert!(
            self.index.find_by_short(&key.dir_key).is_some(),
            "key {:?} not present in index — Keys are only handed out for sessions that exist",
            key.dir_key,
        );
        let record_file = self
            .minimal_dir
            .as_utf8_path()
            .join("sessions")
            .join(&key.dir_key)
            .join("record.json");
        let record: Record = serde_json::from_reader(std::fs::File::open(record_file)?)?;
        Ok(DiskSession {
            minimal_state_dir: self.minimal_dir.clone(),
            key: key.clone(),
            record,
        })
    }

    fn rename(&mut self, key: &Self::Key, new_name: String) -> Result<(), std::io::Error> {
        if self.index.find_by_name(&new_name).is_some() {
            return Err(std::io::Error::new(
                AlreadyExists,
                format!("a session with the name `{new_name}` already exists"),
            ));
        }

        let mut obj = self.get(key)?;
        let short = obj.key.dir_key.to_string();
        let old_name = obj.record.name.clone();

        obj.record.name = Some(new_name.clone());
        self.write_record(&short, &obj.record)?;

        // Only mutate in-memory index after disk writes succeed
        if let Some(old_name) = &old_name {
            self.index.name_to_id.remove(old_name);
        }
        self.index.name_to_id.insert(new_name, obj.record.id);
        self.flush_index()?;

        Ok(())
    }

    fn delete(&mut self, key: &Self::Key) -> Result<(), std::io::Error> {
        let short = key.dir_key.to_string();
        // Discover the name index entry from the index itself, not by reading
        // the record: index cleanup must not depend on the on-disk tree still
        // existing, or a half-deleted session (dir gone, index entries left)
        // could never be scrubbed.
        let name = self.index.name_by_id(key.id()).cloned();

        // Drop the index entries and flush before touching the filesystem: the
        // index is the source of truth for `keys()`, so removing it first means
        // a crash mid-delete can only ever orphan a directory (invisible and
        // harmless), never leave a key pointing at a removed tree.
        self.index.remove(&short, name.as_deref());
        self.flush_index()?;

        let session_dir = self
            .minimal_dir
            .as_utf8_path()
            .join("sessions")
            .join(&short);
        match std::fs::remove_dir_all(&session_dir) {
            Ok(()) => Ok(()),
            // A missing tree is fine — the session is gone either way.
            Err(e) if e.kind() == NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
