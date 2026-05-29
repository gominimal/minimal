//! Manages session state on disk.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::Record;
use crate::paths::{DaemonAbsPath, DaemonRelPath};

/// Describes the session object yielded by [`Loader`].
pub trait SessionObject: Sized + Send + 'static + std::fmt::Debug {
    type Key: SessionKey;

    fn record(&self) -> &Record;
    fn key(&self) -> &Self::Key;
    fn workspace_path(&self) -> DaemonAbsPath;
}

/// Describes the primary key a [`Loader`] uses to reference
/// sessions.
pub trait SessionKey: Sized + Send + 'static + std::fmt::Debug + Clone + Eq + Ord {
    /// Returns the UUID of the session.
    fn uuid(&self) -> &Uuid;
}

/// A type which can load sessions.
pub trait Loader {
    type Key: SessionKey;
    type Object: SessionObject<Key = Self::Key>;

    /// Lists all sessions known to this loader, by key.
    fn list(&self) -> impl Iterator<Item = Self::Key>;

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
    fn find_by_uuid(&self, id: &Uuid) -> Result<Option<Self::Key>, std::io::Error>;

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
}

/// The concrete key used to identify sessions from [`DiskLoader`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiskSessionKey {
    session_uuid: Uuid,
    dir_key: String,
}

impl SessionKey for DiskSessionKey {
    fn uuid(&self) -> &Uuid {
        &self.session_uuid
    }
}

/// The concrete session object from [`DiskLoader`].
#[derive(Debug)]
pub struct DiskSession {
    key: DiskSessionKey,
    minimal_state_dir: DaemonAbsPath,
    record: Record,
}

impl SessionObject for DiskSession {
    type Key = DiskSessionKey;

    fn record(&self) -> &Record {
        &self.record
    }
    fn key(&self) -> &DiskSessionKey {
        &self.key
    }
    fn workspace_path(&self) -> DaemonAbsPath {
        self.minimal_state_dir
            .sub_path("sessions")
            .join(&DaemonRelPath::try_new(&self.key.dir_key).unwrap())
            .sub_path("tree")
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
    index: BTreeMap<String, Uuid>,
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
            BTreeMap::new()
        };

        Ok(Self { minimal_dir, index })
    }

    /// Writes the in-memory index back to disk.
    ///
    /// The write is staged into a sibling temp file and then atomically
    /// renamed into place, so a crash mid-write can never leave a partially
    /// serialized `index.json` behind.
    fn flush(&self) -> Result<(), std::io::Error> {
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
}

impl Loader for DiskLoader {
    type Key = DiskSessionKey;
    type Object = DiskSession;

    fn create(&mut self, mut record: Record) -> Result<Self::Key, std::io::Error> {
        let uuid = Uuid::now_v7();
        record.id = uuid;

        let uuid_str = uuid.simple().to_string();
        let mut short = uuid_str[uuid_str.len() - 5..].to_string();
        // We got unlucky and the short name collided, 20 bits of entropy
        // so rare but very possible. Increment the short name past
        // any collisions in this case.
        while self.index.contains_key(&short) {
            let n = u32::from_str_radix(&short, 16)
                .expect("short dir name is always 5 hex chars from a UUID suffix");
            short = format!("{:05x}", n.wrapping_add(1));
        }

        let session_dir = self
            .minimal_dir
            .as_utf8_path()
            .join("sessions")
            .join(&short);
        std::fs::create_dir_all(&session_dir)?;
        let record_file = session_dir.join("record.json");
        serde_json::to_writer(std::fs::File::create(record_file)?, &record)?;

        self.index.insert(short.clone(), uuid);
        self.flush()?;

        Ok(DiskSessionKey {
            session_uuid: uuid,
            dir_key: short,
        })
    }

    fn list(&self) -> impl Iterator<Item = Self::Key> {
        self.index.iter().map(|(short, id)| Self::Key {
            session_uuid: *id,
            dir_key: short.clone(),
        })
    }

    fn find_by_uuid(&self, id: &Uuid) -> Result<Option<Self::Key>, std::io::Error> {
        Ok(self
            .index
            .iter()
            .find(|(_short, iter_id)| *iter_id == id)
            .map(|(short, id)| Self::Key {
                dir_key: short.clone(),
                session_uuid: *id,
            }))
    }
    fn find_by_name<S: AsRef<str>>(&self, name: S) -> Result<Option<Self::Key>, std::io::Error> {
        for k in self.list() {
            let record = self.get(&k)?;
            if let Some(stored_name) = &record.record().name
                && stored_name == name.as_ref()
            {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    fn get(&self, key: &Self::Key) -> Result<Self::Object, std::io::Error> {
        assert!(
            self.index.contains_key(&key.dir_key),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::HostAbsPath;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    fn loader_dir(tmp: &TempDir) -> DaemonAbsPath {
        DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap()
    }

    fn sample_record() -> Record {
        Record {
            id: Uuid::nil(),
            name: Some("my-session".to_string()),
            username: Some("alice".to_string()),
            project_path: HostAbsPath::try_new("/home/alice/proj").unwrap(),
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

        // Check find_by_uuid as well.
        assert_eq!(
            loader.find_by_uuid(&got.record.id).unwrap().as_ref(),
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
        input.id = Uuid::nil();
        let key = loader.create(input).unwrap();

        assert_ne!(key.uuid(), &Uuid::nil(), "create must overwrite caller id");
        let stored = loader.get(&key).unwrap();
        assert_eq!(&stored.record().id, key.uuid());
    }

    #[test]
    fn list_yields_a_key_for_every_created_session() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(loader_dir(&tmp)).unwrap();

        let created: BTreeSet<Uuid> = (0..5)
            .map(|_| *loader.create(sample_record()).unwrap().uuid())
            .collect();
        let listed: BTreeSet<Uuid> = loader.list().map(|k| *k.uuid()).collect();

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
            .list()
            .find(|k| k.uuid() == original.uuid())
            .expect("previously-created session should be visible after reinit");
        let stored = reloaded.get(&key).unwrap();
        assert_eq!(&stored.record().id, original.uuid());
        assert_eq!(stored.record().name.as_deref(), Some("my-session"));
    }
}
