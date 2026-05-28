//! Implementations of the local cache: storing artifacts keyed by [SpecHash].

use common::SpecHash;
use common::renameat2::{AT_FDCWD, RENAME_EXCHANGE, renameat2};

use std::io;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[allow(dead_code)]
mod fs;
pub use fs::FSError;
pub use fs::FileSystem;
pub use fs::LocalDir;

pub(crate) mod entry_meta;
pub use entry_meta::{EntryMeta, MetaInner};

mod read_tracker;
pub use read_tracker::ReadSnapshot;
use read_tracker::ReadTracker;

/// A directory tree in the cache you can read or write.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DirCacheEntry<FS: FileSystem> {
    c: Cache<FS>,
    hash: SpecHash,
    tree: FS::Subtree,
}

impl DirCacheEntry<LocalDir> {
    /// The path on the filesystem representing this cache entry.
    pub fn path(&self) -> &Path {
        self.tree.path()
    }
}

impl<FS: FileSystem<Subtree = ST>, ST: FileSystem> FileSystem for DirCacheEntry<FS> {
    type File = ST::File;
    type DirEntry = ST::DirEntry;
    type Subtree = ST::Subtree;

    fn open_read<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError> {
        self.tree.open_read(path)
    }
    fn open_write<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError> {
        self.tree.open_write(path)
    }

    fn read_dir<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Self::DirEntry>, FSError> {
        self.tree.read_dir(path)
    }

    fn mkdir<P: AsRef<Path>>(&self, path: P) -> Result<(), FSError> {
        self.tree.mkdir(path)
    }

    fn subtree<P: AsRef<Path>>(&self, path: P) -> Result<Self::Subtree, FSError> {
        self.tree.subtree(path)
    }
    fn remove_file<P: AsRef<Path>>(&self, _: P) -> Result<(), std::io::Error> {
        todo!()
    }
    fn remove_dir<P: AsRef<Path>>(&self, _: P) -> Result<(), std::io::Error> {
        todo!()
    }
}

/// A writeable directory that will end up in the cache when finalized.
#[derive(Debug)]
#[allow(dead_code)]
pub struct PendingDir {
    c: Cache<LocalDir>,
    hash: SpecHash,
    tempdir: tempfile::TempDir,
    temp_tree: LocalDir,
}

impl PendingDir {
    /// The path on the filesystem representing this pending cache entry.
    pub fn path(&self) -> &Path {
        self.tempdir.path()
    }

    pub fn finalize(self, meta: EntryMeta) -> Result<(), CacheErr> {
        let hash_hex = self.hash.0.to_hex();
        // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
        let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
            .iter()
            .collect();

        let inner = self.c.inner();
        inner.fs.mkdir(&subpath)?;

        let st = inner.fs.subtree(&subpath)?;
        let (from, to) = (self.tempdir.keep(), st.path());
        let from_path = from.as_path();

        // use our direct syscall impl
        renameat2(AT_FDCWD, from_path, AT_FDCWD, to, RENAME_EXCHANGE).map_err(CacheErr::IO)?;
        std::fs::remove_dir_all(from)?;

        drop(st);

        meta.write(&inner.fs, &self.hash)?;
        Ok(())
    }
}

impl FileSystem for PendingDir {
    type File = <LocalDir as fs::FileSystem>::File;
    type DirEntry = <LocalDir as fs::FileSystem>::DirEntry;
    type Subtree = <LocalDir as fs::FileSystem>::Subtree;

    fn open_read<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError> {
        self.temp_tree.open_read(path)
    }
    fn open_write<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError> {
        self.temp_tree.open_write(path)
    }

    fn read_dir<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Self::DirEntry>, FSError> {
        self.temp_tree.read_dir(path)
    }

    fn mkdir<P: AsRef<Path>>(&self, path: P) -> Result<(), FSError> {
        self.temp_tree.mkdir(path)
    }

    fn subtree<P: AsRef<Path>>(&self, path: P) -> Result<Self::Subtree, FSError> {
        self.temp_tree.subtree(path)
    }
    fn remove_file<P: AsRef<Path>>(&self, _: P) -> Result<(), std::io::Error> {
        todo!()
    }
    fn remove_dir<P: AsRef<Path>>(&self, _: P) -> Result<(), std::io::Error> {
        todo!()
    }
}

/// The implementation of [Cache].
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CacheInner<FS: FileSystem> {
    fs: FS,
    read_tracker: Option<Arc<Mutex<ReadTracker>>>,
}

impl<FS: FileSystem> CacheInner<FS> {
    fn ensure_hash_dir_exists(&mut self, hash_prefix: u8) -> Result<(), CacheErr> {
        self.fs.mkdir(format!("{:02x}", hash_prefix)).ok(); //ignore error
        Ok(())
    }

    fn dir(&self, hash: &SpecHash) -> Result<FS::Subtree, CacheErr> {
        let hash_hex = hash.0.to_hex();
        // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
        let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
            .iter()
            .collect();

        self.fs.subtree(subpath).map_err(|e| {
            if let std::io::ErrorKind::NotFound = e.kind() {
                CacheErr::NotFound
            } else {
                e.into()
            }
        })
    }
    fn record_access(&self, hash: &SpecHash) {
        if let Some(t) = &self.read_tracker
            && let Err(e) = t.as_ref().lock().unwrap().record_read(hash)
        {
            tracing::warn!("Error flushing read tracker: {}", e);
        }
    }
}

/// Errors when interacting with the cache.
#[derive(Debug)]
pub enum CacheErr {
    NotFound,
    IO(FSError),
}

impl From<FSError> for CacheErr {
    fn from(fse: FSError) -> Self {
        CacheErr::IO(fse)
    }
}

impl fmt::Display for CacheErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheErr::IO(e) => write!(f, "i/o error: {}", e),
            CacheErr::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for CacheErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CacheErr::IO(e) => Some(e),
            _ => None,
        }
    }
}

/// Storage for inter-build artifacts.
///
/// Cache is thread-safe and copyable, implemented using interior mutability.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Cache<FS: FileSystem> {
    inner: Arc<Mutex<CacheInner<FS>>>,
}

impl<FS: FileSystem> Clone for Cache<FS> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Cache<LocalDir> {
    /// Constructs a local cache that uses the given directory for storage.
    pub fn at_dir<P: AsRef<Path>>(p: P) -> Result<Self, std::io::Error> {
        let fs = LocalDir::with_base(p)?;

        for dir in &["temp", "meta", "alog"] {
            match fs.mkdir(dir) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if let std::io::ErrorKind::AlreadyExists = e.kind() {
                        Ok(())
                    } else {
                        Err(e)
                    }
                }
            }?;
        }

        // Create a ReadTracker. Pick the filename based on the PID so we
        // get some randomness as to what file we start at.
        //
        // Read trackers aren't _essential_ to operation, so if after 32 rounds
        // we still cant get a lock on a file, we just give up.
        let read_tracker = {
            let mut attempts = 0;
            let mut n = std::process::id() % 32;
            loop {
                if attempts > 32 {
                    break None;
                } else if let Ok(tracker) =
                    ReadTracker::at_path(&fs.path().join("alog").join(format!("{}.v1", n)))
                {
                    break Some(tracker);
                } else {
                    attempts += 1;
                    n += 1;
                }
            }
        }
        .map(|t| Arc::new(Mutex::new(t)));

        let inner = CacheInner { fs, read_tracker };

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Invalidates (deletes) a directory cache entry with the given spec hash.
    pub fn invalidate_dir(&self, hash: &SpecHash) -> Result<(), CacheErr> {
        let hash_hex = hash.0.to_hex();
        // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
        let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
            .iter()
            .collect();

        let p = self.inner().fs.path().join(subpath);
        std::fs::remove_dir_all(p).map_err(CacheErr::from)
    }

    /// Allocates a temporary directory in the same filesystem as the rest of the cache.
    pub fn temp_dir(&self) -> Result<tempfile::TempDir, std::io::Error> {
        let inner = self.inner();
        tempfile::TempDir::with_suffix_in(
            format!("-{}", std::process::id()),
            inner.fs.path().join("temp"),
        )
    }

    /// Iterates all cached entries, yielding each spec hash.
    ///
    /// Entries are discovered lazily, one bucket directory at a time.
    pub fn iter_entries(&self) -> impl Iterator<Item = SpecHash> {
        let base = self.inner().fs.path().to_path_buf();

        (0u8..=255).flat_map(move |prefix| {
            let bucket_dir = base.join(format!("{:02x}", prefix));
            let prefix_hex = format!("{:02x}", prefix);

            std::fs::read_dir(&bucket_dir)
                .into_iter()
                .flatten()
                .filter_map(move |entry| {
                    let entry = entry.ok()?;
                    if !entry.file_type().ok()?.is_dir() {
                        return None;
                    }
                    let name = entry.file_name().into_string().ok()?;
                    let full_hex = format!("{}{}", prefix_hex, name);
                    let hash = SpecHash::from_hex(&full_hex).ok()?;

                    Some(hash)
                })
        })
    }

    /// Returns a type that can be used to check the last time a cache entry was used.
    pub fn atimes(&self) -> Result<ReadSnapshot, io::Error> {
        ReadSnapshot::load_dir(&self.inner().fs.path().join("alog"))
    }

    /// Allocates a directory for writing into the cache as the given spec_hash when finalized.
    ///
    /// Call `finalize` on the [PendingDir] once it is populated to have it show up in the cache.
    pub fn write_dir(&self, hash: &SpecHash) -> Result<PendingDir, CacheErr> {
        let tempdir = self.temp_dir()?;

        let mut inner = self.inner();
        inner.ensure_hash_dir_exists(hash.as_bytes()[0])?;

        Ok(PendingDir {
            c: self.clone(),
            temp_tree: LocalDir::with_base(tempdir.path())?,
            tempdir,
            hash: hash.clone(),
        })
    }
}

#[allow(dead_code)]
impl<FS: FileSystem> Cache<FS> {
    fn inner(&'_ self) -> MutexGuard<'_, CacheInner<FS>> {
        self.inner.lock().unwrap()
    }
    fn with_inner<T>(&self, f: impl FnOnce(&CacheInner<FS>) -> T) -> T {
        let guard = self.inner.lock().unwrap();
        f(&*guard)
    }

    /// Reads a directory cached as the given spec hash.
    pub fn read_dir(&self, hash: &SpecHash) -> Result<DirCacheEntry<FS>, CacheErr> {
        let i = self.inner();
        i.record_access(hash);
        Ok(DirCacheEntry {
            c: self.clone(),
            tree: i.dir(hash)?,
            hash: hash.clone(),
        })
    }

    /// Reads the metadata associated with the given spec hash.
    pub fn read_meta(&self, hash: &SpecHash) -> Result<EntryMeta, CacheErr> {
        EntryMeta::read(&self.inner().fs, hash)
    }

    /// Returns the cache entry that was most recently generated by a spec of the given name.
    ///
    /// NOTE: This method breaks the caching model and should not be used unless you know what you are doing!!
    pub fn unsafe_get_build_by_name(&self, name: &str) -> Result<DirCacheEntry<FS>, CacheErr> {
        let candidates = {
            let inner = self.inner();
            EntryMeta::find_build_by_name(&inner.fs, name)?
        };

        if let Some((spec_hash_hex, _)) = candidates.first() {
            self.read_dir(&SpecHash::from_hex(spec_hash_hex).unwrap())
        } else {
            Err(CacheErr::NotFound)
        }
    }
}

/// An adapter that lets you use a [Cache] as a [graph::BinProvider].
#[derive(Debug, Clone)]
pub struct CacheBinProvider<'a> {
    graph: &'a graph::Graph,
    cache: Cache<LocalDir>,
}

impl<'a> CacheBinProvider<'a> {
    pub fn new(graph: &'a graph::Graph, cache: Cache<LocalDir>) -> Self {
        Self { graph, cache }
    }
}

impl<'a> graph::BinProvider for CacheBinProvider<'a> {
    fn exists(&self, bsr: &graph::BuildSpecRef) -> bool {
        self.cache.read_dir(&self.graph.spec_hash(bsr)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::entry_meta::MetaInner;

    use super::*;
    use tempfile::TempDir;

    #[test]
    fn smoketest_folder() {
        let tmp_dir = TempDir::new().unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let test_key = SpecHash(blake3::hash("direct-tory".as_bytes()));

        let w = cache.write_dir(&test_key).unwrap();
        use std::io::Write;
        w.open_write("file_name")
            .unwrap()
            .write_all("uwu".as_bytes())
            .unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec("some spec huh".to_string()),
            fetched: false,
            ..Default::default()
        })
        .unwrap();

        let meta = EntryMeta::read(&cache.inner().fs, &test_key).unwrap();
        assert!(!meta.fetched);
        assert_eq!(meta.inner.spec_name(), Some(&"some spec huh".to_string()));

        let r = cache
            .read_dir(&test_key)
            .unwrap()
            .open_read("file_name")
            .unwrap();
        assert_eq!("uwu", std::io::read_to_string(r).unwrap());
    }

    #[test]
    fn unfinalized_pending_doesnt_writeback() {
        use std::io::Write;
        let tmp_dir = TempDir::new().unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let test_key = SpecHash(blake3::hash("direct-tory".as_bytes()));

        let w = cache.write_dir(&test_key).unwrap();
        w.open_write("file_name")
            .unwrap()
            .write_all("uwu".as_bytes())
            .unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec("old name".to_string()),
            fetched: false,
            ..Default::default()
        })
        .unwrap();

        // Write again and change the data in the file, but don't call finalize
        let w = cache.write_dir(&test_key).unwrap();
        w.open_write("file_name")
            .unwrap()
            .write_all("new data".as_bytes())
            .unwrap();
        drop(w);

        let r = cache
            .read_dir(&test_key)
            .unwrap()
            .open_read("file_name")
            .unwrap();
        assert_eq!("uwu", std::io::read_to_string(r).unwrap());
        let meta = EntryMeta::read(&cache.inner().fs, &test_key).unwrap();
        assert_eq!(meta.inner.spec_name(), Some(&"old name".to_string()));
    }

    #[test]
    fn writeback_dir_overwrites_fine() {
        use std::io::Write;
        let tmp_dir = TempDir::new().unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let test_key = SpecHash(blake3::hash("direct-tory".as_bytes()));

        let w = cache.write_dir(&test_key).unwrap();
        w.open_write("file_name")
            .unwrap()
            .write_all("bad data".as_bytes())
            .unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec("old".to_string()),
            fetched: false,
            ..Default::default()
        })
        .unwrap();

        // Write again and change the data in the file
        let w = cache.write_dir(&test_key).unwrap();
        w.open_write("file_name")
            .unwrap()
            .write_all("good data".as_bytes())
            .unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec("new".to_string()),
            fetched: false,
            ..Default::default()
        })
        .unwrap();

        let r = cache
            .read_dir(&test_key)
            .unwrap()
            .open_read("file_name")
            .unwrap();
        assert_eq!("good data", std::io::read_to_string(r).unwrap());
        let meta = EntryMeta::read(&cache.inner().fs, &test_key).unwrap();
        assert_eq!(meta.inner.spec_name(), Some(&"new".to_string()));
    }

    #[test]
    fn iter_entries_lists_all() {
        use std::io::Write;
        let tmp_dir = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp_dir.path()).unwrap();

        let keys: Vec<SpecHash> = (0..5)
            .map(|i| SpecHash(blake3::hash(format!("key-{}", i).as_bytes())))
            .collect();

        for key in &keys {
            let w = cache.write_dir(key).unwrap();
            w.open_write("f").unwrap().write_all(b"x").unwrap();
            w.finalize(EntryMeta {
                inner: MetaInner::Spec("s".to_string()),
                fetched: false,
                ..Default::default()
            })
            .unwrap();
        }

        let mut found: Vec<SpecHash> = cache.iter_entries().collect();
        found.sort();
        let mut expected = keys.clone();
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn unsafe_get_by_name() {
        use std::io::Write;
        let tmp_dir = TempDir::new().unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let key1 = SpecHash(blake3::hash("key1".as_bytes()));
        let key2 = SpecHash(blake3::hash("key2".as_bytes()));

        let w = cache.write_dir(&key1).unwrap();
        let m = EntryMeta {
            inner: MetaInner::Spec("spec".to_string()),
            fetched: false,
            ..Default::default()
        };
        w.open_write("file_name")
            .unwrap()
            .write_all("old data".as_bytes())
            .unwrap();
        w.finalize(m.clone()).unwrap();

        // Write again and change the data in the file
        let w = cache.write_dir(&key2).unwrap();
        w.open_write("file_name")
            .unwrap()
            .write_all("new data".as_bytes())
            .unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec("spec".to_string()),
            fetched: true,
            epoch_millis: m.epoch_millis + 1000,
            ..Default::default()
        })
        .unwrap();

        // Make sure the returned dir was the latest write with that name
        let dir = cache.unsafe_get_build_by_name("spec").unwrap();
        let r = dir.open_read("file_name").unwrap();
        assert_eq!("new data", std::io::read_to_string(r).unwrap());
        assert_eq!(dir.hash, key2);
    }
}
