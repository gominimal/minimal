//! Implementations of caches storing artifacts keyed by [SpecHash].

use common::SpecHash;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
mod fs;
pub use fs::FSError;
pub use fs::FileSystem;
pub use fs::LocalDir;

#[allow(dead_code)]
mod remote;
pub use remote::{Error as RemoteError, RemoteCache};

use crate::fs::DirEntry;
#[allow(dead_code)]
mod remote_index;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntryMeta {
    pub spec_name: String,
    pub fetched: bool,
    pub epoch_millis: u128,
}

impl Default for EntryMeta {
    fn default() -> Self {
        EntryMeta {
            spec_name: "".to_string(),
            fetched: false,
            epoch_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        }
    }
}

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
        std::fs::remove_dir_all(st.path())?;
        std::fs::rename(self.tempdir.keep(), st.path())?;
        drop(st);

        let f = inner.fs.open_write(format!("meta/{}.json", hash_hex))?;
        serde_json::to_writer(f, &meta).map_err(std::io::Error::from)?;
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

/// A blob in the cache you can read or write.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileCacheEntry<FS: FileSystem> {
    c: Cache<FS>,
    hash: SpecHash,
    file: FS::File,
}

impl<FS: FileSystem> std::io::Read for FileCacheEntry<FS> {
    // Required method
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.file.read(buf)
    }
    // TODO: Implement passthroughs for the provided methods
}

impl<FS: FileSystem> std::io::Seek for FileCacheEntry<FS> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, std::io::Error> {
        self.file.seek(pos)
    }
    // TODO: Implement passthroughs for the provided methods
}

impl<FS: FileSystem> std::io::Write for FileCacheEntry<FS> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.file.flush()
    }
    // TODO: Implement passthroughs for the provided methods
}

/// The implementation of [Cache].
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CacheInner<FS: FileSystem> {
    fs: FS,
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
        let inner = CacheInner {
            fs: LocalDir::with_base(p)?,
        };

        for dir in &["temp", "meta"] {
            match inner.fs.mkdir(dir) {
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

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Allocates a temporary directory in the same filesystem as the rest of the cache.
    pub fn temp_dir(&self) -> Result<tempfile::TempDir, std::io::Error> {
        let inner = self.inner();
        tempfile::tempdir_in(inner.fs.path().join("temp"))
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

    /// Invalidates (deletes) a directory cache entry with the given spec hash.
    pub fn invalidate_dir(&self, hash: &SpecHash) -> Result<(), CacheErr> {
        let hash_hex = hash.0.to_hex();
        // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
        let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
            .iter()
            .collect();

        self.inner().fs.remove_dir(subpath).map_err(CacheErr::from)
    }

    /// Reads a file cached as the given spec hash.
    pub fn read_file(&self, hash: &SpecHash) -> Result<FileCacheEntry<FS>, CacheErr> {
        let hash_hex = hash.0.to_hex();
        // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
        let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
            .iter()
            .collect();

        let file = self.inner().fs.open_read(subpath).map_err(|e| {
            if let std::io::ErrorKind::NotFound = e.kind() {
                CacheErr::NotFound
            } else {
                e.into()
            }
        })?;

        Ok(FileCacheEntry {
            c: self.clone(),
            file,
            hash: hash.clone(),
        })
    }

    /// Reads a directory cached as the given spec hash.
    pub fn read_dir(&self, hash: &SpecHash) -> Result<DirCacheEntry<FS>, CacheErr> {
        Ok(DirCacheEntry {
            c: self.clone(),
            tree: self.inner().dir(hash)?,
            hash: hash.clone(),
        })
    }

    /// Returns a handle for writing a file into the cache as a given spec hash.
    pub fn write_file(&self, hash: &SpecHash) -> Result<FileCacheEntry<FS>, CacheErr> {
        let file = {
            let mut inner = self.inner();
            let hash_hex = hash.0.to_hex();
            inner.ensure_hash_dir_exists(hash.as_bytes()[0])?;

            // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
            let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
                .iter()
                .collect();

            inner.fs.open_write(subpath)?
        };

        Ok(FileCacheEntry {
            c: self.clone(),
            file,
            hash: hash.clone(),
        })
    }

    /// Returns the cache entry that was most recently generated by a spec of the given name.
    ///
    /// NOTE: This method breaks the caching model and should not be used unless you know what you are doing!!
    pub fn unsafe_get_by_name(&self, name: &str) -> Result<DirCacheEntry<FS>, CacheErr> {
        let mut candidates = Vec::new();

        {
            let inner = self.inner();
            for e in inner.fs.read_dir("meta")? {
                let f = inner.fs.open_read(e.path()?)?;
                let entry: EntryMeta = serde_json::from_reader(f).map_err(std::io::Error::from)?;
                if entry.spec_name == name {
                    let p = e.path()?;
                    candidates.push((
                        p.file_name()
                            .map(|n| n.to_str().unwrap())
                            .unwrap()
                            .strip_suffix(".json")
                            .unwrap()
                            .to_ascii_lowercase(),
                        entry.epoch_millis,
                    ));
                }
            }
        }
        candidates.sort_by(|a, b| a.1.cmp(&b.1).reverse());

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
    graph: &'a graph::DepGraph,
    cache: Cache<LocalDir>,
}

impl<'a> CacheBinProvider<'a> {
    pub fn new(graph: &'a graph::DepGraph, cache: Cache<LocalDir>) -> Self {
        Self { graph, cache }
    }
}

impl<'a> graph::BinProvider for CacheBinProvider<'a> {
    fn exists(&self, bsr: &graph::BuildSpecRef) -> bool {
        self.cache.read_dir(&self.graph.spec_hash(bsr)).is_ok()
    }
}

/// An adapter that lets you use a [RemoteCache] as a [graph::BinProvider].
#[derive(Debug, Clone)]
pub struct RemoteBinProvider<'a, B: common::fetchers::FetchBackend> {
    graph: &'a graph::DepGraph,
    remote: &'a RemoteCache<B>,
}

impl<'a, B: common::fetchers::FetchBackend> RemoteBinProvider<'a, B> {
    pub fn new(graph: &'a graph::DepGraph, remote: &'a RemoteCache<B>) -> Self {
        Self { graph, remote }
    }
}

impl<'a, B: common::fetchers::FetchBackend> graph::BinProvider for RemoteBinProvider<'a, B> {
    fn exists(&self, bsr: &graph::BuildSpecRef) -> bool {
        self.remote.exists(&self.graph.spec_hash(bsr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn smoketest_files() {
        let tmp_dir = TempDir::new().unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let test_key = SpecHash(blake3::hash("swiggity swooty".as_bytes()));

        let mut w = cache.write_file(&test_key).unwrap();
        w.write_all("uwu".as_bytes()).unwrap();
        drop(w);

        let r = cache.read_file(&test_key).unwrap();
        assert_eq!("uwu", std::io::read_to_string(r).unwrap());
    }

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
            spec_name: "".to_string(),
            fetched: false,
            ..Default::default()
        })
        .unwrap();

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
            spec_name: "".to_string(),
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
            spec_name: "".to_string(),
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
            spec_name: "".to_string(),
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
    }
}
