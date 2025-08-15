use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[allow(dead_code)]
mod fs;
pub use fs::FSError;
pub use fs::FileSystem;
pub use fs::LocalDir;

/// A directory tree in the cache you can read or write.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DirCacheEntry<FS: FileSystem> {
    c: Cache<FS>,
    hash: blake3::Hash,
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
}

/// A blob in the cache you can read or write.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileCacheEntry<FS: FileSystem> {
    c: Cache<FS>,
    hash: blake3::Hash,
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

    fn dir(&self, hash: blake3::Hash) -> Result<FS::Subtree, CacheErr> {
        let hash_hex = hash.to_hex();
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
    pub fn at_dir<P: AsRef<Path>>(p: P) -> Result<Self, std::io::Error> {
        let inner = CacheInner {
            fs: LocalDir::with_base(p)?,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
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

    pub fn read_file(&self, hash: blake3::Hash) -> Result<FileCacheEntry<FS>, CacheErr> {
        let hash_hex = hash.to_hex();
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
            hash,
        })
    }

    pub fn read_dir(&self, hash: blake3::Hash) -> Result<DirCacheEntry<FS>, CacheErr> {
        Ok(DirCacheEntry {
            c: self.clone(),
            tree: self.inner().dir(hash)?,
            hash,
        })
    }
    pub fn write_dir(&self, hash: blake3::Hash) -> Result<DirCacheEntry<FS>, CacheErr> {
        let mut inner = self.inner();
        inner.ensure_hash_dir_exists(hash.as_bytes()[0])?;

        let hash_hex = hash.to_hex();
        // Entries on disk are at <root>/<first byte as hex>/<remaining bytes as hex>
        let subpath: PathBuf = [&hash_hex.as_str()[0..2], &hash_hex.as_str()[2..]]
            .iter()
            .collect();
        inner.fs.mkdir(subpath)?;

        Ok(DirCacheEntry {
            c: self.clone(),
            tree: inner.dir(hash)?,
            hash,
        })
    }

    pub fn write_file(&self, hash: blake3::Hash) -> Result<FileCacheEntry<FS>, CacheErr> {
        let file = {
            let mut inner = self.inner();
            let hash_hex = hash.to_hex();
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
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempdir::TempDir;

    #[test]
    fn smoketest_files() {
        let tmp_dir = TempDir::new("cache-smoketest").unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let test_key = blake3::hash("swiggity swooty".as_bytes());

        let mut w = cache.write_file(test_key).unwrap();
        w.write_all("uwu".as_bytes()).unwrap();
        drop(w);

        let r = cache.read_file(test_key).unwrap();
        assert_eq!("uwu", std::io::read_to_string(r).unwrap());
    }

    #[test]
    fn smoketest_folder() {
        let tmp_dir = TempDir::new("cache-smoketest").unwrap();

        let cache = Cache::at_dir(tmp_dir.path()).unwrap();
        let test_key = blake3::hash("direct-tory".as_bytes());

        let w = cache.write_dir(test_key).unwrap();
        use std::io::Write;
        w.open_write("file_name")
            .unwrap()
            .write_all("uwu".as_bytes())
            .unwrap();
        drop(w);

        let r = cache
            .read_dir(test_key)
            .unwrap()
            .open_read("file_name")
            .unwrap();
        assert_eq!("uwu", std::io::read_to_string(r).unwrap());
    }
}
