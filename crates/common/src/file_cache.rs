use crate::Tee;
use crate::fetchers::{self, FetchResponse, FetchUrl};

use either::Either;
use ot::OpTracker;
use sha2::{Digest, Sha256};

use std::fmt::{self};
use std::fs::{self};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;

/// An error when using [FileCache].
#[derive(Debug)]
pub enum FileCacheError {
    /// An I/O error occurred.
    IO(std::io::Error),
    /// The sha256 hash value was malformed.
    BadSha,
    /// The sha256 hash that was requested differed from what was written/downloaded.
    HashMismatch { want: String, got: String },
    /// The cache is in offline mode and the requested entry is not present.
    /// Caller asked for a file we'd need to download, but `--no-fetch` is set.
    OfflineCacheMiss { sha256: String, filename: String },
    /// Something unexpected.
    Internal(String),
}

impl From<std::io::Error> for FileCacheError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl fmt::Display for FileCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileCacheError::IO(e) => write!(f, "I/O error: {}", e),
            FileCacheError::BadSha => write!(f, "Bad SHA256 value"),
            FileCacheError::HashMismatch { want, got } => {
                write!(f, "HashMismatch: want={}, got={}", want, got)
            }
            FileCacheError::OfflineCacheMiss { sha256, filename } => write!(
                f,
                "offline cache miss for {filename} ({sha256}) — \
                 --no-fetch is set; pre-populate the cache or remove the flag"
            ),
            FileCacheError::Internal(e) => write!(f, "internal: {}", e),
        }
    }
}

impl std::error::Error for FileCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileCacheError::IO(e) => Some(e),
            _ => None,
        }
    }
}

/// Something that manages a cache of files on the filesystem, keyed by SHA-256 hash and filename.
#[derive(Debug, Clone)]
pub struct FileCache {
    base_dir: PathBuf,
    /// When true, [CachingDownloader] returns [FileCacheError::OfflineCacheMiss] on cache
    /// miss instead of attempting a network download. Set to mirror the value of
    /// [`mctx::Config::use_remote_cache`] (i.e. `--no-fetch`).
    offline: bool,
}

impl FileCache {
    /// Creates a new file cache rooted at the given directory.
    pub fn new(dir: PathBuf) -> Result<Self, FileCacheError> {
        Self::new_with_offline(dir, false)
    }

    /// Creates a new file cache rooted at the given directory, optionally in offline
    /// mode. In offline mode, any cache miss surfaces as an error rather than a silent
    /// network fetch.
    pub fn new_with_offline(dir: PathBuf, offline: bool) -> Result<Self, FileCacheError> {
        match fs::create_dir_all(&dir) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            }
        };

        Ok(Self {
            base_dir: dir,
            offline,
        })
    }

    /// Returns whether this cache rejects network fetches on cache miss.
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    fn sha_dir(&self, sha256: &str) -> Result<PathBuf, FileCacheError> {
        if sha256.contains("/") {
            return Err(FileCacheError::BadSha);
        }

        let dir_path = self.base_dir.join(sha256);
        match fs::metadata(&dir_path) {
            Ok(stat) => {
                if stat.is_dir() {
                    Ok(dir_path)
                } else {
                    Err(FileCacheError::IO(std::io::Error::new(
                        ErrorKind::NotADirectory,
                        dir_path.to_str().unwrap(),
                    )))
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    fs::create_dir(&dir_path)?;
                    Ok(dir_path)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Reads a file at the given directory with the given hash and file base of the URL.
    pub fn read_cached(
        &self,
        filename: &str,
        sha256: &str,
    ) -> Result<Option<PathBuf>, FileCacheError> {
        let cached_path = self.sha_dir(sha256)?.join(filename);

        // File exists in cache, try and use it if the hash matches
        if fs::exists(&cached_path)? {
            let computed_hash = {
                let mut f = fs::File::open(&cached_path)?;
                let mut hasher = super::HashWriter(Sha256::new());
                std::io::copy(&mut f, &mut hasher)?;

                hasher.0.finalize()
            };

            if hex::encode(computed_hash) == sha256 {
                Ok(Some(cached_path))
            } else {
                fs::remove_file(&cached_path)?;
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Drives the given response to read bytes and write them into the cache with the given filename
    /// and hash.
    pub async fn write_through<R>(
        &self,
        filename: &str,
        sha256: &str,
        response: &mut R,
        op: &OpTracker,
    ) -> Result<PathBuf, Either<FileCacheError, R::Error>>
    where
        R: fetchers::FetchResponse,
    {
        let cached_path = self.sha_dir(sha256).map_err(Either::Left)?.join(filename);

        let mut hasher = super::HashWriter(Sha256::new());
        {
            let mut f = fs::File::create(&cached_path).map_err(|e| Either::Left(e.into()))?;
            let mut w = Tee::new(&mut f, &mut hasher);

            if let Some(size) = response.content_length() {
                op.set_length(size);
            }
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        op.increment(chunk.len() as u64);
                        w.write_all(&chunk).unwrap();
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(e) => {
                        return Err(Either::Right(e));
                    }
                }
            }

            f.sync_all().map_err(|e| Either::Left(e.into()))?;
        }

        let computed_hash = hasher.0.finalize();
        let computed_hex = hex::encode(computed_hash);

        if computed_hex != sha256 {
            fs::remove_file(&cached_path).ok(); // ignore error, best effort
            Err(Either::Left(FileCacheError::HashMismatch {
                want: sha256.to_string(),
                got: computed_hex,
            }))
        } else {
            Ok(cached_path)
        }
    }
}

pub trait CachingDownloader<B: fetchers::FetchBackend> {
    fn download(
        &self,
        url: B::Url,
        sha256: &str,
        op: &OpTracker,
    ) -> impl Future<
        Output = Result<
            PathBuf,
            Either<FileCacheError, <B::Response as fetchers::FetchResponse>::Error>,
        >,
    >;
}

impl<B: fetchers::FetchBackend> CachingDownloader<B> for (&B, &FileCache) {
    async fn download(
        &self,
        url: <B as fetchers::FetchBackend>::Url,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<
        PathBuf,
        Either<
            FileCacheError,
            <<B as fetchers::FetchBackend>::Response as fetchers::FetchResponse>::Error,
        >,
    > {
        let filename = url.filename();

        // Return cached if exists
        if let Some(p) = self
            .1
            .read_cached(&filename, sha256)
            .map_err(Either::Left)?
        {
            return Ok(p);
        }

        // Cache miss: in offline mode this is a hard error (caller asked for
        // a file we'd need network to fetch). Otherwise fall through to fetch.
        if self.1.offline {
            return Err(Either::Left(FileCacheError::OfflineCacheMiss {
                sha256: sha256.to_string(),
                filename: filename.to_string(),
            }));
        }

        // Otherwise download
        let mut r = self
            .0
            .execute(self.0.get(url).map_err(Either::Right)?)
            .await
            .map_err(Either::Right)?
            .error_for_status()
            .map_err(Either::Right)?;

        self.1.write_through(&filename, sha256, &mut r, op).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// A fake [FetchResponse] that yields data from a pre-loaded buffer.
    #[derive(Debug)]
    struct FakeResponse {
        data: Option<Bytes>,
    }

    impl FakeResponse {
        fn new(data: &[u8]) -> Self {
            Self {
                data: Some(Bytes::copy_from_slice(data)),
            }
        }
    }

    impl fetchers::FetchResponse for FakeResponse {
        type Error = std::convert::Infallible;

        fn error_for_status(self) -> Result<Self, Self::Error> {
            Ok(self)
        }
        fn is_success(&self) -> bool {
            true
        }
        fn status_code(&self) -> usize {
            200
        }
        fn content_length(&self) -> Option<u64> {
            self.data.as_ref().map(|d| d.len() as u64)
        }
        async fn bytes(self) -> Result<Bytes, Self::Error> {
            Ok(self.data.unwrap_or_default())
        }
        async fn chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
            Ok(self.data.take())
        }
    }

    #[tokio::test]
    async fn write_through_hash_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = FileCache::new(tmp.path().to_path_buf()).unwrap();
        let op = OpTracker::new_with_root(&None);

        let content = b"hello world";
        let wrong_sha = "0000000000000000000000000000000000000000000000000000000000000000";

        let mut resp = FakeResponse::new(content);
        let result = cache
            .write_through("test.txt", wrong_sha, &mut resp, &op)
            .await;

        let err = result.unwrap_err().unwrap_left();
        match err {
            FileCacheError::HashMismatch { want, got } => {
                assert_eq!(want, wrong_sha);
                // Verify the 'got' hash is the real sha256 of "hello world".
                let expected = {
                    let mut h = sha2::Sha256::new();
                    sha2::Digest::update(&mut h, content);
                    hex::encode(h.finalize())
                };
                assert_eq!(got, expected);
            }
            other => panic!("expected HashMismatch, got: {other}"),
        }

        // The mismatched file should have been cleaned up.
        let cached = cache.sha_dir(wrong_sha).unwrap().join("test.txt");
        assert!(
            !cached.exists(),
            "file should be removed after hash mismatch"
        );
    }
}
