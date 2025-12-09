use crate::Tee;
use crate::fetchers::{self, FetchUrl};

use either::Either;
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
}

impl FileCache {
    /// Creates a new file cache rooted at the given directory.
    pub async fn new(dir: PathBuf) -> Result<Self, FileCacheError> {
        match fs::create_dir_all(&dir) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            }
        };

        Ok(Self { base_dir: dir })
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
                let mut hasher = Sha256::new();
                std::io::copy(&mut f, &mut hasher)?;

                hasher.finalize()
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
    ) -> Result<PathBuf, Either<FileCacheError, R::Error>>
    where
        R: fetchers::FetchResponse,
    {
        let cached_path = self.sha_dir(sha256).map_err(Either::Left)?.join(filename);

        let mut hasher = Sha256::new();
        {
            let mut f = fs::File::create(&cached_path).map_err(|e| Either::Left(e.into()))?;
            let mut w = Tee::new(&mut f, &mut hasher);

            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => w.write_all(&chunk).unwrap(),
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

        let computed_hash = hasher.finalize();
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
    ) -> impl Future<
        Output = Result<
            PathBuf,
            Either<FileCacheError, <B::Response as fetchers::FetchResponse>::Error>,
        >,
    >;
}

impl<B: fetchers::FetchBackend> CachingDownloader<B> for (B, FileCache) {
    async fn download(
        &self,
        url: <B as fetchers::FetchBackend>::Url,
        sha256: &str,
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

        // Otherwise download
        let mut r = self
            .0
            .execute(self.0.get(url).map_err(Either::Right)?)
            .await
            .map_err(Either::Right)?;

        self.1.write_through(&filename, sha256, &mut r).await
    }
}
