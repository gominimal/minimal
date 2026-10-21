//! The store: where objects and repository copies live on disk, and the few
//! file operations every part of the daemon shares.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use common::mirror::{CacheKey, CacheOrigin, RepoSlug};

/// The store's layout under one root (MIR-044).
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the store's directories at mode 0700 and clears the temporary
    /// directory, so no partial object from an earlier run is visible or kept
    /// (MIR-073).
    pub fn init(&self) -> io::Result<()> {
        for dir in [self.root.clone(), self.cache_root(), self.git_root()] {
            fs::create_dir_all(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let tmp = self.tmp_dir();
        if tmp.exists() {
            fs::remove_dir_all(&tmp)?;
        }
        fs::create_dir_all(&tmp)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn cache_root(&self) -> PathBuf {
        self.root.join("c")
    }

    fn git_root(&self) -> PathBuf {
        self.root.join("git")
    }

    /// Where in-flight writes land before their rename.
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// A fresh temporary path for one write.
    pub fn tmp_path(&self) -> PathBuf {
        let unique = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        self.tmp_dir().join(unique)
    }

    /// One cache object's file: `c/<origin>/<key>`.
    pub fn object_path(&self, origin: &CacheOrigin, key: &CacheKey) -> PathBuf {
        self.cache_root()
            .join(origin.as_str())
            .join(key.to_string())
    }

    /// The validator the origin gave for a mutable object, beside it.
    pub fn etag_path(&self, origin: &CacheOrigin, key: &CacheKey) -> PathBuf {
        let mut path = self.object_path(origin, key).into_os_string();
        path.push(".etag");
        PathBuf::from(path)
    }

    /// One repository copy's directory: `git/<slug>`.
    pub fn repo_dir(&self, slug: &RepoSlug) -> PathBuf {
        self.git_root().join(slug.as_str())
    }

    /// The bare mirror clone inside a copy's directory.
    pub fn repo_git(&self, slug: &RepoSlug) -> PathBuf {
        self.repo_dir(slug).join("repo.git")
    }

    /// The bundle served to a guest, inside a copy's directory.
    pub fn bundle_path(&self, slug: &RepoSlug) -> PathBuf {
        self.repo_dir(slug).join("bundle")
    }

    /// Moves a finished temporary file into place, creating the parents.
    pub fn commit(&self, tmp: &Path, dest: &Path) -> io::Result<()> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(tmp, dest)
    }

    /// Records a request for an object: its modification time is its last
    /// request (MIR-033).
    pub fn touch(path: &Path) -> io::Result<()> {
        let file = fs::OpenOptions::new().append(true).open(path)?;
        file.set_modified(SystemTime::now())
    }

    /// How long ago an object was last written or requested.
    pub fn age(path: &Path) -> Option<Duration> {
        let modified = fs::metadata(path).ok()?.modified().ok()?;
        SystemTime::now().duration_since(modified).ok()
    }

    /// The bytes every file under the root takes.
    pub fn used_bytes(&self) -> u64 {
        walkdir::WalkDir::new(&self.root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    /// Every repository slug that has a copy.
    pub fn repo_slugs(&self) -> Vec<RepoSlug> {
        let root = self.git_root();
        walkdir::WalkDir::new(&root)
            .min_depth(2)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_name() == "repo.git" && e.file_type().is_dir())
            .filter_map(|e| {
                let rel = e.path().parent()?.strip_prefix(&root).ok()?;
                RepoSlug::parse(rel.to_str()?).ok()
            })
            .collect()
    }
}
