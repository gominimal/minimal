//! Common types and utilities used across the minimal codebase.

pub mod archive;
pub mod fetchers;
pub mod file_cache;
pub mod fuzzy_search;
pub mod jq;
mod remote_storage;
pub use remote_storage::RemoteStorage;

#[cfg(target_os = "linux")]
pub mod renameat2;

pub mod repo_spec;
mod spec_hash;
pub use spec_hash::SpecHash;
mod subsets;
pub use subsets::SubsetSpec;
pub mod target;
pub use target::Target;
pub mod ncl_eval;

use std::{
    env, fmt,
    hash::Hash,
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
};
use tracing::warn;

/// Describes where a build-spec came from.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SpecOrigin {
    /// Filetree of nickel came from a path on the filesystem, not necessarily under VCS.
    LocalDir { given: PathBuf, absolute: PathBuf },
    /// Filetree came from a checkout of a VCS repo.
    Repo(repo_spec::Repo),
    /// Nickel was given inline and cannot be attributed to somewhere - usually for tests.
    #[default]
    Inline,
}

impl SpecOrigin {
    /// Constructs a [SpecOrigin] from the given directory on the system. Do not use this
    /// if the directory represents a checked-out pristine repo, for that case,
    /// use [SpecOrigin::Repo] instead.
    pub fn from_dir<P: AsRef<Path>>(p: P) -> Self {
        let p = p.as_ref();
        match p.is_absolute() {
            true => SpecOrigin::LocalDir {
                given: p.to_path_buf(),
                absolute: p.to_path_buf(),
            },
            false => SpecOrigin::LocalDir {
                given: p.to_path_buf(),
                absolute: env::current_dir().unwrap().join(p).canonicalize().unwrap(),
            },
        }
    }

    pub fn as_repo(&self) -> Option<&repo_spec::Repo> {
        if let SpecOrigin::Repo(r) = self {
            Some(r)
        } else {
            None
        }
    }
}

impl Hash for SpecOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Inline => state.write_u8(0), // type marker: 0 == Inline
            Self::LocalDir { given, absolute } => {
                state.write_u8(1); // type marker: 1 == LocalDir
                state.write(given.as_os_str().as_encoded_bytes());
                state.write_u8(b',');
                state.write(absolute.as_os_str().as_encoded_bytes());
            }
            Self::Repo(r) => {
                state.write_u8(2); // type marker: 2 == Repo
                match r {
                    repo_spec::Repo::Git { url, rev, tracking } => {
                        state.write(url.as_bytes());
                        state.write_u8(b',');
                        state.write(rev.as_bytes());
                        state.write_u8(b',');
                        match tracking {
                            Some(repo_spec::GitRef::Branch(b)) => {
                                state.write(b.as_bytes());
                            }
                            Some(repo_spec::GitRef::Tag(t)) => {
                                state.write_u8(b't');
                                state.write(t.as_bytes());
                            }
                            None => {}
                        }
                    }
                }
            }
        }
    }
}

/// Implements [Write], mirroring all writes to two underlying writers.
#[derive(Debug)]
pub struct Tee<W1: Write, W2: Write> {
    writer1: W1,
    writer2: W2,
}

impl<W1: Write, W2: Write> Tee<W1, W2> {
    /// Creates a new tee, where all writes are mirrorred to both given writers.
    pub fn new(writer1: W1, writer2: W2) -> Self {
        Tee { writer1, writer2 }
    }

    /// Deconstructs the [Tee], returning the two internal writers.
    pub fn into_inner(self) -> (W1, W2) {
        (self.writer1, self.writer2)
    }
}

impl<W1: Write, W2: Write> Write for Tee<W1, W2> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer1.write_all(buf)?;
        self.writer2.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer1.flush()?;
        self.writer2.flush()?;
        Ok(())
    }
}

/// Wrapper that implements [Write] for types implementing [sha2::Digest],
/// since `digest` 0.11 no longer provides a blanket `std::io::Write` impl.
pub struct HashWriter<D: sha2::Digest>(pub D);

impl<D: sha2::Digest> Write for HashWriter<D> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        sha2::Digest::update(&mut self.0, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The error produced by calls to [hardlink_dir_contents].
#[derive(Debug)]
pub enum HardlinkError {
    IO(&'static str, PathBuf, std::io::Error),
    HardlinkFailed(PathBuf, PathBuf, std::io::Error),
}

impl fmt::Display for HardlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardlinkError::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            HardlinkError::HardlinkFailed(from, to, e) => write!(
                f,
                "failed to hardlink {} to {}: {}",
                from.display(),
                to.display(),
                e
            ),
        }
    }
}

impl std::error::Error for HardlinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HardlinkError::IO(_, _, e) => Some(e),
            HardlinkError::HardlinkFailed(_, _, e) => Some(e),
        }
    }
}

/// Creates a hardlink farm in dst representing files in src, recursively.
pub fn hardlink_dir_contents(src: &Path, dst: &Path) -> Result<(), HardlinkError> {
    use std::fs;

    for entry in
        fs::read_dir(src).map_err(|e| HardlinkError::IO("read directory", src.to_path_buf(), e))?
    {
        let entry =
            entry.map_err(|e| HardlinkError::IO("read directory entry", src.to_path_buf(), e))?;

        let path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        let metadata = entry
            .metadata()
            .map_err(|e| HardlinkError::IO("get metadata", path.to_path_buf(), e))?;

        if metadata.is_dir() {
            fs::create_dir_all(&dst_path)
                .map_err(|e| HardlinkError::IO("create directory", dst_path.clone(), e))?;
            hardlink_dir_contents(&path, &dst_path)?;
        } else if metadata.is_file() {
            match fs::hard_link(&path, &dst_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    warn!(
                        "Not linking {} => {}, already exists",
                        path.display(),
                        dst_path.display()
                    );
                    Ok(())
                }
                // The cache and destination can live on different filesystems
                // (e.g. a per-VM `/state` volume vs. the rootfs holding
                // `/home`), where hardlinks are impossible (`EXDEV`). Fall back
                // to a copy so materialization still succeeds — slower and no
                // longer deduplicated, but correct.
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                    // Every file in a cross-device tree hits EXDEV, so warn only
                    // on the first — a per-file log would flood with thousands
                    // of identical lines. Once-per-process is enough: the cause
                    // is a fixed filesystem-layout fact, not a per-file
                    // condition.
                    use std::sync::atomic::{AtomicBool, Ordering};
                    static WARNED: AtomicBool = AtomicBool::new(false);
                    if !WARNED.swap(true, Ordering::Relaxed) {
                        warn!(
                            "Copying instead of hardlinking: cache and \
                             destination are on different filesystems; further \
                             cross-device copies this run are silent (first: {} \
                             => {})",
                            path.display(),
                            dst_path.display()
                        );
                    }
                    fs::copy(&path, &dst_path).map(|_| ())
                }
                Err(e) => Err(e),
            }
            .map_err(|e| HardlinkError::HardlinkFailed(path.to_path_buf(), dst_path, e))?;
        } else if metadata.is_symlink() {
            use std::os::unix::fs::symlink;

            let target = fs::read_link(&path)
                .map_err(|e| HardlinkError::IO("read symlink", path.to_path_buf(), e))?;
            match symlink(&target, &dst_path) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        warn!(
                            "Not symlinking {} => {}, already exists",
                            path.display(),
                            dst_path.display()
                        );
                        Ok(())
                    } else {
                        Err(HardlinkError::IO("create symlink", dst_path, e))
                    }
                }
            }?;
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum GlobError {
    IO(std::io::Error),
    Glob(globset::Error),
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlobError::IO(e) => {
                write!(f, "I/O error: {}", e)
            }
            GlobError::Glob(e) => write!(f, "glob error: {}", e),
        }
    }
}

impl std::error::Error for GlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GlobError::IO(e) => Some(e),
            GlobError::Glob(e) => Some(e),
        }
    }
}

impl From<globset::Error> for GlobError {
    fn from(e: globset::Error) -> Self {
        GlobError::Glob(e)
    }
}

impl From<std::io::Error> for GlobError {
    fn from(e: std::io::Error) -> Self {
        GlobError::IO(e)
    }
}

/// Enumerates files which match the given glob within the given directory.
pub fn match_files_for_glob(dir: &Path, glob: &str) -> Result<Vec<PathBuf>, GlobError> {
    let mut results = Vec::new();

    let matcher = globset::GlobBuilder::new(glob)
        .literal_separator(true)
        .empty_alternates(true)
        .build()?
        .compile_matcher();

    // Walk the filesystem starting from root_dir
    fn walk_dir(
        dir: &Path,
        root_dir: &Path,
        matcher: &globset::GlobMatcher,
        results: &mut Vec<PathBuf>,
    ) -> Result<(), GlobError> {
        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;

            let path = entry.path();
            let subset = path.strip_prefix(root_dir).unwrap();
            if path.is_file() && matcher.is_match(subset) {
                results.push(path);
            } else if path.is_dir() {
                // Recursively walk subdirectories
                walk_dir(&path, root_dir, matcher, results)?;
            }
        }

        Ok(())
    }

    walk_dir(dir, dir, &matcher, &mut results)?;
    Ok(results)
}

pub fn synth_dns_config(p: &Path) -> Result<(), io::Error> {
    let conf = if let Ok(c) = std::fs::read_to_string("/etc/resolv.conf") {
        match resolv_conf::Config::parse(c) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(
                    "Failed parsing /etc/resolv.conf, falling back to quad-8. Error: {}",
                    e
                );
                None
            }
        }
    } else {
        None
    };
    let conf = match conf {
        Some(c) => c,
        None => {
            let mut config = resolv_conf::Config::new();
            config
                .nameservers
                .push(resolv_conf::ScopedIp::V4(std::net::Ipv4Addr::new(
                    8, 8, 8, 8,
                )));
            config
        }
    };

    std::fs::create_dir_all(p.join("etc"))?;
    std::fs::write(p.join("etc").join("resolv.conf"), format!("{}", conf))
}

pub fn synth_user_group_config(p: &Path, username: &str, home: &str) -> Result<(), io::Error> {
    std::fs::create_dir_all(p.join("etc"))?;
    std::fs::write(
        p.join("etc").join("passwd"),
        format!(
            "root:x:0:0:root:/root:/usr/bin/bash\n{}:x:1000:1000:User,,,:{}:/bin/bash",
            username, home
        ),
    )?;
    std::fs::write(
        p.join("etc").join("group"),
        format!(
            "root:x:0:\nusers:x:100:{}\nnogroup:x:65534:\n{}:x:1000:\n",
            username, username
        ),
    )
}

pub fn random_alphanumeric(length: usize) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Recursively copies a directory from one path to another.
pub fn copy_directory<Q: AsRef<Path>, P: AsRef<Path>>(from: P, to: Q) -> Result<(), io::Error> {
    copy_dir::copy_dir(from, to)?;
    Ok(())
}

/// Returns true if the specified command exists in a directory configured by the PATH variable.
pub fn command_exists(command: &str) -> Result<bool, io::Error> {
    let path_var = match env::var_os("PATH") {
        Some(p) => p,
        None => return Ok(false),
    };

    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(command);

        let candidates = vec![candidate];
        for path in candidates {
            match std::fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        return Ok(true);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            }
        }
    }

    Ok(false)
}

/// An [`tokio::io::AsyncWrite`] implementation that emits complete lines as tracing events.
///
/// Stdout lines are emitted at `INFO` level, stderr lines at `WARN` level.
/// Events are emitted with no parent span (`parent: tracing::Span::none()`) so
/// they don't inherit noisy span context from the caller.
pub struct TracingWriter {
    buf: Vec<u8>,
    is_stderr: bool,
    target: Option<String>,
}

impl TracingWriter {
    /// Creates a writer that emits lines at `INFO` level.
    pub fn stdout() -> Self {
        Self {
            buf: Vec::new(),
            is_stderr: false,
            target: None,
        }
    }

    /// Creates a writer that emits lines at `WARN` level.
    pub fn stderr() -> Self {
        Self {
            buf: Vec::new(),
            is_stderr: true,
            target: None,
        }
    }

    /// Sets the tracing target for emitted log lines (e.g. a package name).
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    fn emit_line(&self, line: &str) {
        match (&self.target, self.is_stderr) {
            (Some(t), true) => tracing::warn!(parent: tracing::Span::none(), "{}: {}", t, line),
            (Some(t), false) => tracing::info!(parent: tracing::Span::none(), "{}: {}", t, line),
            (None, true) => tracing::warn!(parent: tracing::Span::none(), "{}", line),
            (None, false) => tracing::info!(parent: tracing::Span::none(), "{}", line),
        }
    }

    fn emit_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
            self.emit_line(&line);
            self.buf.drain(..=pos);
        }
    }

    fn emit_remaining(&mut self) {
        if !self.buf.is_empty() {
            let line = String::from_utf8_lossy(&self.buf).into_owned();
            self.emit_line(&line);
            self.buf.clear();
        }
    }
}

impl tokio::io::AsyncWrite for TracingWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        self.buf.extend_from_slice(buf);
        self.emit_lines();
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        self.emit_remaining();
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for TracingWriter {
    fn drop(&mut self) {
        self.emit_remaining();
    }
}

/// Describes a file or directory mapped from the host to the sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsMapping {
    /// The path on the host which will be mapped into the sandbox.
    pub host_path: String,
    /// The path within the sandbox which will point to the host path.
    ///
    /// If unset, the path in the sandbox is the same as the host.
    pub sandbox_path: Option<String>,
    /// If set, the path is read-only within the sandbox.
    pub read_only: bool,

    /// The path represents a file, not a directory.
    pub is_file: bool,
    /// Create the file or directory if it does not exist.
    pub create_if_missing: bool,
}

impl FsMapping {
    pub fn path_in_sandbox(&self) -> String {
        match &self.sandbox_path {
            Some(p) => p.clone(),
            None => match std::env::var("MINIMAL_INTERNAL_PATCH_STRIP") {
                Err(_) => self.host_path.clone(),
                Ok(prefix) => match self.host_path.strip_prefix(&prefix) {
                    Some(stripped) => stripped.to_string(),
                    None => self.host_path.clone(),
                },
            },
        }
    }
}

fn get_cgroup_limit_gb() -> Option<f64> {
    // cgroup v2
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let trimmed = content.trim();
        if trimmed != "max"
            && let Ok(bytes) = trimmed.parse::<u64>()
        {
            return Some(bytes as f64 / 1_073_741_824.0);
        }
    }

    // cgroup v1
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        && let Ok(bytes) = content.trim().parse::<u64>()
    {
        // v1 reports a huge sentinel value (near u64::MAX) when unlimited
        if bytes < u64::MAX / 2 {
            return Some(bytes as f64 / 1_073_741_824.0);
        }
    }

    None
}

fn get_physical_ram_gb() -> Option<f64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
            return Some(kb as f64 / 1_048_576.0);
        }
    }

    None
}

/// Returns the amount of RAM in gigabytes available on the system to this process.
fn get_available_ram_gb() -> Option<u64> {
    let cgroup = get_cgroup_limit_gb();
    let physical = get_physical_ram_gb();

    match (cgroup, physical) {
        // Take whichever is smaller — cgroup can't exceed physical
        (Some(c), Some(p)) => Some(c.min(p)),
        (Some(c), None) => Some(c),
        (None, Some(p)) => Some(p),
        (None, None) => None,
    }
    .map(|v| v.floor() as u64)
}

/// Recursively removes the given directory, including setting permissions as writeable where needed.
///
/// Same as [std::fs::remove_dir_all] except it can also handle Golang cache directories.
pub fn remove_dir_all<P: AsRef<Path>>(dir: P) -> Result<(), std::io::Error> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            // remove_dir_all will fail if files are set as non-writeable even
            // if theres a path to delete them. Urgh. Only golang does this.
            //
            // We do the same thing as `go clean -modcache` to fix the horror of their
            // making.
            //
            // https://cs.opensource.google/go/go/+/refs/tags/go1.25.7:src/cmd/go/internal/modfetch/fetch.go;l=426-438
            for entry in walkdir::WalkDir::new(&dir) {
                if let Ok(entry) = entry
                    && entry.file_type().is_dir()
                {
                    fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o777)).ok();
                }
            }
            // Try again
            fs::remove_dir_all(dir)
        }
        Err(e) => Err(e),
    }
}

/// Returns the suggested number of parallel builds to run based on the number of cores and system memory.
pub fn default_parallelism() -> usize {
    let rough_threadcount = std::thread::available_parallelism().unwrap().get();
    let para_by_cpu = match rough_threadcount {
        0..=3 => 1,
        4..=7 => 3,
        8..=11 => 5,
        12..=14 => 7,
        15..=18 => 9,
        19..=21 => 11,
        22..=24 => 13,
        _ => (rough_threadcount - 24) / 3 + 15,
    };

    let para_by_mem = get_available_ram_gb().map(|gbs| match gbs {
        0..=6 => 1,
        7..=12 => 2,
        13..=19 => 3,
        _ => gbs / 5,
    });

    para_by_mem
        .map(|m| (m as usize).min(para_by_cpu))
        .unwrap_or(para_by_cpu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_user_group_config_sets_home_on_uid_1000() {
        let tmp = tempfile::tempdir().unwrap();
        synth_user_group_config(tmp.path(), "build", "/host/Users/bryan").unwrap();

        let passwd = std::fs::read_to_string(tmp.path().join("etc/passwd")).unwrap();
        // uid 1000 (the runtime uid) gets the passed-in home so user.Current()
        // returns a path that matches the HOME env var.
        assert!(
            passwd.contains("build:x:1000:1000:User,,,:/host/Users/bryan:"),
            "build line missing or wrong: {}",
            passwd
        );
    }
}
