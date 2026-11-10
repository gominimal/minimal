//! Common types and utilities used across the minimal codebase.

pub mod archive;
pub mod fetchers;
pub mod file_cache;
pub mod fuzzy_search;
pub mod jq;
mod remote_storage;
pub use remote_storage::{
    NO_NETWORK, NetNamespace, Placement, RULES_REFUSE, RemoteStorage, gcs_object_url,
};

#[cfg(target_os = "linux")]
pub mod renameat2;

pub mod repo_spec;
mod report;
pub use report::report_to_stderr;
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

/// Why a path that two layers both ship was not linked twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCollision {
    /// The destination is the same inode, or a regular file with the same
    /// bytes: the usual overlap, kept quiet.
    Same,
    /// Two regular files of equal size, too large to compare cheaply
    /// ([`COLLISION_COMPARE_MAX`]): kept quiet, but never called the same.
    Unchecked,
    /// The destination differs in a way worth a WARN per file.
    Differs(&'static str),
}

impl LinkCollision {
    /// The note a log line puts after "already exists".
    #[must_use]
    pub fn note(self) -> &'static str {
        match self {
            Self::Same => "same file",
            Self::Unchecked => "same size, too large to compare",
            Self::Differs(why) => why,
        }
    }
}

/// The collisions one or more [`hardlink_dir_contents_counted`] calls found,
/// by kind. The caller owns it, so concurrent assemblies never share counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinkCollisions {
    /// Same inode, same bytes, or a symlink to the same target.
    pub same: u64,
    /// Equal-size regular files too large to compare.
    pub unchecked: u64,
    /// Files or symlinks that differ: each one also logs a WARN.
    pub differ: u64,
}

impl LinkCollisions {
    fn add(&mut self, collision: LinkCollision) {
        let n = match collision {
            LinkCollision::Same => &mut self.same,
            LinkCollision::Unchecked => &mut self.unchecked,
            LinkCollision::Differs(_) => &mut self.differ,
        };
        *n = n.saturating_add(1);
    }

    /// Every collision counted, of any kind.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.same
            .saturating_add(self.unchecked)
            .saturating_add(self.differ)
    }
}

/// Equal-size collisions up to this size are compared byte for byte. A
/// version-string bump keeps the size and changes the bytes, so size alone
/// cannot call two files the same; above this, reading both would cost
/// more than the link it replaced.
const COLLISION_COMPARE_MAX: u64 = 4 << 20;

/// Compares the file at `src` (described by `src_meta`) with what already
/// sits at `dst`. Same (device, inode) is the same file. A destination that
/// is not a regular file (a symlink included: it is not followed) differs,
/// as does one of another size. Equal sizes are compared by content up to
/// [`COLLISION_COMPARE_MAX`].
fn hardlink_collision(src: &Path, src_meta: &std::fs::Metadata, dst: &Path) -> LinkCollision {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::symlink_metadata(dst) {
        Ok(d) if d.dev() == src_meta.dev() && d.ino() == src_meta.ino() => LinkCollision::Same,
        Ok(d) if !d.is_file() => LinkCollision::Differs("not a regular file"),
        Ok(d) if d.len() != src_meta.len() => LinkCollision::Differs("different size"),
        Ok(d) if d.len() > COLLISION_COMPARE_MAX => LinkCollision::Unchecked,
        Ok(_) => match (std::fs::read(src), std::fs::read(dst)) {
            (Ok(a), Ok(b)) if a == b => LinkCollision::Same,
            (Ok(_), Ok(_)) => LinkCollision::Differs("different content"),
            _ => LinkCollision::Differs("unreadable"),
        },
        Err(_) => LinkCollision::Differs("unreadable"),
    }
}

/// How the file at `src` compares with the one already at `dst`, by the
/// rule [`hardlink_dir_contents`] uses, for a caller that places single
/// files itself: quiet when they match, a WARN when they differ.
#[must_use]
pub fn link_collision(src: &Path, dst: &Path) -> LinkCollision {
    match std::fs::metadata(src) {
        Ok(src_meta) => hardlink_collision(src, &src_meta, dst),
        Err(_) => LinkCollision::Differs("unreadable"),
    }
}

/// Creates a hardlink farm in dst representing files in src, recursively.
pub fn hardlink_dir_contents(src: &Path, dst: &Path) -> Result<(), HardlinkError> {
    hardlink_dir_contents_counted(src, dst, &mut LinkCollisions::default())
}

/// [`hardlink_dir_contents`], adding each path already in place at `dst`
/// to `counts`. A caller that assembles a tree from several layers passes
/// one `counts` to every call and logs one summary line, instead of one
/// line per path.
pub fn hardlink_dir_contents_counted(
    src: &Path,
    dst: &Path,
    counts: &mut LinkCollisions,
) -> Result<(), HardlinkError> {
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
            hardlink_dir_contents_counted(&path, &dst_path, counts)?;
        } else if metadata.is_file() {
            match fs::hard_link(&path, &dst_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Two layers of one closure shipping the same path is the
                    // rule, not the exception. The first-linked file stays;
                    // the collision is a WARN only when the files differ.
                    let collision = hardlink_collision(&path, &metadata, &dst_path);
                    counts.add(collision);
                    match collision {
                        LinkCollision::Same | LinkCollision::Unchecked => tracing::debug!(
                            "Not linking {} => {}, already exists ({})",
                            path.display(),
                            dst_path.display(),
                            collision.note()
                        ),
                        LinkCollision::Differs(why) => warn!(
                            "Not linking {} => {}, already exists ({why}; the first-linked file stays)",
                            path.display(),
                            dst_path.display()
                        ),
                    }
                    Ok(())
                }
                // The cache and destination can live on different filesystems
                // (e.g. a per-VM `/state` volume vs. the rootfs holding
                // `/home`), where hardlinks are impossible (`EXDEV`). Fall back
                // to a copy so materialization still succeeds — slower and no
                // longer deduplicated, but correct.
                Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
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
                        // Same rule as for files: a symlink to the same target
                        // is the common overlap, a different target is worth
                        // the WARN.
                        match fs::read_link(&dst_path) {
                            Ok(existing) if existing == target => {
                                counts.add(LinkCollision::Same);
                                tracing::debug!(
                                    "Not symlinking {} => {}, already exists (same target)",
                                    path.display(),
                                    dst_path.display()
                                );
                            }
                            _ => {
                                counts.add(LinkCollision::Differs("another target"));
                                warn!(
                                    "Not symlinking {} => {}, already exists (another target or not a symlink; the first stays)",
                                    path.display(),
                                    dst_path.display()
                                );
                            }
                        }
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
/// Symlinked directories are followed and nothing stops a loop: a link to an
/// ancestor (`a -> .`) is walked down to the kernel's link limit, matching
/// each file under it once per level. For a tree a build wrote, use
/// [`match_files_for_glob_no_follow`].
pub fn match_files_for_glob(dir: &Path, glob: &str) -> Result<Vec<PathBuf>, GlobError> {
    match_files_for_glob_with(dir, glob, true)
}

/// [`match_files_for_glob`] that does not descend into a symlinked directory:
/// a loop in an output (`a -> .`) or a link out of it is not walked, while a
/// symlinked file still matches. For the scans that read whatever a build
/// produced.
pub fn match_files_for_glob_no_follow(dir: &Path, glob: &str) -> Result<Vec<PathBuf>, GlobError> {
    match_files_for_glob_with(dir, glob, false)
}

fn match_files_for_glob_with(
    dir: &Path,
    glob: &str,
    follow_symlinked_dirs: bool,
) -> Result<Vec<PathBuf>, GlobError> {
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
        follow: bool,
        results: &mut Vec<PathBuf>,
    ) -> Result<(), GlobError> {
        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;

            let path = entry.path();
            let subset = path.strip_prefix(root_dir).unwrap();
            // a symlinked directory is a directory only to the walk that follows links
            let descend = if follow {
                path.is_dir()
            } else {
                entry.file_type()?.is_dir()
            };
            if path.is_file() && matcher.is_match(subset) {
                results.push(path);
            } else if descend {
                // Recursively walk subdirectories
                walk_dir(&path, root_dir, matcher, follow, results)?;
            }
        }

        Ok(())
    }

    walk_dir(dir, dir, &matcher, follow_symlinked_dirs, &mut results)?;
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

    /// A symlink loop in a tree sends the following walk down `a/a/a/...` until
    /// the kernel's link limit, matching the same file at every level; the
    /// no-follow walk returns each file once, ignores the loop, and still
    /// matches a symlinked file.
    #[test]
    fn the_no_follow_walk_ignores_a_symlink_loop() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("bin")).unwrap();
        std::fs::write(t.path().join("bin/x"), b"x").unwrap();
        std::os::unix::fs::symlink(".", t.path().join("a")).unwrap();
        std::os::unix::fs::symlink("bin/x", t.path().join("y")).unwrap();
        let mut got = match_files_for_glob_no_follow(t.path(), "**/*").unwrap();
        got.sort();
        assert_eq!(got, vec![t.path().join("bin/x"), t.path().join("y")]);
        let following = match_files_for_glob(t.path(), "**/*").unwrap();
        assert!(
            following.len() > got.len(),
            "the following walk matched {} paths: the loop walked",
            following.len()
        );
    }

    /// A path two layers both ship is linked once and counted, with a WARN
    /// only when the two differ: another size, other bytes of the same size
    /// (a version-string bump), or a destination that is not a regular file
    /// (a symlink is not followed). The same inode or the same bytes is the
    /// quiet case; equal-size files too large to compare are quiet too, but
    /// counted apart as unchecked.
    #[test]
    fn a_second_layer_shipping_the_same_path_is_counted_not_warned_unless_it_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b, dst) = (
            tmp.path().join("a"),
            tmp.path().join("b"),
            tmp.path().join("rootfs"),
        );
        for d in [&a, &b, &dst] {
            std::fs::create_dir_all(d.join("usr/lib")).unwrap();
        }
        std::fs::write(a.join("usr/lib/same.txt"), b"same bytes").unwrap();
        std::fs::write(b.join("usr/lib/same.txt"), b"same bytes").unwrap();
        std::fs::write(a.join("usr/lib/bumped.txt"), b"v1.0.1").unwrap();
        std::fs::write(b.join("usr/lib/bumped.txt"), b"v1.0.2").unwrap(); // equal size, other bytes
        std::fs::write(a.join("usr/lib/differs.txt"), b"short").unwrap();
        std::fs::write(b.join("usr/lib/differs.txt"), b"rather longer").unwrap();
        std::os::unix::fs::symlink("target", a.join("usr/lib/link")).unwrap();
        std::os::unix::fs::symlink("other", b.join("usr/lib/link")).unwrap();
        // A symlink in place whose target holds the same bytes: compared
        // through the target it would pass as the same file.
        std::os::unix::fs::symlink("same.txt", a.join("usr/lib/alias")).unwrap();
        std::fs::write(b.join("usr/lib/alias"), b"same bytes").unwrap();
        let big = usize::try_from(COLLISION_COMPARE_MAX + 1).unwrap();
        std::fs::write(a.join("usr/lib/big.bin"), vec![0u8; big]).unwrap();
        std::fs::write(b.join("usr/lib/big.bin"), vec![1u8; big]).unwrap();

        let mut counts = LinkCollisions::default();
        hardlink_dir_contents_counted(&a, &dst, &mut counts).unwrap();
        assert_eq!(
            counts,
            LinkCollisions::default(),
            "the first layer collides with nothing"
        );
        hardlink_dir_contents_counted(&b, &dst, &mut counts).unwrap();
        assert_eq!(
            counts,
            LinkCollisions {
                same: 1,
                unchecked: 1,
                differ: 4
            },
            "same bytes; an unchecked large file; other bytes, another size, \
             a differing symlink and a symlink destination"
        );
        assert_eq!(counts.total(), 6);
        // the first-linked file stays
        assert_eq!(
            std::fs::read(dst.join("usr/lib/differs.txt")).unwrap(),
            b"short"
        );
        assert_eq!(
            std::fs::read(dst.join("usr/lib/bumped.txt")).unwrap(),
            b"v1.0.1"
        );
        assert_eq!(
            std::fs::read_link(dst.join("usr/lib/link"))
                .unwrap()
                .to_str(),
            Some("target")
        );
        assert_eq!(
            link_collision(
                &b.join("usr/lib/bumped.txt"),
                &dst.join("usr/lib/bumped.txt")
            ),
            LinkCollision::Differs("different content")
        );
        assert_eq!(
            link_collision(&b.join("usr/lib/alias"), &dst.join("usr/lib/alias")),
            LinkCollision::Differs("not a regular file")
        );
        assert_eq!(
            link_collision(&b.join("usr/lib/same.txt"), &dst.join("usr/lib/same.txt")),
            LinkCollision::Same
        );
        // an equal-size file too large to compare is unchecked, never the same
        let big_collision =
            link_collision(&b.join("usr/lib/big.bin"), &dst.join("usr/lib/big.bin"));
        assert_eq!(big_collision, LinkCollision::Unchecked);
        assert_eq!(big_collision.note(), "same size, too large to compare");
        // the same inode is the same file
        let src = a.join("usr/lib/same.txt");
        let m = std::fs::metadata(&src).unwrap();
        assert_eq!(
            hardlink_collision(&src, &m, &dst.join("usr/lib/same.txt")),
            LinkCollision::Same
        );
    }

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
