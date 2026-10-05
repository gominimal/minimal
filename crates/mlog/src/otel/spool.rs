//! The local telemetry spool (spec 25 TEL-014): with telemetry
//! on, every finished span and every exported log record is also appended,
//! synchronously and as it happens, to a per-process OTLP-JSON file under
//! `<state>/telemetry/spool/`. One line is one `ExportTraceServiceRequest`
//! or `ExportLogsServiceRequest` in the OTLP/JSON encoding (the collector's
//! file exporter writes the same shape), so a shipper can POST each line as
//! is to `/v1/traces` or `/v1/logs`.
//!
//! Written on span end, not on a batch timer: a SIGKILL or a hang loses at
//! most the spans still open, never a 5 s batch. The spool never blocks on
//! the network and never fails a command.
//!
//! Files: a process writes `<service>-<pid>-<start_ms>.jsonl`, and when that
//! reaches [`SEGMENT_BYTES`] it rotates to `<service>-<pid>-<start_ms>-<n>.jsonl`
//! (n = 1, 2, ...), so a long-lived `minimald` keeps spooling for its whole
//! life. [`SpoolName`] is the one grammar of those names: the writer formats
//! them and the pruner (and a shipper, through [`is_spool_file`]) parses them. Every file is opened on the first record that needs it (a process
//! that records nothing creates nothing) with mode 0600 in a 0700 directory.
//! The directory is checked before its first file: opened without following
//! a symlink, it must be this user's and carry no group or other bits. One
//! that is not (a shared `MINIMAL_OTEL_SPOOL_DIR`, a link someone planted)
//! is refused with one warning naming it, and the spool moves to the
//! state-dir default instead; a refused default leaves nowhere to spool.
//!
//! Bound: before a process opens a new file, the directory is pruned: spool
//! files (named as above, see [`is_spool_file`]) older than [`MAX_AGE`] are
//! deleted, then the oldest (by mtime) until at most [`MAX_BYTES`] minus one
//! segment is left. Nothing else in the directory is touched but the
//! `.pruned` stamp: `MINIMAL_OTEL_SPOOL_DIR` can name a directory that holds
//! other files, other `*.jsonl` included. A rotation always prunes;
//! a process's first file prunes only when nobody has in the last
//! [`PRUNE_EVERY`] (the `.pruned` stamp's mtime), so a short CLI run costs one
//! `stat`, not a scan of the directory. With one writer the directory stays
//! under [`MAX_BYTES`]; it can go over by one segment per process writing at
//! the same time, plus what short-lived processes write between two scans (at
//! most [`PRUNE_EVERY`] of it). A writer notices within [`RECHECK_EVERY`] when
//! another process pruned its open file away and moves to a new one.
//!
//! Errors: the spool is best effort. A failed open (a full or read-only
//! filesystem, a directory that cannot be made) drops the record and is
//! retried: the next record tries again, and after that at most once per
//! [`RETRY_EVERY`] until a file opens, so a cause that goes away (space
//! freed, a volume remounted) costs at most that long of records, and one
//! that stays costs one `open` per [`RETRY_EVERY`]. The first failure is
//! logged once, at warn. A failed write drops that record and the next record
//! tries again. A short write (the disk filled mid-line) is finished if the file
//! takes the rest, else the next record starts with a newline, so the torn
//! line stays one bad line of its own and never swallows the next record.
//!
//! Not here yet: a daemon-side shipper (a spec 25 non-goal; the harness ships
//! a VM's spool after the run with `otel/spool-ship.py`).

use std::fmt::{self, Write as _};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use opentelemetry::logs::AnyValue;
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry::{Array, InstrumentationScope, Key, Value};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogProcessor, SdkLogRecord};
use opentelemetry_sdk::trace::{SpanData, SpanProcessor};

/// Spool files older than this are deleted when the directory is pruned.
pub(crate) const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// The spool directory's size bound (see the module docs for how tight).
pub(crate) const MAX_BYTES: u64 = 50 * 1024 * 1024;
/// One spool file is at most this; the process then rotates to a new file.
pub(crate) const SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
/// A process's first file scans the directory only if no scan is this recent.
pub(crate) const PRUNE_EVERY: Duration = Duration::from_secs(60);
/// How often a writer checks that its open file still has a name.
pub(crate) const RECHECK_EVERY: Duration = Duration::from_secs(5);
/// After a failed open, and a failed retry on the next record, a writer
/// tries to open a file at most this often.
pub(crate) const RETRY_EVERY: Duration = Duration::from_secs(5);
/// Touched after each scan; its mtime gates [`PRUNE_EVERY`].
const STAMP: &str = ".pruned";

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) max_bytes: u64,
    pub(crate) segment_bytes: u64,
    pub(crate) max_age: Duration,
    pub(crate) prune_every: Duration,
    pub(crate) recheck_every: Duration,
    pub(crate) retry_every: Duration,
}

impl Limits {
    pub(crate) const DEFAULT: Self = Self {
        max_bytes: MAX_BYTES,
        segment_bytes: SEGMENT_BYTES,
        max_age: MAX_AGE,
        prune_every: PRUNE_EVERY,
        recheck_every: RECHECK_EVERY,
        retry_every: RETRY_EVERY,
    };
}

/// The spool directory `MINIMAL_OTEL_SPOOL_DIR` names, when set and not
/// empty: an explicit location (tests, isolated daemons) that wins over the
/// state directory, both here and in [`super::relocate_spool`].
pub(crate) fn dir_override() -> Option<PathBuf> {
    std::env::var_os("MINIMAL_OTEL_SPOOL_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

/// The spool directory. Whether the spool is on is the switches' call
/// ([`super::switches`]). `MINIMAL_OTEL_SPOOL_DIR` overrides the location
/// ([`dir_override`]).
pub(crate) fn dir() -> Option<PathBuf> {
    dir_override().or_else(state_dir_spool)
}

/// The default spool directory, `<state>/telemetry/spool`, whatever
/// `MINIMAL_OTEL_SPOOL_DIR` says: where a refused directory falls back to
/// ([`SpoolFile::open`]).
pub(crate) fn state_dir_spool() -> Option<PathBuf> {
    // minimal_state_dir panics when no home can be resolved: no spool then.
    std::panic::catch_unwind(paths::minimal_state_dir)
        .ok()
        .map(|d| {
            d.as_utf8_path()
                .as_std_path()
                .join("telemetry")
                .join("spool")
        })
}

/// Why a spool directory is not written to.
#[derive(Debug)]
enum DirRefusal {
    /// The path is a symbolic link, or not a directory at all (opened
    /// `O_NOFOLLOW | O_DIRECTORY`: Linux answers ENOTDIR for a link, macOS
    /// ELOOP): whoever controls a link decides where spool files land.
    NotAPlainDirectory,
    /// Owned by another user: a shared or foreign directory.
    ForeignOwner { uid: u32, ours: u32 },
    /// Group or other permission bits are set: a shared directory, whose
    /// other users would read every finished span.
    Shared { mode: u32 },
}

impl fmt::Display for DirRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAPlainDirectory => {
                f.write_str("the path is a symbolic link or not a directory")
            }
            Self::ForeignOwner { uid, ours } => {
                write!(f, "owned by uid {uid}, not this process's uid {ours}")
            }
            Self::Shared { mode } => write!(
                f,
                "mode {mode:04o} grants group or other access (0700 is required)"
            ),
        }
    }
}

/// What kept a record out of the spool: an open that failed (the caller
/// retries), or a directory the spool refuses to use (the caller moves on
/// to `fallback`, if there is one, and never comes back).
enum Failure {
    Open(PathBuf, std::io::Error),
    Refused {
        path: PathBuf,
        why: DirRefusal,
        fallback: Option<PathBuf>,
    },
}

/// Create `dir` (and its parents) with mode 0700 if it does not exist, then
/// open it and check it is one this process may spool into: opened without
/// following a final symlink, owned by the process's effective uid, and with
/// no group or other permission bits. A directory that exists with wider bits
/// is refused rather than tightened: it may be shared on purpose, and a spool
/// of finished spans (command lines, hostnames) must not land in it.
/// Returns the opened directory and whether it was created here.
///
/// The check is made on the descriptor that is then kept ([`SpoolDir`]), and
/// every later open, listing, unlink and stamp goes through that descriptor,
/// never through the path again. So a user who can write a parent directory
/// and swaps the checked directory for a symlink or another directory after
/// the check redirects nothing.
fn ensure_private_dir(dir: &Path) -> Result<(SpoolDir, bool), Failure> {
    let existed = dir.symlink_metadata().is_ok();
    let mut db = std::fs::DirBuilder::new();
    db.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        db.mode(0o700);
    }
    db.create(dir)
        .map_err(|e| Failure::Open(dir.to_path_buf(), e))?;
    let opened = SpoolDir::open_checked(dir)?;
    Ok((opened, !existed))
}

/// A spool directory, opened once and checked private
/// ([`ensure_private_dir`]). On unix every operation is relative to the kept
/// descriptor (`openat`, `fstatat`, `unlinkat`, and a listing of the same
/// directory), so what was checked is what is written. Every file the spool
/// creates or writes is opened with mode 0600 and `O_NOFOLLOW`: a symbolic
/// link at a spool file's name or at the [`STAMP`] is never followed. Names
/// passed in are single path components the spool chose (a [`SpoolName`] or
/// [`STAMP`]), never a path.
#[derive(Debug)]
pub(crate) struct SpoolDir {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(not(unix))]
    path: PathBuf,
}

/// One spool file in a [`SpoolDir`] listing: its name, mtime (nanoseconds
/// since the epoch) and size.
struct Entry {
    name: String,
    mtime: u64,
    len: u64,
}

/// `name` as a C string, refused unless it is one path component.
#[cfg(unix)]
fn c_name(name: &str) -> std::io::Result<std::ffi::CString> {
    if name.contains('/') {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    std::ffi::CString::new(name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

#[cfg(unix)]
impl SpoolDir {
    fn open_checked(dir: &Path) -> Result<Self, Failure> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let refused = |why| Failure::Refused {
            path: dir.to_path_buf(),
            why,
            fallback: None,
        };
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(dir);
        let file = match opened {
            Ok(f) => f,
            // `O_NOFOLLOW | O_DIRECTORY` on a symlink: ENOTDIR on Linux, ELOOP
            // on macOS; the link is never followed and the refusal names it.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
                return Err(refused(DirRefusal::NotAPlainDirectory));
            }
            Err(e) => return Err(Failure::Open(dir.to_path_buf(), e)),
        };
        let m = file
            .metadata()
            .map_err(|e| Failure::Open(dir.to_path_buf(), e))?;
        // SAFETY: geteuid(2) takes no arguments, touches no memory and cannot
        // fail.
        let ours = unsafe { libc::geteuid() };
        if m.uid() != ours {
            return Err(refused(DirRefusal::ForeignOwner { uid: m.uid(), ours }));
        }
        let mode = m.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(refused(DirRefusal::Shared { mode }));
        }
        Ok(Self { fd: file.into() })
    }

    /// `openat(2)` relative to the directory, creating with mode 0600, never
    /// following a symbolic link at `name`.
    fn open_at(&self, name: &str, flags: libc::c_int) -> std::io::Result<File> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let c = c_name(name)?;
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mode: libc::c_uint = 0o600;
        // SAFETY: `self.fd` is an open directory descriptor for the life of
        // `self`, `c` is a NUL-terminated string that outlives the call, and
        // the variadic mode is passed as the `c_uint` openat(2) reads.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat(2) and nothing else owns it.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Open `name` for appending, creating it.
    fn open_append(&self, name: &str) -> std::io::Result<File> {
        self.open_at(name, libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND)
    }

    /// Create `name` empty, or truncate it (which updates its mtime).
    fn touch(&self, name: &str) -> std::io::Result<File> {
        self.open_at(name, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)
    }

    /// `fstatat(2)` without following a link: whether `name` is a regular
    /// file, its mtime in nanoseconds since the epoch, and its size.
    fn stat(&self, name: &str) -> std::io::Result<(bool, u64, u64)> {
        use std::os::fd::AsRawFd as _;
        let c = c_name(name)?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: as in `open_at`; `st` is a writable `stat` that fstatat(2)
        // fills when it returns 0.
        let rc = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstatat(2) returned 0, so `st` is initialised.
        let st = unsafe { st.assume_init() };
        let regular = st.st_mode & libc::S_IFMT == libc::S_IFREG;
        #[cfg_attr(
            target_pointer_width = "64",
            expect(
                clippy::useless_conversion,
                reason = "time_t and c_long are i64 on 64-bit targets but i32 on 32-bit ones"
            )
        )]
        let (secs, nsec) = (
            u64::try_from(i64::from(st.st_mtime)).unwrap_or(0),
            u64::try_from(i64::from(st.st_mtime_nsec)).unwrap_or(0),
        );
        let mtime = secs.saturating_mul(1_000_000_000).saturating_add(nsec);
        let len = u64::try_from(st.st_size).unwrap_or(0);
        Ok((regular, mtime, len))
    }

    /// `unlinkat(2)` of the file `name`.
    fn unlink(&self, name: &str) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        let c = c_name(name)?;
        // SAFETY: as in `open_at`.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// The names in the directory other than `.` and `..`, read from a new
    /// descriptor for the same directory (`openat(fd, ".")`), so the kept
    /// descriptor's offset is never moved by a listing. Names that are not
    /// UTF-8 are left out: no spool file has one.
    fn names(&self) -> std::io::Result<Vec<String>> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
        let here = c_name(".")?;
        // SAFETY: as in `open_at`.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                here.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new directory descriptor; fdopendir(3) owns it
        // when it succeeds.
        let dirp = unsafe { libc::fdopendir(fd) };
        if dirp.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: fdopendir(3) failed, so `fd` is still ours to close.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
            return Err(e);
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: `dirp` is a valid stream until the closedir below; the
            // entry readdir(3) returns stays valid until the next readdir,
            // and its name is copied out before then.
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                break;
            }
            // SAFETY: `ent` is non-null and points to an entry valid until
            // the next readdir(3) call, which comes after the copy below.
            let d_name = unsafe { &(*ent).d_name };
            // SAFETY: `d_name` is NUL-terminated within the entry.
            let name = unsafe { std::ffi::CStr::from_ptr(d_name.as_ptr()) };
            if let Ok(n) = name.to_str()
                && n != "."
                && n != ".."
            {
                names.push(n.to_owned());
            }
        }
        // SAFETY: `dirp` came from fdopendir(3) and is closed once here;
        // closedir(3) also closes the descriptor the stream owns.
        unsafe { libc::closedir(dirp) };
        Ok(names)
    }
}

#[cfg(not(unix))]
impl SpoolDir {
    fn open_checked(dir: &Path) -> Result<Self, Failure> {
        Ok(Self {
            path: dir.to_path_buf(),
        })
    }

    fn open_append(&self, name: &str) -> std::io::Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.join(name))
    }

    fn touch(&self, name: &str) -> std::io::Result<File> {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.path.join(name))
    }

    fn stat(&self, name: &str) -> std::io::Result<(bool, u64, u64)> {
        let m = std::fs::symlink_metadata(self.path.join(name))?;
        let mtime = since_epoch(m.modified().unwrap_or(UNIX_EPOCH));
        Ok((m.is_file(), mtime, m.len()))
    }

    fn unlink(&self, name: &str) -> std::io::Result<()> {
        std::fs::remove_file(self.path.join(name))
    }

    fn names(&self) -> std::io::Result<Vec<String>> {
        Ok(std::fs::read_dir(&self.path)?
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect())
    }
}

impl SpoolDir {
    /// The spool files ([`is_spool_file`]) that are regular files, listed
    /// and stat'ed through the directory.
    fn spool_files(&self) -> Vec<Entry> {
        let Ok(names) = self.names() else {
            return Vec::new();
        };
        names
            .into_iter()
            .filter(|n| is_spool_file(n))
            .filter_map(|name| {
                let (regular, mtime, len) = self.stat(&name).ok()?;
                regular.then_some(Entry { name, mtime, len })
            })
            .collect()
    }
}

/// Mark in `delete` which of `files` a clean-up deletes: every file older
/// than `max_age`, then the oldest of the rest until what is left totals at
/// most `prune_to` bytes. A file is `(mtime, bytes)`; times are nanoseconds
/// since the epoch, and a file dated after `now` is never old. `delete` is as
/// long as `files`.
pub(crate) fn plan_prune(
    files: &[(u64, u64)],
    delete: &mut [bool],
    now: u64,
    max_age: u64,
    prune_to: u64,
) {
    let mut left: u128 = 0;
    for (d, &(mtime, len)) in delete.iter_mut().zip(files) {
        *d = now.checked_sub(mtime).is_some_and(|age| age > max_age);
        if !*d {
            left = left.saturating_add(u128::from(len));
        }
    }
    while left > u128::from(prune_to) {
        let mut oldest: Option<(usize, (u64, u64))> = None;
        for (i, (d, &f)) in delete.iter().zip(files).enumerate() {
            if !*d && oldest.is_none_or(|(_, o)| f < o) {
                oldest = Some((i, f));
            }
        }
        let Some((i, (_, len))) = oldest else {
            break;
        };
        if let Some(d) = delete.get_mut(i) {
            *d = true;
        }
        left = left.saturating_sub(u128::from(len));
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn since_epoch(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, nanos)
}

/// A spool file's name: `<service>-<pid>-<start_ms>[-<n>].jsonl`, where
/// the service is one or more ASCII letters, digits, `-` and `_`, the pid is
/// a decimal `u32` with no leading zero, `start_ms` is milliseconds since the
/// epoch in exactly 13 digits (any time from 2001 to 2286; the 13 digits
/// keep a name like `report-2024-10.jsonl` out) and `n`, the rotation, is a
/// decimal with no leading zero. The one grammar for the writer and every
/// reader: `Display` formats a name and [`parse`](Self::parse) recognises
/// one, and they round-trip both ways (`parse(x.to_string()) == Some(x)` for
/// every `x` from [`new`](Self::new) and [`rotation`](Self::rotation);
/// `parse(s).map(|x| x.to_string()) == Some(s)` for every accepted `s`). A
/// name reads one way only: a pid has at most 10 digits and a start exactly
/// 13, so the last field is a start or a rotation, never either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpoolName {
    service: String,
    pid: u32,
    start_ms: u64,
    n: Option<u64>,
}

impl SpoolName {
    /// The 13-digit range of `start_ms`.
    const START_MS: std::ops::RangeInclusive<u64> = 1_000_000_000_000..=9_999_999_999_999;

    /// This process's first file's name: `service` with every character
    /// outside the grammar made `_` (and `_` for an empty one), `pid` (0,
    /// which no process has, becomes 1) and `start` clamped into the 13-digit
    /// range, so a clock before 2001 (a guest's pid 1 before timekeep) or
    /// after 2286 gives the nearest name the grammar has, never one the
    /// pruner would skip.
    pub(crate) fn new(service: &str, pid: u32, start: SystemTime) -> Self {
        let mut service: String = service
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if service.is_empty() {
            service.push('_');
        }
        let start_ms = start
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .clamp(*Self::START_MS.start(), *Self::START_MS.end());
        Self {
            service,
            pid: pid.max(1),
            start_ms,
            n: None,
        }
    }

    /// The name of this process's `n`th rotation (0 is the first file).
    pub(crate) fn rotation(&self, n: u32) -> Self {
        Self {
            n: (n > 0).then_some(u64::from(n)),
            ..self.clone()
        }
    }

    /// The name `name` spells, `None` when it is not a spool file's.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        fn number<T: std::str::FromStr>(s: &str) -> Option<T> {
            (!s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        }
        /// `<service>-<pid>-<start_ms>`
        fn stem(s: &str) -> Option<(String, u32, u64)> {
            let mut parts = s.rsplitn(3, '-');
            let (start, pid, service) = (parts.next()?, parts.next()?, parts.next()?);
            let start_ms = (start.len() == 13).then(|| number(start)).flatten()?;
            let pid = number(pid)?;
            (!service.is_empty()
                && service
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
            .then(|| (service.to_owned(), pid, start_ms))
        }
        let s = name.strip_suffix(".jsonl")?;
        if let Some((service, pid, start_ms)) = stem(s) {
            return Some(Self {
                service,
                pid,
                start_ms,
                n: None,
            });
        }
        let (s, n) = s.rsplit_once('-')?;
        let n = number(n)?;
        let (service, pid, start_ms) = stem(s)?;
        Some(Self {
            service,
            pid,
            start_ms,
            n: Some(n),
        })
    }
}

impl fmt::Display for SpoolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}-{}", self.service, self.pid, self.start_ms)?;
        if let Some(n) = self.n {
            write!(f, "-{n}")?;
        }
        f.write_str(".jsonl")
    }
}

/// Whether `name` is a spool file's name ([`SpoolName`]), this process's or
/// any other spool writer's. The one predicate the pruner and a shipper
/// share (exported as `mlog::otel::is_spool_file`), so what the writer
/// names, the pruner bounds and a shipper ships are the same files.
pub fn is_spool_file(name: &str) -> bool {
    SpoolName::parse(name).is_some()
}

/// Delete the spool files ([`is_spool_file`]) older than `max_age`, then
/// the oldest until their total is at most `prune_to` (see [`plan_prune`]),
/// and touch the [`STAMP`]; nothing else in `dir` is touched, and every step
/// goes through the directory's descriptor ([`SpoolDir`]). Returns the spool
/// bytes left. Errors are ignored: a file that cannot be deleted stays and
/// counts, and a directory that cannot be listed is left alone.
pub(crate) fn prune(dir: &SpoolDir, now: SystemTime, max_age: Duration, prune_to: u64) -> u64 {
    let files = dir.spool_files();
    let sizes: Vec<(u64, u64)> = files.iter().map(|f| (f.mtime, f.len)).collect();
    let mut delete = vec![false; sizes.len()];
    plan_prune(
        &sizes,
        &mut delete,
        since_epoch(now),
        nanos(max_age),
        prune_to,
    );
    let mut left: u64 = 0;
    for (f, d) in files.iter().zip(delete) {
        if !d || dir.unlink(&f.name).is_err() {
            left = left.saturating_add(f.len);
        }
    }
    #[expect(
        clippy::let_underscore_must_use,
        reason = "best effort: the spool never fails a caller (spec 25 principle 8)"
    )]
    let _ = dir.touch(STAMP);
    left
}

/// Whether the last scan (the [`STAMP`]'s mtime) is older than `every`, or
/// unknown, or in the future by more than `every` (a clock step).
fn prune_due(dir: &SpoolDir, now: SystemTime, every: Duration) -> bool {
    let Ok((_, mtime, _)) = dir.stat(STAMP) else {
        return true;
    };
    let t = UNIX_EPOCH + Duration::from_nanos(mtime);
    match now.duration_since(t) {
        Ok(age) => age > every,
        Err(e) => e.duration() > every,
    }
}

/// One process's spool, shared by the span and log processors.
#[derive(Debug)]
pub(crate) struct SpoolFile {
    /// This process's first file's name; rotations derive from it.
    name: SpoolName,
    limits: Limits,
    state: Mutex<State>,
    /// A failed open has been logged (once per process).
    warned: AtomicBool,
}

#[derive(Debug, Default)]
struct State {
    /// The directory files go in; `None` for a deferred spool (see
    /// [`SpoolFile::deferred`]) until [`SpoolFile::relocate`] names one.
    dir: Option<PathBuf>,
    /// `dir`, created (0700), opened and checked private
    /// ([`ensure_private_dir`]); every file operation goes through it. Opened
    /// and checked again when `dir` changes or has gone away.
    opened_dir: Option<SpoolDir>,
    /// Where to spool instead if `dir` is refused: the state-dir default
    /// when `dir` is somewhere else ([`SpoolFile::open`]). Used once.
    fallback: Option<PathBuf>,
    file: Option<File>,
    path: Option<PathBuf>,
    /// Files opened so far (the next file's number).
    opened: u32,
    /// Bytes in the open file.
    written: u64,
    /// The open file ends in a partial line.
    torn: bool,
    /// When the open file's link count was last checked.
    checked: Option<Instant>,
    /// Opens that failed in a row since the last one that worked.
    failures: u32,
    /// After a failed retry: no open is tried before this.
    retry_at: Option<Instant>,
}

impl SpoolFile {
    /// Name this process's files in `dir`. No I/O: the directory is pruned
    /// and a file created on the first record. If `dir` turns out to be one
    /// the spool refuses (a symlink, another user's, or group/other
    /// readable; see [`ensure_private_dir`]) and it is not the state-dir
    /// default, the spool moves to that default instead, once, and says so
    /// in one warning that names the refused path.
    pub(crate) fn open(dir: PathBuf, service: &str) -> Arc<Self> {
        let fallback = state_dir_spool().filter(|d| *d != dir);
        Self::with_fallback(dir, service, fallback, Limits::DEFAULT)
    }

    /// [`open`](Self::open) with explicit limits and no fallback (tests).
    #[cfg(test)]
    pub(crate) fn with_limits(dir: PathBuf, service: &str, limits: Limits) -> Arc<Self> {
        Self::with_fallback(dir, service, None, limits)
    }

    fn with_fallback(
        dir: PathBuf,
        service: &str,
        fallback: Option<PathBuf>,
        limits: Limits,
    ) -> Arc<Self> {
        let f = Self::deferred_with_limits(service, limits);
        if let Ok(mut st) = f.state.lock() {
            st.dir = Some(dir);
            st.fallback = fallback;
        }
        f
    }

    /// A spool with no directory yet: records are dropped until
    /// [`relocate`](Self::relocate) names one. For a process whose state
    /// directory is not known when telemetry initialises (the microVM's
    /// `/init`, which has no home and mounts its state volume later).
    pub(crate) fn deferred(service: &str) -> Arc<Self> {
        Self::deferred_with_limits(service, Limits::DEFAULT)
    }

    fn deferred_with_limits(service: &str, limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            name: SpoolName::new(service, std::process::id(), SystemTime::now()),
            limits,
            state: Mutex::new(State::default()),
            warned: AtomicBool::new(false),
        })
    }

    /// Move the spool to `dir`: the next record opens this process's first
    /// file there (pruning as a first file does), whatever was open before
    /// stays as it is, and a spool waiting to retry a failed open tries again
    /// at once. A no-op when `dir` is already the spool's directory.
    pub(crate) fn relocate(&self, dir: PathBuf) {
        let Ok(mut st) = self.state.lock() else {
            return;
        };
        if st.dir.as_ref() == Some(&dir) {
            return;
        }
        *st = State {
            dir: Some(dir),
            ..State::default()
        };
    }

    /// Close the open file and forget the directory: from here on records are
    /// dropped, as a deferred spool drops them, until
    /// [`relocate`](Self::relocate) names a directory again. What was written
    /// stays on disk. A no-op on a spool with no directory.
    pub(crate) fn release(&self) {
        let Ok(mut st) = self.state.lock() else {
            return;
        };
        *st = State {
            path: st.path.take(),
            ..State::default()
        };
    }

    /// The spool's directory, once it has one.
    pub(crate) fn dir(&self) -> Option<PathBuf> {
        self.state.lock().ok().and_then(|st| st.dir.clone())
    }

    /// The file written last (or being written), if any.
    #[cfg(test)]
    pub(crate) fn path(&self) -> Option<PathBuf> {
        self.state.lock().unwrap().path.clone()
    }

    /// Append `line` plus a newline. Never fails, never panics.
    pub(crate) fn append(&self, line: &str) {
        let failed = self.append_locked(line);
        // Logged with the lock released: the event may come back here
        // through the log bridge.
        match failed {
            Some(Failure::Open(path, error)) => {
                if !self.warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "telemetry spool: cannot open a file, records are dropped until one \
                         opens (retried at most every {} s)",
                        self.limits.retry_every.as_secs()
                    );
                }
            }
            Some(Failure::Refused {
                path,
                why,
                fallback,
            }) => {
                // Once per refused directory (the spool never returns to it).
                match fallback {
                    Some(fallback) => tracing::warn!(
                        refused = %path.display(),
                        reason = %why,
                        spool = %fallback.display(),
                        "telemetry spool: directory refused, spooling to the default instead"
                    ),
                    None => tracing::warn!(
                        refused = %path.display(),
                        reason = %why,
                        "telemetry spool: directory refused and no other to use, \
                         records are dropped"
                    ),
                }
            }
            None => {}
        }
    }

    /// [`append`](Self::append) under the lock. Returns what kept this
    /// record out, for the caller to log.
    fn append_locked(&self, line: &str) -> Option<Failure> {
        let n = line.len() as u64 + 1;
        if n + 1 > self.limits.segment_bytes {
            return None; // a record bigger than a whole file is dropped
        }
        let Ok(mut st) = self.state.lock() else {
            return None;
        };
        // A deferred spool has nowhere to write yet.
        st.dir.as_ref()?;
        if st.file.is_some() {
            let full = st.written + n + u64::from(st.torn) > self.limits.segment_bytes;
            if full || self.unlinked(&mut st) {
                st.file = None;
            }
        }
        if st.file.is_none() {
            if st.retry_at.is_some_and(|t| Instant::now() < t) {
                return None; // backing off after a failed open
            }
            if let Err(e) = self.next_file(&mut st) {
                return Some(e);
            }
        }
        let mut buf = Vec::with_capacity(line.len() + 2);
        if st.torn {
            buf.push(b'\n');
        }
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let f = st.file.as_mut()?;
        let done = write_line(f, &buf);
        st.written += done as u64;
        if done > 0 {
            st.torn = done < buf.len();
        }
        None
    }

    /// Prune (always on a rotation; on the first file only when due) and
    /// open the next file. When it cannot be opened, returns the path and
    /// the error and schedules the retry: the next record tries again after
    /// a first failure, a record [`Limits::retry_every`] later after any
    /// further one.
    ///
    /// The directory is created (0700) and checked private the first time
    /// a file is opened in it ([`ensure_private_dir`]). A refused directory
    /// is left for good: the spool moves to its fallback, if it has one
    /// (checked in turn on the next record), else it has nowhere to write.
    fn next_file(&self, st: &mut State) -> Result<(), Failure> {
        let Some(dir) = st.dir.clone() else {
            return Ok(());
        };
        // A directory made here is empty: nothing to prune, no stamp to
        // write for its first file.
        let mut fresh = false;
        if st.opened_dir.is_none() {
            match ensure_private_dir(&dir) {
                Ok((opened, created)) => {
                    st.opened_dir = Some(opened);
                    fresh = created;
                }
                Err(Failure::Refused { path, why, .. }) => {
                    let fallback = st.fallback.take();
                    *st = State {
                        dir: fallback.clone(),
                        ..State::default()
                    };
                    return Err(Failure::Refused {
                        path,
                        why,
                        fallback,
                    });
                }
                Err(Failure::Open(path, e)) => {
                    self.note_failed_open(st);
                    return Err(Failure::Open(path, e));
                }
            }
        }
        let Some(handle) = st.opened_dir.as_ref() else {
            return Ok(());
        };
        let now = SystemTime::now();
        if !fresh && (st.opened > 0 || prune_due(handle, now, self.limits.prune_every)) {
            let room = self
                .limits
                .max_bytes
                .saturating_sub(self.limits.segment_bytes);
            prune(handle, now, self.limits.max_age, room);
        }
        let name = self.name.rotation(st.opened).to_string();
        let path = dir.join(&name);
        match handle.open_append(&name) {
            Ok(f) => {
                st.file = Some(f);
                st.path = Some(path);
                st.opened += 1;
                st.written = 0;
                st.torn = false;
                st.checked = Some(Instant::now());
                st.failures = 0;
                st.retry_at = None;
                Ok(())
            }
            Err(e) => {
                // The directory went away under us (a clean-up, a tmpfs
                // remount): the next try creates and checks it again.
                if e.kind() == std::io::ErrorKind::NotFound {
                    st.opened_dir = None;
                }
                self.note_failed_open(st);
                Err(Failure::Open(path, e))
            }
        }
    }

    /// Schedule the retry after a failed open (or a failed directory
    /// create): the next record tries again after a first failure, a record
    /// [`Limits::retry_every`] later after any further one.
    fn note_failed_open(&self, st: &mut State) {
        st.failures = st.failures.saturating_add(1);
        st.retry_at = (st.failures > 1)
            .then(|| Instant::now().checked_add(self.limits.retry_every))
            .flatten();
    }

    /// Whether the open file was deleted under us (another process pruned
    /// it), checked at most every `recheck_every`.
    fn unlinked(&self, st: &mut State) -> bool {
        if st
            .checked
            .is_some_and(|t| t.elapsed() < self.limits.recheck_every)
        {
            return false;
        }
        st.checked = Some(Instant::now());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            st.file
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .is_some_and(|m| m.nlink() == 0)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// Write `buf` (one record, newline-terminated) with one `write`, which an
/// append-mode file places whole at its end. A short write is continued
/// (a few tries); returns the bytes written, so `0 < n < buf.len()` means the
/// file now ends in a torn line.
fn write_line(w: &mut impl std::io::Write, buf: &[u8]) -> usize {
    let mut done = 0;
    for _ in 0..4 {
        match w.write(buf.get(done..).unwrap_or_default()) {
            Ok(0) => break,
            Ok(k) => {
                done += k;
                if done == buf.len() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    done
}

/// Writes each finished span to the spool as it ends.
#[derive(Debug)]
pub(crate) struct SpoolSpans {
    file: Arc<SpoolFile>,
    resource: String,
}

impl SpoolSpans {
    pub(crate) fn new(file: Arc<SpoolFile>) -> Self {
        Self {
            file,
            resource: resource_json(&Resource::builder_empty().build()),
        }
    }
}

impl SpanProcessor for SpoolSpans {
    fn on_start(&self, _span: &mut opentelemetry_sdk::trace::Span, _cx: &opentelemetry::Context) {}

    fn on_end(&self, span: SpanData) {
        if span.span_context.is_sampled() {
            self.file.append(&span_line(&self.resource, &span));
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource_json(resource);
    }
}

/// Writes each exported log record to the spool as it is emitted.
#[derive(Debug)]
pub(crate) struct SpoolLogs {
    file: Arc<SpoolFile>,
    resource: String,
}

impl SpoolLogs {
    pub(crate) fn new(file: Arc<SpoolFile>) -> Self {
        Self {
            file,
            resource: resource_json(&Resource::builder_empty().build()),
        }
    }
}

impl LogProcessor for SpoolLogs {
    fn emit(&self, record: &mut SdkLogRecord, scope: &InstrumentationScope) {
        self.file.append(&log_line(&self.resource, record, scope));
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource_json(resource);
    }
}

// ---- OTLP/JSON encoding (proto3 JSON mapping, with the OTLP exceptions:
// trace and span ids are lowercase hex, enums are integers). 64-bit integers
// are strings.

fn str_json(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "fmt::Write into a String cannot fail"
                )]
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn f64_json(out: &mut String, f: f64) {
    if f.is_nan() {
        out.push_str("\"NaN\"");
    } else if f.is_infinite() {
        out.push_str(if f > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        });
    } else {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write into a String cannot fail"
        )]
        let _ = write!(out, "{f}");
    }
}

fn nanos_json(out: &mut String, t: SystemTime) {
    let n = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    #[expect(
        clippy::let_underscore_must_use,
        reason = "fmt::Write into a String cannot fail"
    )]
    let _ = write!(out, "\"{n}\"");
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for ch in bytes.chunks(3) {
        let b = [
            *ch.first().unwrap_or(&0),
            *ch.get(1).unwrap_or(&0),
            *ch.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= ch.len() {
                s.push(char::from(
                    T.get(((n >> shift) & 63) as usize).copied().unwrap_or(b'A'),
                ));
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn list_json<T>(out: &mut String, items: &[T], mut each: impl FnMut(&mut String, &T)) {
    out.push('[');
    for (i, x) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        each(out, x);
    }
    out.push(']');
}

fn value_json(out: &mut String, v: &Value) {
    match v {
        Value::Bool(b) => {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write into a String cannot fail"
            )]
            let _ = write!(out, "{{\"boolValue\":{b}}}");
        }
        Value::I64(i) => {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write into a String cannot fail"
            )]
            let _ = write!(out, "{{\"intValue\":\"{i}\"}}");
        }
        Value::F64(f) => {
            out.push_str("{\"doubleValue\":");
            f64_json(out, *f);
            out.push('}');
        }
        Value::String(s) => {
            out.push_str("{\"stringValue\":");
            str_json(out, s.as_str());
            out.push('}');
        }
        Value::Array(a) => {
            out.push_str("{\"arrayValue\":{\"values\":");
            match a {
                Array::Bool(xs) => list_json(out, xs, |o, x| value_json(o, &Value::Bool(*x))),
                Array::I64(xs) => list_json(out, xs, |o, x| value_json(o, &Value::I64(*x))),
                Array::F64(xs) => list_json(out, xs, |o, x| value_json(o, &Value::F64(*x))),
                Array::String(xs) => list_json(out, xs, |o, x| {
                    o.push_str("{\"stringValue\":");
                    str_json(o, x.as_str());
                    o.push('}');
                }),
                _ => out.push_str("[]"),
            }
            out.push_str("}}");
        }
        _ => {
            out.push_str("{\"stringValue\":");
            str_json(out, &v.as_str());
            out.push('}');
        }
    }
}

fn any_json(out: &mut String, v: &AnyValue) {
    match v {
        AnyValue::Int(i) => value_json(out, &Value::I64(*i)),
        AnyValue::Double(f) => value_json(out, &Value::F64(*f)),
        AnyValue::Boolean(b) => value_json(out, &Value::Bool(*b)),
        AnyValue::String(s) => {
            out.push_str("{\"stringValue\":");
            str_json(out, s.as_str());
            out.push('}');
        }
        AnyValue::Bytes(b) => {
            out.push_str("{\"bytesValue\":");
            str_json(out, &base64(b));
            out.push('}');
        }
        AnyValue::ListAny(xs) => {
            out.push_str("{\"arrayValue\":{\"values\":");
            list_json(out, xs, any_json);
            out.push_str("}}");
        }
        AnyValue::Map(m) => {
            let mut kv: Vec<_> = m.iter().collect();
            kv.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
            out.push_str("{\"kvlistValue\":{\"values\":");
            list_json(out, &kv, |o, (k, v)| {
                o.push_str("{\"key\":");
                str_json(o, k.as_str());
                o.push_str(",\"value\":");
                any_json(o, v);
                o.push('}');
            });
            out.push_str("}}");
        }
        _ => out.push_str("{}"),
    }
}

fn attrs_json<'a>(out: &mut String, kvs: impl Iterator<Item = (&'a Key, &'a Value)>) {
    let kvs: Vec<_> = kvs.collect();
    list_json(out, &kvs, |o, (k, v)| {
        o.push_str("{\"key\":");
        str_json(o, k.as_str());
        o.push_str(",\"value\":");
        value_json(o, v);
        o.push('}');
    });
}

fn resource_json(r: &Resource) -> String {
    let mut out = String::from("{\"attributes\":");
    attrs_json(&mut out, r.iter());
    out.push('}');
    out
}

fn scope_json(out: &mut String, name: &str, s: &InstrumentationScope) {
    out.push_str("{\"name\":");
    str_json(out, name);
    if let Some(v) = s.version() {
        out.push_str(",\"version\":");
        str_json(out, v);
    }
    let attrs: Vec<_> = s.attributes().map(|kv| (&kv.key, &kv.value)).collect();
    if !attrs.is_empty() {
        out.push_str(",\"attributes\":");
        attrs_json(out, attrs.into_iter());
    }
    out.push('}');
}

fn span_kind(k: &SpanKind) -> u8 {
    match k {
        SpanKind::Server => 2,
        SpanKind::Client => 3,
        SpanKind::Producer => 4,
        SpanKind::Consumer => 5,
        SpanKind::Internal => 1,
    }
}

/// One span as a one-line `ExportTraceServiceRequest`.
pub(crate) fn span_line(resource: &str, s: &SpanData) -> String {
    let mut o = String::with_capacity(512);
    o.push_str("{\"resourceSpans\":[{\"resource\":");
    o.push_str(resource);
    o.push_str(",\"scopeSpans\":[{\"scope\":");
    scope_json(
        &mut o,
        s.instrumentation_scope.name(),
        &s.instrumentation_scope,
    );
    if let Some(u) = s.instrumentation_scope.schema_url() {
        o.push_str(",\"schemaUrl\":");
        str_json(&mut o, u);
    }
    let sc = &s.span_context;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "fmt::Write into a String cannot fail"
    )]
    let _ = write!(
        o,
        ",\"spans\":[{{\"traceId\":\"{}\",\"spanId\":\"{}\"",
        sc.trace_id(),
        sc.span_id()
    );
    let ts = sc.trace_state().header();
    if !ts.is_empty() {
        o.push_str(",\"traceState\":");
        str_json(&mut o, &ts);
    }
    if s.parent_span_id != opentelemetry::trace::SpanId::INVALID {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write into a String cannot fail"
        )]
        let _ = write!(o, ",\"parentSpanId\":\"{}\"", s.parent_span_id);
    }
    // W3C flags, plus the OTLP "has is_remote" (0x100) and "is_remote" (0x200) bits.
    let flags = u32::from(sc.trace_flags().to_u8())
        | 0x100
        | if s.parent_span_is_remote { 0x200 } else { 0 };
    #[expect(
        clippy::let_underscore_must_use,
        reason = "fmt::Write into a String cannot fail"
    )]
    let _ = write!(o, ",\"flags\":{flags},\"name\":");
    str_json(&mut o, &s.name);
    #[expect(
        clippy::let_underscore_must_use,
        reason = "fmt::Write into a String cannot fail"
    )]
    let _ = write!(
        o,
        ",\"kind\":{},\"startTimeUnixNano\":",
        span_kind(&s.span_kind)
    );
    nanos_json(&mut o, s.start_time);
    o.push_str(",\"endTimeUnixNano\":");
    nanos_json(&mut o, s.end_time);
    o.push_str(",\"attributes\":");
    attrs_json(&mut o, s.attributes.iter().map(|kv| (&kv.key, &kv.value)));
    if s.dropped_attributes_count > 0 {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write into a String cannot fail"
        )]
        let _ = write!(
            o,
            ",\"droppedAttributesCount\":{}",
            s.dropped_attributes_count
        );
    }
    if !s.events.events.is_empty() {
        o.push_str(",\"events\":");
        list_json(&mut o, &s.events.events, |o, e| {
            o.push_str("{\"timeUnixNano\":");
            nanos_json(o, e.timestamp);
            o.push_str(",\"name\":");
            str_json(o, &e.name);
            o.push_str(",\"attributes\":");
            attrs_json(o, e.attributes.iter().map(|kv| (&kv.key, &kv.value)));
            o.push('}');
        });
    }
    if s.events.dropped_count > 0 {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write into a String cannot fail"
        )]
        let _ = write!(o, ",\"droppedEventsCount\":{}", s.events.dropped_count);
    }
    if !s.links.links.is_empty() {
        o.push_str(",\"links\":");
        list_json(&mut o, &s.links.links, |o, l| {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write into a String cannot fail"
            )]
            let _ = write!(
                o,
                "{{\"traceId\":\"{}\",\"spanId\":\"{}\",\"attributes\":",
                l.span_context.trace_id(),
                l.span_context.span_id()
            );
            attrs_json(o, l.attributes.iter().map(|kv| (&kv.key, &kv.value)));
            o.push('}');
        });
    }
    match &s.status {
        Status::Error { description } => {
            o.push_str(",\"status\":{\"code\":2,\"message\":");
            str_json(&mut o, description);
            o.push('}');
        }
        Status::Ok => o.push_str(",\"status\":{\"code\":1}"),
        Status::Unset => o.push_str(",\"status\":{}"),
    }
    o.push_str("}]}]}]}");
    o
}

/// One log record as a one-line `ExportLogsServiceRequest`.
pub(crate) fn log_line(resource: &str, r: &SdkLogRecord, scope: &InstrumentationScope) -> String {
    let mut o = String::with_capacity(512);
    o.push_str("{\"resourceLogs\":[{\"resource\":");
    o.push_str(resource);
    o.push_str(",\"scopeLogs\":[{\"scope\":");
    // As the OTLP exporter does: the event's target names the scope.
    let name = r.target().map_or_else(|| scope.name(), |t| t.as_ref());
    scope_json(&mut o, name, scope);
    o.push_str(",\"logRecords\":[{");
    // As the OTLP exporter does: timeUnixNano only when the record has a
    // timestamp (the tracing bridge sets none), so a spooled record and the
    // exporter's copy of it carry the same fields.
    let observed = r.observed_timestamp().unwrap_or_else(SystemTime::now);
    if let Some(t) = r.timestamp() {
        o.push_str("\"timeUnixNano\":");
        nanos_json(&mut o, t);
        o.push(',');
    }
    o.push_str("\"observedTimeUnixNano\":");
    nanos_json(&mut o, observed);
    if let Some(sev) = r.severity_number() {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write into a String cannot fail"
        )]
        let _ = write!(o, ",\"severityNumber\":{}", sev as i32);
    }
    if let Some(t) = r.severity_text() {
        o.push_str(",\"severityText\":");
        str_json(&mut o, t);
    }
    if let Some(b) = r.body() {
        o.push_str(",\"body\":");
        any_json(&mut o, b);
    }
    let attrs: Vec<_> = r.attributes_iter().collect();
    o.push_str(",\"attributes\":");
    list_json(&mut o, &attrs, |o, (k, v)| {
        o.push_str("{\"key\":");
        str_json(o, k.as_str());
        o.push_str(",\"value\":");
        any_json(o, v);
        o.push('}');
    });
    if let Some(tc) = r.trace_context() {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write into a String cannot fail"
        )]
        let _ = write!(
            o,
            ",\"traceId\":\"{}\",\"spanId\":\"{}\"",
            tc.trace_id, tc.span_id
        );
        if let Some(f) = tc.trace_flags {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write into a String cannot fail"
            )]
            let _ = write!(o, ",\"flags\":{}", f.to_u8());
        }
    }
    if let Some(e) = r.event_name() {
        o.push_str(",\"eventName\":");
        str_json(&mut o, e);
    }
    o.push_str("}]}]}]}");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::KeyValue;
    use opentelemetry::logs::{LogRecord as _, Logger as _, LoggerProvider as _, Severity};
    use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
    use opentelemetry_sdk::logs::SdkLoggerProvider;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use serde_json::Value as J;
    use std::io::Write as _;

    /// The oracle is the shipper's own parser (strict `serde_json`, LangSec
    /// F19), so a line passes here only if the consumer takes it.
    fn lines(p: &Path) -> Vec<J> {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is JSON"))
            .collect()
    }

    fn attr<'a>(attrs: &'a J, key: &str) -> &'a J {
        attrs
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == key)
            .map(|a| &a["value"])
            .unwrap_or_else(|| panic!("no attribute {key} in {attrs}"))
    }

    /// A span ends -> one line, in the shape the harness readers (q.py,
    /// span-check.py) take from the collector's file exporter, already on
    /// disk before any flush or shutdown.
    #[test]
    fn a_finished_span_is_on_disk_as_one_otlp_json_line() {
        let dir = private_tempdir();
        let file = SpoolFile::open(dir.path().join("spool"), "svc");
        let provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder_empty()
                    .with_service_name("svc")
                    .with_attribute(KeyValue::new("process.pid", 42_i64))
                    .build(),
            )
            .with_span_processor(SpoolSpans::new(file.clone()))
            .build();
        let tracer = provider.tracer("scope-a");
        let mut span = tracer.start("session.message");
        span.set_attribute(KeyValue::new("kind", "exec \"q\"\n"));
        span.set_attribute(KeyValue::new("n", 7_i64));
        span.set_attribute(KeyValue::new("ok", true));
        span.set_attribute(KeyValue::new("r", 1.5_f64));
        span.add_event("ev", vec![KeyValue::new("e", "x")]);
        let sc = span.span_context().clone();
        span.end();
        // No flush, no shutdown: the line is already written.
        let got = lines(&file.path().unwrap());
        assert_eq!(got.len(), 1, "one line per finished span");
        let rs = &got[0]["resourceSpans"][0];
        assert_eq!(
            attr(&rs["resource"]["attributes"], "service.name")["stringValue"],
            "svc"
        );
        assert_eq!(
            attr(&rs["resource"]["attributes"], "process.pid")["intValue"],
            "42"
        );
        let ss = &rs["scopeSpans"][0];
        assert_eq!(ss["scope"]["name"], "scope-a");
        let sp = &ss["spans"][0];
        assert_eq!(sp["name"], "session.message");
        assert_eq!(sp["traceId"], format!("{}", sc.trace_id()));
        assert_eq!(sp["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(sp["spanId"], format!("{}", sc.span_id()));
        assert!(
            sp.get("parentSpanId").is_none(),
            "a root span has no parent id"
        );
        let start: u128 = sp["startTimeUnixNano"].as_str().unwrap().parse().unwrap();
        let end: u128 = sp["endTimeUnixNano"].as_str().unwrap().parse().unwrap();
        assert!(start > 1_600_000_000_000_000_000 && end >= start);
        assert_eq!(
            attr(&sp["attributes"], "kind")["stringValue"],
            "exec \"q\"\n"
        );
        assert_eq!(attr(&sp["attributes"], "n")["intValue"], "7");
        assert_eq!(attr(&sp["attributes"], "ok")["boolValue"], true);
        assert_eq!(attr(&sp["attributes"], "r")["doubleValue"], 1.5);
        assert_eq!(sp["events"][0]["name"], "ev");
        assert_eq!(sp["kind"], 1);
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = provider.shutdown();
    }

    #[test]
    fn a_log_record_is_one_otlp_json_line() {
        let dir = private_tempdir();
        let file = SpoolFile::open(dir.path().to_path_buf(), "svc");
        let provider = SdkLoggerProvider::builder()
            .with_resource(Resource::builder_empty().with_service_name("svc").build())
            .with_log_processor(SpoolLogs::new(file.clone()))
            .build();
        let logger = provider.logger("scope-l");
        let mut rec = logger.create_log_record();
        rec.set_severity_number(Severity::Warn);
        rec.set_severity_text("WARN");
        rec.set_body(AnyValue::from("hello"));
        rec.add_attribute("k", AnyValue::Int(3));
        rec.add_attribute("b", AnyValue::Bytes(Box::new(b"abcd".to_vec())));
        logger.emit(rec);
        let got = lines(&file.path().unwrap());
        assert_eq!(got.len(), 1);
        let rl = &got[0]["resourceLogs"][0];
        assert_eq!(
            attr(&rl["resource"]["attributes"], "service.name")["stringValue"],
            "svc"
        );
        let lr = &rl["scopeLogs"][0]["logRecords"][0];
        assert_eq!(lr["severityNumber"], 13);
        assert_eq!(lr["severityText"], "WARN");
        assert_eq!(lr["body"]["stringValue"], "hello");
        assert_eq!(attr(&lr["attributes"], "k")["intValue"], "3");
        assert_eq!(attr(&lr["attributes"], "b")["bytesValue"], "YWJjZA==");
        let _observed: u128 = lr["observedTimeUnixNano"]
            .as_str()
            .unwrap()
            .parse()
            .expect("observedTimeUnixNano is a decimal u128");
        assert!(
            lr.get("timeUnixNano").is_none(),
            "no timestamp was set, so none is made up: {lr}"
        );
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = provider.shutdown();
    }

    /// F19, writer side: for every string and double an attribute can carry
    /// (controls, NUL, DEL, NEL, the line separators, a BOM, U+FFFD, an
    /// astral character; subnormal, tiny, huge, negative zero and non-finite
    /// doubles) the writer emits exactly one line, with no raw LF or CR,
    /// that the strict consumer parses back to the same value: non-finite
    /// doubles to the strings OTLP/JSON names them by, and every other
    /// double bit for bit. The one exception is pinned, not hidden: the
    /// consumer's serde_json (default features, no `float_roundtrip`)
    /// parses a double as significand times a power of ten and overflows on
    /// `f64::MAX` however it is spelled, so it refuses that line with
    /// "number out of range". The fix is the consumer's feature flag.
    #[test]
    fn every_attribute_value_round_trips_through_the_strict_parser() {
        let controls: String = (0u8..0x20).map(char::from).collect();
        let strings = [
            "\0",
            "a\0b",
            "\u{1}\u{1f}\u{7f}",
            "\u{85}",
            "\u{2028}\u{2029}",
            "\u{feff}",
            "\u{fffd}",
            "\u{1F600}",
            "\"\\/",
            "\t\n\r",
            "\r\n",
            controls.as_str(),
        ];
        enum Read {
            Exact,
            Named(&'static str),
            Refused,
        }
        let doubles = [
            (f64::MIN_POSITIVE, Read::Exact),
            (5e-324, Read::Exact),
            (-0.0, Read::Exact),
            (1e300, Read::Exact),
            (1e308, Read::Exact),
            (1.5, Read::Exact),
            (f64::MAX, Read::Refused),
            (-f64::MAX, Read::Refused),
            (f64::NAN, Read::Named("NaN")),
            (f64::INFINITY, Read::Named("Infinity")),
            (f64::NEG_INFINITY, Read::Named("-Infinity")),
        ];
        let dir = private_tempdir();
        let file = SpoolFile::open(dir.path().to_path_buf(), "svc");
        let provider = SdkTracerProvider::builder()
            .with_span_processor(SpoolSpans::new(file.clone()))
            .build();
        let tracer = provider.tracer("t");
        for s in strings {
            let mut span = tracer.start("s");
            span.set_attribute(KeyValue::new("v", s.to_owned()));
            span.end();
        }
        for (f, _) in &doubles {
            let mut span = tracer.start("d");
            span.set_attribute(KeyValue::new("v", *f));
            span.end();
        }
        let text = std::fs::read_to_string(file.path().unwrap()).unwrap();
        assert!(!text.contains('\r'), "a raw CR in the spool");
        assert!(text.ends_with('\n'));
        let raw: Vec<&str> = text.split_terminator('\n').collect();
        assert_eq!(
            raw.len(),
            strings.len() + doubles.len(),
            "one line per span"
        );
        let value = |l: &str| -> Result<J, serde_json::Error> {
            let j: J = serde_json::from_str(l)?;
            Ok(attr(
                &j["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"],
                "v",
            )
            .clone())
        };
        for (s, l) in strings.iter().zip(&raw) {
            assert_eq!(value(l).unwrap()["stringValue"], J::from(*s), "{l}");
        }
        for ((f, read), l) in doubles.iter().zip(&raw[strings.len()..]) {
            match read {
                Read::Exact => {
                    let got = value(l).unwrap()["doubleValue"].as_f64();
                    assert_eq!(got.map(f64::to_bits), Some(f.to_bits()), "{f:e}: {l}");
                }
                Read::Named(name) => {
                    assert_eq!(value(l).unwrap()["doubleValue"], *name, "{f:e}: {l}");
                }
                Read::Refused => {
                    let err = value(l).unwrap_err().to_string();
                    assert!(err.contains("number out of range"), "{f:e}: {err}: {l}");
                }
            }
        }
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = provider.shutdown();
    }

    /// F19, consumer side: the lines the strict consumer refuses, and that
    /// the former lenient oracle would have passed or that the writer could
    /// be regressed into emitting: a trailing comma, a comment, a torn line,
    /// a raw NUL, a BOM, a lone surrogate escape, nesting past 127 levels.
    /// The writer's spelling of the same NUL is accepted.
    #[test]
    fn the_strict_parser_refuses_what_the_writer_must_never_emit() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        let strict = |l: &str| serde_json::from_str::<J>(l).is_ok();
        for (line, ok) in [
            ("{\"resourceSpans\":[],}", false),
            ("{\"resourceSpans\":[]/*x*/}", false),
            ("{\"resourceSpans\":[{\"resource", false),
            ("{\"a\":\"\0\"}", false),
            ("\u{feff}{\"a\":1}", false),
            ("{\"a\":\"\\ud800\"}", false),
            (deep(128).as_str(), false),
            (deep(127).as_str(), true),
            ("{\"a\":\"\\u0000\"}", true),
            ("{\"resourceSpans\":[]}", true),
        ] {
            assert_eq!(strict(line), ok, "{line:?}");
        }
        // Why the oracle changed: the lenient parser took these two.
        for line in ["{\"resourceSpans\":[],}", "{\"resourceSpans\":[]/*x*/}"] {
            if let Err(e) = serde_json_lenient::from_str::<serde_json_lenient::Value>(line) {
                panic!("the lenient parser refused {line:?}: {e}");
            }
        }
    }

    /// The one shape the writer can emit that the strict consumer refuses:
    /// a log body nested as a list of lists 40 deep (3 JSON levels per list
    /// plus the 8 of the envelope pass serde_json's 127). Nothing in the tree
    /// nests a body (the tracing bridge's bodies are strings), so this pins
    /// the boundary rather than a bug: a line for a body nested 39 deep is
    /// taken, 40 deep is dropped by the shipper.
    #[test]
    fn a_log_body_nested_forty_deep_is_a_line_the_strict_parser_drops() {
        fn nested(depth: usize) -> AnyValue {
            (0..depth).fold(AnyValue::from("x"), |inner, _| {
                AnyValue::ListAny(Box::new(vec![inner]))
            })
        }
        let dir = private_tempdir();
        let file = SpoolFile::open(dir.path().to_path_buf(), "svc");
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(SpoolLogs::new(file.clone()))
            .build();
        let logger = provider.logger("l");
        for depth in [39, 40] {
            let mut rec = logger.create_log_record();
            rec.set_body(nested(depth));
            logger.emit(rec);
        }
        let text = std::fs::read_to_string(file.path().unwrap()).unwrap();
        let raw: Vec<&str> = text.split_terminator('\n').collect();
        assert_eq!(raw.len(), 2);
        assert!(
            serde_json::from_str::<J>(raw[0]).is_ok(),
            "39 deep: {}",
            raw[0]
        );
        let err = serde_json::from_str::<J>(raw[1]).unwrap_err();
        assert!(
            err.to_string().contains("recursion limit"),
            "40 deep: {err}"
        );
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = provider.shutdown();
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    /// A temporary directory with mode 0700: the spool refuses a directory
    /// with group or other bits, and `tempfile` creates its directories with
    /// the umask's default (0755).
    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    /// `dir` opened and checked as the spool opens it.
    fn opened(dir: &Path) -> SpoolDir {
        SpoolDir::open_checked(dir)
            .ok()
            .expect("a private directory is accepted")
    }

    fn put(dir: &Path, name: &str, len: usize, age: Duration) {
        let p = dir.join(name);
        std::fs::write(&p, vec![b'x'; len]).unwrap();
        let f = File::options().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    fn jsonl(dir: &Path) -> Vec<(String, u64)> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
            .map(|e| {
                (
                    e.file_name().into_string().unwrap(),
                    e.metadata().unwrap().len(),
                )
            })
            .collect();
        v.sort();
        v
    }

    fn small(max_bytes: u64, segment_bytes: u64) -> Limits {
        Limits {
            max_bytes,
            segment_bytes,
            ..Limits::DEFAULT
        }
    }

    /// The bound: files past the age limit go, then the oldest until the
    /// directory is under the size limit; other files are never touched.
    #[test]
    fn prune_drops_old_files_then_oldest_until_under_the_size_bound() {
        let dir = private_tempdir();
        let d = dir.path();
        let hour = Duration::from_secs(3600);
        put(d, "ancient-1-1700000000000.jsonl", 10, MAX_AGE + hour);
        put(d, "a-1-1700000000000.jsonl", 400, 5 * hour);
        put(d, "b-1-1700000000000.jsonl", 400, 4 * hour);
        put(d, "c-1-1700000000000.jsonl", 400, 3 * hour);
        put(d, "keep.txt", 5000, MAX_AGE + hour);
        let left = prune(&opened(d), SystemTime::now(), MAX_AGE, 1000);
        let mut names: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                STAMP,
                "b-1-1700000000000.jsonl",
                "c-1-1700000000000.jsonl",
                "keep.txt"
            ]
        );
        assert_eq!(left, 800);
    }

    /// A long-lived writer never stops: it rotates to a new file at the
    /// segment size, and the rotation prunes its own oldest files, so the
    /// directory stays under the bound while the newest records are kept.
    #[test]
    fn a_long_lived_process_rotates_and_keeps_the_directory_bounded() {
        let dir = private_tempdir();
        let d = dir.path();
        let file = SpoolFile::with_limits(d.to_path_buf(), "svc", small(10_000, 2_000));
        let mut peak = 0;
        for i in 0..1000 {
            // 100-byte lines: 20 per file, 50_000 lines' worth of the old
            // per-process budget five times over.
            file.append(&format!("{i:099}"));
            let total: u64 = jsonl(d).iter().map(|f| f.1).sum();
            peak = peak.max(total);
        }
        assert!(peak <= 10_000, "directory peaked at {peak} bytes");
        let files = jsonl(d);
        assert!(files.len() >= 4, "rotated: {files:?}");
        assert!(files.iter().all(|f| f.1 <= 2_000), "{files:?}");
        let newest = std::fs::read_to_string(file.path().unwrap()).unwrap();
        assert!(newest.ends_with(&format!("{:099}\n", 999)), "{newest}");
        // Every file holds only whole lines.
        for (name, _) in &files {
            let t = std::fs::read_to_string(d.join(name)).unwrap();
            assert!(t.ends_with('\n') && t.lines().all(|l| l.len() == 99));
        }
        // The first file of the process (the oldest) was pruned away.
        assert!(!files.iter().any(|f| f.0 == file.name.to_string()));
    }

    /// A file another process pruned away under a live writer (a quiet
    /// daemon's file is the oldest) is noticed, and writing moves to a new file.
    #[test]
    fn a_file_pruned_away_under_a_writer_is_replaced() {
        let dir = private_tempdir();
        let limits = Limits {
            recheck_every: Duration::ZERO,
            ..Limits::DEFAULT
        };
        let file = SpoolFile::with_limits(dir.path().to_path_buf(), "svc", limits);
        file.append("one");
        let first = file.path().unwrap();
        std::fs::remove_file(&first).unwrap();
        file.append("two");
        let second = file.path().unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(second).unwrap(), "two\n");
    }

    /// A process's first file scans the directory only when no scan is
    /// recent (the stamp), so a CLI run in a big spool costs one stat.
    #[test]
    fn a_first_file_prunes_only_when_no_scan_is_recent() {
        let dir = private_tempdir();
        let d = dir.path();
        let limits = small(1000, 100);
        put(
            d,
            "big-1-1700000000000.jsonl",
            5000,
            Duration::from_secs(60),
        );
        std::fs::write(d.join(STAMP), b"").unwrap();
        SpoolFile::with_limits(d.to_path_buf(), "a", limits).append("x");
        assert!(
            d.join("big-1-1700000000000.jsonl").exists(),
            "a fresh stamp skips the scan"
        );
        let stamp = File::options().write(true).open(d.join(STAMP)).unwrap();
        stamp
            .set_modified(SystemTime::now() - PRUNE_EVERY - Duration::from_secs(1))
            .unwrap();
        SpoolFile::with_limits(d.to_path_buf(), "b", limits).append("x");
        assert!(
            !d.join("big-1-1700000000000.jsonl").exists(),
            "a stale stamp scans"
        );
        let age = SystemTime::now()
            .duration_since(
                std::fs::metadata(d.join(STAMP))
                    .unwrap()
                    .modified()
                    .unwrap(),
            )
            .unwrap_or_default();
        assert!(age < PRUNE_EVERY, "the scan touched the stamp");
    }

    /// A symbolic link at a spool file's name or at the [`STAMP`]'s name is
    /// not followed: the open and the stamp's write fail on the link, and
    /// the file it points at keeps its contents (code review, CodeRabbit).
    #[test]
    fn a_symlink_at_a_spool_file_or_the_stamp_is_not_followed() {
        let dir = private_tempdir();
        let outside = private_tempdir();
        let target = outside.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let d = dir.path();

        let file = d.join("min-1-1700000000000.jsonl");
        std::os::unix::fs::symlink(&target, &file).unwrap();
        let err = opened(d)
            .open_append("min-1-1700000000000.jsonl")
            .expect_err("a link is not opened");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "{err}");

        std::os::unix::fs::symlink(&target, d.join(STAMP)).unwrap();
        prune(
            &opened(d),
            SystemTime::now(),
            Duration::from_secs(60),
            u64::MAX,
        );
        assert!(
            std::fs::symlink_metadata(d.join(STAMP))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the stamp's link is left as it was"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"keep", "target untouched");
    }

    /// A writer that takes part of a line and then fails (ENOSPC).
    struct Short {
        out: Vec<u8>,
        take: Vec<Option<usize>>,
    }

    impl std::io::Write for Short {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self.take.pop().flatten() {
                Some(k) => {
                    let k = k.min(buf.len());
                    self.out.extend_from_slice(&buf[..k]);
                    Ok(k)
                }
                None => Err(std::io::Error::other("ENOSPC")),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A short write is continued when the file takes the rest; one that
    /// cannot finish reports the torn length.
    #[test]
    fn a_short_write_is_continued_or_reported() {
        // 3 bytes, then the rest: the line is whole.
        let mut w = Short {
            out: vec![],
            take: vec![Some(usize::MAX), Some(3)],
        };
        assert_eq!(write_line(&mut w, b"abcdef\n"), 7);
        assert_eq!(w.out, b"abcdef\n");
        // 3 bytes, then an error on every retry: torn at 3.
        let mut w = Short {
            out: vec![],
            take: vec![None, None, None, Some(3)],
        };
        assert_eq!(write_line(&mut w, b"abcdef\n"), 3);
    }

    /// After a torn line, the next record starts with a newline, so the torn
    /// line stays one bad line and the next record is whole on its own line.
    #[test]
    fn a_torn_line_never_joins_the_next_record() {
        let dir = private_tempdir();
        let file = SpoolFile::open(dir.path().to_path_buf(), "svc");
        file.append("{\"a\":1}");
        let path = file.path().unwrap();
        // What a short write leaves: part of a record, no newline.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"torn\":")
            .unwrap();
        file.state.lock().unwrap().torn = true;
        file.append("{\"b\":2}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "{\"a\":1}\n{\"torn\":\n{\"b\":2}\n");
        assert!(!file.state.lock().unwrap().torn);
    }

    /// A relocated spool opens its next file in the new directory and leaves
    /// the old file as it was; a deferred spool writes nothing until it is
    /// given a directory, then writes there.
    #[test]
    fn a_spool_relocates_and_a_deferred_one_waits_for_its_directory() {
        let tmp = private_tempdir();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        let f = SpoolFile::open(a.clone(), "svc");
        f.append("{\"one\":1}");
        assert_eq!(std::fs::read_dir(&a).unwrap().count(), 1, "one file in a");
        f.relocate(b.clone());
        assert_eq!(f.dir(), Some(b.clone()));
        f.append("{\"two\":2}");
        assert_eq!(std::fs::read_dir(&a).unwrap().count(), 1, "a is left alone");
        let in_b: Vec<_> = std::fs::read_dir(&b)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(in_b.len(), 1, "one file in b: {in_b:?}");
        assert_eq!(std::fs::read_to_string(&in_b[0]).unwrap(), "{\"two\":2}\n");
        f.relocate(b.clone()); // the same directory: nothing changes
        f.append("{\"three\":3}");
        assert_eq!(
            std::fs::read_dir(&b).unwrap().count(),
            1,
            "still one file in b"
        );

        let d = SpoolFile::deferred("svc");
        assert_eq!(d.dir(), None);
        d.append("{\"dropped\":0}");
        let c = tmp.path().join("c");
        assert!(!c.exists(), "a deferred spool creates nothing");
        d.relocate(c.clone());
        d.append("{\"kept\":1}");
        let in_c: Vec<_> = std::fs::read_dir(&c)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(in_c.len(), 1);
        assert_eq!(std::fs::read_to_string(&in_c[0]).unwrap(), "{\"kept\":1}\n");
    }

    /// A released spool has closed its file (no descriptor is left on it)
    /// and drops what comes after; a relocation brings it back.
    #[test]
    fn a_released_spool_closes_its_file_and_drops_later_records() {
        let tmp = private_tempdir();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        let f = SpoolFile::open(a.clone(), "svc");
        f.append("{\"one\":1}");
        let p = f.path().unwrap();
        let open_fds = |p: &Path| {
            std::fs::read_dir("/proc/self/fd").map_or(0, |fds| {
                fds.filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                    .filter(|t| t == p)
                    .count()
            })
        };
        if cfg!(target_os = "linux") {
            assert_eq!(open_fds(&p), 1, "the spool file is open before release");
        }
        f.release();
        assert_eq!(f.dir(), None);
        assert!(f.state.lock().unwrap().file.is_none());
        if cfg!(target_os = "linux") {
            assert_eq!(open_fds(&p), 0, "no descriptor left on the spool file");
        }
        f.append("{\"dropped\":2}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"one\":1}\n");
        assert_eq!(std::fs::read_dir(&a).unwrap().count(), 1, "no new file");
        f.release(); // again: a no-op

        f.relocate(b.clone());
        f.append("{\"three\":3}");
        assert_eq!(std::fs::read_dir(&b).unwrap().count(), 1, "relocated");
    }

    /// A process that records nothing creates nothing (no file, no directory,
    /// no stamp), even after the processors are built.
    #[test]
    fn a_process_that_records_nothing_leaves_no_file() {
        let dir = private_tempdir();
        let file = SpoolFile::open(dir.path().join("spool"), "svc");
        let provider = SdkTracerProvider::builder()
            .with_span_processor(SpoolSpans::new(file.clone()))
            .build();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = provider.shutdown();
        assert!(file.path().is_none());
        assert!(!dir.path().join("spool").exists());
    }

    /// A record bigger than a whole file is dropped; the next one is written.
    #[test]
    fn a_record_bigger_than_a_file_is_dropped() {
        let dir = private_tempdir();
        let file = SpoolFile::with_limits(dir.path().to_path_buf(), "svc", small(10_000, 100));
        file.append(&"x".repeat(200));
        file.append("small");
        let text = std::fs::read_to_string(file.path().unwrap()).unwrap();
        assert_eq!(text, "small\n");
    }

    /// The names prune may touch: a spool writer's, first file or rotated,
    /// whatever its service; nothing else.
    #[test]
    fn only_spool_names_are_spool_files() {
        for name in [
            "minimald-42-1700000000000.jsonl",
            "minimald-42-1700000000000-3.jsonl",
            "minimal-cli-7-1700000000000.jsonl",
            "a_b-1-9999999999999-12.jsonl",
        ] {
            assert!(is_spool_file(name), "{name}");
        }
        for name in [
            "results.jsonl",
            "report-2024-10.jsonl",
            "svc-42-1700000000000.json",
            "svc-42-1700000000000.jsonl.bak",
            "-42-1700000000000.jsonl",
            "svc-042-1700000000000.jsonl",
            "svc-42-170000000000.jsonl",
            "svc-42-1700000000000-0.jsonl",
            "svc-42-1700000000000-x.jsonl",
            "s.vc-42-1700000000000.jsonl",
            ".pruned",
        ] {
            assert!(!is_spool_file(name), "{name}");
        }
        assert!(is_spool_file(
            &SpoolFile::open(PathBuf::from("/nowhere"), "min d")
                .name
                .to_string()
        ));
    }

    /// One grammar for the writer and the pruner (LangSec F17, F18): every
    /// name the writer can make, whatever the service string, pid or clock,
    /// parses back to the same value, and every accepted name formats back
    /// to itself. A clock before 2001 or after 2286 gives the nearest name
    /// the grammar has, not one the pruner skips.
    #[test]
    fn spool_names_round_trip_through_one_grammar() {
        let ms = |n: u64| UNIX_EPOCH + Duration::from_millis(n);
        let made = [
            (
                ("minimald", 1, ms(1_700_000_000_000)),
                "minimald-1-1700000000000",
            ),
            (
                ("min d/x.y", 42, ms(1_700_000_000_000)),
                "min_d_x_y-42-1700000000000",
            ),
            (("", 7, ms(1_700_000_000_000)), "_-7-1700000000000"),
            (
                ("a-b_c", u32::MAX, ms(9_999_999_999_999)),
                "a-b_c-4294967295-9999999999999",
            ),
            // F18: a clock before 2001 (the guest's pid 1 before timekeep)
            (("minimald", 1, ms(5_000)), "minimald-1-1000000000000"),
            (("minimald", 1, UNIX_EPOCH), "minimald-1-1000000000000"),
            (
                ("minimald", 1, ms(999_999_999_999)),
                "minimald-1-1000000000000",
            ),
            // a clock after 2286
            (("svc", 1, ms(10_000_000_000_000)), "svc-1-9999999999999"),
            // pid 0 is not a process; the grammar has no leading zero
            (("svc", 0, ms(1_700_000_000_000)), "svc-1-1700000000000"),
        ];
        for ((service, pid, start), stem) in made {
            let name = SpoolName::new(service, pid, start);
            for n in [0, 1, 2, u32::MAX] {
                let rotated = name.rotation(n);
                let text = rotated.to_string();
                let want = if n == 0 {
                    format!("{stem}.jsonl")
                } else {
                    format!("{stem}-{n}.jsonl")
                };
                assert_eq!(text, want);
                assert_eq!(SpoolName::parse(&text), Some(rotated), "{text}");
                assert!(is_spool_file(&text), "{text}");
            }
        }
        for text in [
            "minimald-42-1700000000000.jsonl",
            "minimald-42-1700000000000-3.jsonl",
            "a-b-1-1700000000000-18446744073709551615.jsonl",
            // 13 digits in the last place can only be a start: this is
            // service `x-1`, pid 1700000000000? No: a pid is a u32, so it
            // is service `x`, pid 1, rotation 1700000000000.
            "x-1-1700000000000-1700000000000.jsonl",
        ] {
            let parsed = SpoolName::parse(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(parsed.to_string(), text);
        }
        assert_eq!(
            SpoolName::parse("x-1-1700000000000-1700000000000.jsonl"),
            Some(SpoolName {
                service: "x".to_owned(),
                pid: 1,
                start_ms: 1_700_000_000_000,
                n: Some(1_700_000_000_000),
            })
        );
    }

    /// TEL-018: a spool whose file could not be opened (the
    /// directory could not be made: a full or read-only filesystem, here a
    /// regular file in the way) tries again on a later record once the cause
    /// is gone, instead of staying off for the life of the process.
    #[test]
    fn a_failed_open_is_retried() {
        let tmp = private_tempdir();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"").unwrap();
        let dir = blocker.join("spool");
        let file = SpoolFile::open(dir.clone(), "svc");
        file.append("{\"lost\":1}");
        assert!(file.path().is_none(), "the open failed");
        std::fs::remove_file(&blocker).unwrap();
        file.append("{\"kept\":2}");
        let p = file.path().expect("the next record opened a file");
        assert_eq!(std::fs::read_to_string(p).unwrap(), "{\"kept\":2}\n");
    }

    /// After the next record's retry fails too, the spool waits
    /// [`Limits::retry_every`] before it tries again, so a cause that stays
    /// costs one failed open per interval, not one per record.
    #[test]
    fn a_failing_open_backs_off_after_the_first_retry() {
        let tmp = private_tempdir();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"").unwrap();
        let limits = Limits {
            retry_every: Duration::from_millis(300),
            ..Limits::DEFAULT
        };
        let file = SpoolFile::with_limits(blocker.join("spool"), "svc", limits);
        file.append("{\"lost\":1}"); // fails
        file.append("{\"lost\":2}"); // the retry fails: back off
        std::fs::remove_file(&blocker).unwrap();
        file.append("{\"lost\":3}"); // within the interval: not tried
        assert!(file.path().is_none(), "no open was tried while backing off");
        assert_eq!(file.state.lock().unwrap().failures, 2);
        std::thread::sleep(Duration::from_millis(350));
        file.append("{\"kept\":4}");
        let p = file
            .path()
            .expect("the interval passed, so the open was retried");
        assert_eq!(std::fs::read_to_string(p).unwrap(), "{\"kept\":4}\n");
        assert_eq!(file.state.lock().unwrap().failures, 0);
        assert!(
            file.warned.load(Ordering::Relaxed),
            "the failure was logged"
        );
    }

    /// TEL-019: a spool directory that is group- or
    /// other-accessible, or reached through a symlink, is refused: nothing
    /// is written there, the spool moves to its fallback (the state-dir
    /// default in production) once, and with no fallback it drops records.
    /// A foreign owner is refused by the same check (`ForeignOwner`); only
    /// root could set one up here, so the mode and link cases stand for it.
    #[cfg(unix)]
    #[test]
    fn a_shared_or_foreign_spool_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = private_tempdir();
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o750)).unwrap();
        let fallback = tmp.path().join("fallback");

        let file = SpoolFile::with_fallback(
            shared.clone(),
            "svc",
            Some(fallback.clone()),
            Limits::DEFAULT,
        );
        file.append("{\"refused\":1}");
        assert!(jsonl(&shared).is_empty(), "nothing lands in the shared dir");
        assert_eq!(file.dir(), Some(fallback.clone()), "moved to the fallback");
        assert!(file.path().is_none(), "the refused record was dropped");
        assert_eq!(
            std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
            0o750,
            "a refused directory is left as it was, not tightened"
        );

        file.append("{\"kept\":2}");
        let p = file.path().expect("the next record opens in the fallback");
        assert!(p.starts_with(&fallback), "{}", p.display());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"kept\":2}\n");
        assert_eq!(
            std::fs::metadata(&fallback).unwrap().permissions().mode() & 0o777,
            0o700,
            "the fallback was created private"
        );
        assert!(jsonl(&shared).is_empty());

        // A symlink to a private directory: refused without following it,
        // and with no fallback the spool has nowhere to write.
        let target = tmp.path().join("target");
        let mut db = std::fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut db, 0o700);
        db.create(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let file = SpoolFile::with_limits(link.clone(), "svc", Limits::DEFAULT);
        file.append("{\"via-link\":3}");
        file.append("{\"via-link\":4}");
        assert!(jsonl(&target).is_empty(), "the link was not followed");
        assert!(file.path().is_none());
        assert_eq!(file.dir(), None, "no fallback: the spool is off");
        assert!(
            !file.warned.load(Ordering::Relaxed),
            "a refusal is not an open failure"
        );
    }

    /// The spool keeps the descriptor of the
    /// directory it checked, and opens, prunes and stamps through it. A user
    /// who renames the checked directory away and puts a symlink to another
    /// directory at its path redirects nothing: every later file, rotations
    /// included, lands in the directory that was checked, and nothing is
    /// created behind the link.
    #[cfg(unix)]
    #[test]
    fn a_directory_swapped_after_the_check_does_not_redirect_writes() {
        let tmp = private_tempdir();
        let spool = tmp.path().join("spool");
        let moved = tmp.path().join("moved");
        let elsewhere = tmp.path().join("elsewhere");
        let mut db = std::fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut db, 0o700);
        db.create(&elsewhere).unwrap();

        // A 64-byte segment: a few records force rotations, each of which
        // prunes, stamps and opens a new file.
        let file = SpoolFile::with_limits(spool.clone(), "svc", small(1 << 20, 64));
        file.append("{\"n\":0}");
        assert_eq!(
            jsonl(&spool).len(),
            1,
            "the first file is in the checked dir"
        );

        std::fs::rename(&spool, &moved).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &spool).unwrap();
        for i in 1..20 {
            file.append(&format!("{{\"n\":{i}}}"));
        }
        assert!(
            std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "nothing was created behind the swapped-in link"
        );
        let files = jsonl(&moved);
        assert!(
            files.len() > 1,
            "rotations stayed in the checked dir: {files:?}"
        );
        let total: u64 = files.iter().map(|(_, n)| n).sum();
        assert!(
            total > 19 * 8,
            "every record is in the checked dir: {files:?}"
        );
    }

    /// TEL-017: prune deletes this spool's files only. A `*.jsonl`
    /// that is not named like a spool file (`<service>-<pid>-<start>[-n]`)
    /// survives however old, in a directory a user named with
    /// `MINIMAL_OTEL_SPOOL_DIR`.
    #[test]
    fn prune_leaves_foreign_jsonl_alone() {
        let dir = private_tempdir();
        let d = dir.path();
        let old = MAX_AGE + Duration::from_secs(3600);
        put(d, "results.jsonl", 10, old);
        put(d, "minimald-42-1700000000000.jsonl", 10, old);
        put(d, "minimald-42-1700000000000-3.jsonl", 10, old);
        prune(&opened(d), SystemTime::now(), MAX_AGE, u64::MAX);
        assert_eq!(jsonl(d), [("results.jsonl".to_owned(), 10)]);
    }

    /// Past [`MAX_AGE`] a file goes whatever the room; a file dated in the
    /// future is never old.
    #[test]
    fn prune_drops_files_older_than_seven_days() {
        let now = 30 * nanos(MAX_AGE);
        let day = nanos(Duration::from_secs(24 * 3600));
        let files = [
            (now - nanos(MAX_AGE) - 1, 1),
            (now - nanos(MAX_AGE), 1),
            (now - day, 1),
            (now + day, 1),
        ];
        let mut delete = [false; 4];
        plan_prune(&files, &mut delete, now, nanos(MAX_AGE), u64::MAX);
        assert_eq!(delete, [true, false, false, false]);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::plan_prune;

    /// Every set of exactly `N` files, sizes, ages and clock readings: every
    /// file past `max_age` is deleted, what is kept totals at most
    /// `prune_to`, a file deleted for size is no newer than any file kept,
    /// and files go for size only while the rest is over `prune_to`.
    fn check<const N: usize>() {
        let files: [(u64, u64); N] = kani::any();
        let now: u64 = kani::any();
        let max_age: u64 = kani::any();
        let prune_to: u64 = kani::any();
        let mut delete = [false; N];
        plan_prune(&files, &mut delete, now, max_age, prune_to);
        let old = |mtime: u64| now.checked_sub(mtime).is_some_and(|age| age > max_age);
        let mut kept: u128 = 0;
        for (&(mtime, len), &d) in files.iter().zip(&delete) {
            assert!(d || !old(mtime), "a file past max_age is kept");
            if !d {
                kept += u128::from(len);
            }
        }
        assert!(
            kept <= u128::from(prune_to),
            "what is kept is over prune_to"
        );
        let mut for_size = false;
        let mut needed = false;
        for (&(gone, len), &d) in files.iter().zip(&delete) {
            if d && !old(gone) {
                for_size = true;
                needed |= kept + u128::from(len) > u128::from(prune_to);
                for (&(k, _), &dk) in files.iter().zip(&delete) {
                    assert!(dk || gone <= k, "a newer file went for size");
                }
            }
        }
        assert!(
            !for_size || needed,
            "a file went for size while the rest fit"
        );
    }

    // Unwind N + 2: the size loop runs at most N + 1 times.

    #[kani::proof]
    #[kani::unwind(3)]
    fn prune_plan_one_file() {
        check::<1>();
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn prune_plan_two_files() {
        check::<2>();
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn prune_plan_three_files() {
        check::<3>();
    }
}
