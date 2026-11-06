//! Patches in a session's home and workbench, bound through handles that no
//! later rename or link swap can redirect (inbox#1152).
//!
//! A box owns its session home and its workbench (the session's two trees),
//! so code it runs can turn any path in them into a symbolic link at any
//! moment, including between a check of the path and the mount that uses it.
//! A bind made by path resolves the path again when the mount runs, so a
//! check before it (minimal#3031 refuses a link already in place) narrows the
//! window and cannot close it. hakoniwa binds by path, before `pivot_root`,
//! with both the source and the mount point resolved in the daemon's view:
//! a source in a tree can be sent out of it, and a mount point under a tree
//! walks the box's names, so hakoniwa's `mkdir_p`/`touch` of a missing one
//! follows a box-made link and the mount lands wherever that link points.
//!
//! So no mapping whose source or mount point lies in a tree is handed to
//! hakoniwa by that path. [`plan`] sorts them out; the box's pre-exec closure
//! makes them with [`bind_all`], after the root is pivoted and while the box
//! still holds its user namespace's root, with the trees already mounted:
//!
//! 1. Every source is opened first, before any of these binds is made. A
//!    source in a tree is opened once, `O_PATH`, with `openat2(2)` beneath the
//!    tree's mount, `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`: a link that
//!    stays in the tree is followed, as it was before; `..` or a link out of
//!    the tree, and every absolute link, is refused (`EXDEV`), as is a `/proc`
//!    magic link (`ELOOP`). A source outside the trees (a host path whose
//!    mount point is under `/home`) is not the box's: hakoniwa binds it by
//!    path, as before, but onto a stage, [`STAGE`]`/<n>` on a tmpfs of the
//!    box's own that nothing of the box's reaches before it runs, and the
//!    closure opens the stage.
//! 2. Then, in target order, each mount point is resolved beneath its tree
//!    the same way (made first, beneath the tree, when it is missing), and
//!    the source lands on it without another name being looked up: a tree
//!    source's tree is cloned from its handle (`open_tree(2)`), attached to
//!    the mount point's handle (`move_mount(2)`) and remounted read-only
//!    through `/proc/self/fd`; a staged source is moved off its stage onto
//!    the mount point's handle (`move_mount(2)`), keeping the flags hakoniwa
//!    gave it. The emptied stage is then unmounted.
//!
//! Opening every source before the first bind keeps hakoniwa's layering: a
//! `~/a/b` patch is the session home's `a/b`, laid on top of a mapping that
//! lands at `/home/a`, never that mapping's own `b`. Mount points are
//! resolved without `RESOLVE_NO_XDEV` on purpose, so the `~/a/b` mount point
//! is the one in the `/home/a` mapping, as hakoniwa's sorted mounts put it.
//!
//! The handles are opened in the child because hakoniwa closes every
//! descriptor above stderr before it builds the namespaces; one the daemon
//! opened would be gone by the time the mount runs. The kernel calls are in
//! the supported floor (Linux 5.10): `openat2` is 5.6, `open_tree` and
//! `move_mount` are 5.2.
//!
//! [`create_beneath`] is the daemon-side twin for a read-write patch whose
//! path does not exist yet: it creates the missing directories and file one
//! component at a time beneath the tree, where `create_dir_all` and
//! `fs::write` would follow a link out of it.

use std::ffi::{CStr, CString, OsStr};
use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

/// Where hakoniwa binds a mapping from outside the trees whose mount point
/// is in one: a tmpfs of the box's own at the root, mounted only when there
/// is such a mapping. The closure moves each mount off it and unmounts it;
/// the box then sees an empty directory of this name in its read-only root.
pub(crate) const STAGE: &str = "/.minimal-patch";
/// [`STAGE`], for `umount2(2)`.
const STAGE_C: &CStr = c"/.minimal-patch";

/// `open_tree(2)` flag: clone the tree rather than open it in place.
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// `move_mount(2)` flag: the source is the descriptor itself.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x04;
/// `move_mount(2)` flag: the target is the descriptor itself.
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;

/// How a patch path is resolved beneath its tree: never outside it (no `..`
/// or link out of it, no absolute link) and never through a `/proc` magic
/// link. A relative link that stays in the tree is followed, as ARCH asks in
/// inbox#1152: #3031's "no links at all" is a rule about what a patch may
/// name, refused up front with its own message, and this layer is the
/// boundary that holds whatever the box does after that check.
const RESOLVE_IN_TREE: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;

/// How many times a resolve the kernel aborted with `EAGAIN` (a rename raced
/// a `..` walk under `RESOLVE_BENEATH`) is retried before it fails.
const RESOLVE_RETRIES: usize = 16;

/// `struct open_how` (`linux/openat2.h`). libc's own is `non_exhaustive`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// One of a session's two trees, which the box owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tree {
    /// The tree's host path, as the daemon sees it.
    pub(crate) host: PathBuf,
    /// Where the box sees it: `/home`, or `/workbench` (unless renamed).
    pub(crate) mount: String,
    /// `home` or `workbench`, for a failure.
    pub(crate) name: &'static str,
}

impl Tree {
    /// The home and the working directory of a session layout, mounted at
    /// `/{SESSION_HOME}` and at `/{wd_name}`.
    pub(crate) fn session(home: &Path, working: &Path, wd_name: &str) -> Vec<Self> {
        vec![
            Self {
                host: home.to_path_buf(),
                mount: format!("/{}", crate::SESSION_HOME),
                name: "home",
            },
            Self {
                host: working.to_path_buf(),
                mount: format!("/{wd_name}"),
                name: "workbench",
            },
        ]
    }
}

/// Where a closure bind's source comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    /// A path in a tree, resolved beneath the tree's `mount` into a handle.
    Tree {
        mount: String,
        name: &'static str,
        rel: PathBuf,
    },
    /// A host path outside the trees, bound by hakoniwa at `stage`.
    Staged { stage: String },
}

/// One patch the box's pre-exec closure binds: its mount point is in a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionBind {
    pub(crate) source: Source,
    /// The mount of the tree the mount point is in.
    pub(crate) mount: String,
    /// That tree's name, for a failure.
    pub(crate) name: &'static str,
    /// The mount point relative to the tree; empty for the tree itself.
    pub(crate) rel: PathBuf,
    /// The mount point in the sandbox, for a failure.
    pub(crate) target: String,
    pub(crate) read_only: bool,
    /// A file is bound alone; a directory with everything mounted below it.
    pub(crate) is_file: bool,
    /// For a tree source, the flags the kernel may have locked on the mount
    /// its host path is on, read by the daemon (as every bind the sandbox
    /// makes reads them): a bind remount in a user namespace that leaves one
    /// out is refused. A staged source keeps the flags hakoniwa gave it.
    pub(crate) locked: libc::c_ulong,
}

/// Every mapping of a sandbox, split between hakoniwa and the closure.
#[derive(Debug)]
pub(crate) struct Plan<'a> {
    /// What hakoniwa binds by path: each mapping with where it lands, which
    /// is the stage for a staged source.
    pub(crate) by_path: Vec<(&'a common::FsMapping, String)>,
    /// What the closure binds, sorted by mount point.
    pub(crate) binds: Vec<SessionBind>,
}

impl Plan<'_> {
    /// Whether the plan stages a source, and so needs the [`STAGE`] tmpfs.
    pub(crate) fn stages(&self) -> bool {
        any_staged(&self.binds)
    }
}

fn any_staged(binds: &[SessionBind]) -> bool {
    binds
        .iter()
        .any(|b| matches!(b.source, Source::Staged { .. }))
}

/// Splits `mappings` between hakoniwa and the closure. A mapping whose mount
/// point is in one of `trees` is the closure's, whatever its source; any
/// other is hakoniwa's, as before. `locked_of_host` reads the locked flags of a
/// host path. A mapping from a tree whose mount point is outside both is
/// refused with its host path: its mount point is in the root the closure
/// cannot write, and a bind by path would read the box's names (no session
/// layout makes one; `mctx`'s `session_mapping` keeps a tree path in its
/// tree).
pub(crate) fn plan<'a>(
    trees: &[Tree],
    mappings: &'a [common::FsMapping],
    locked_of_host: impl Fn(&Path) -> libc::c_ulong,
) -> Result<Plan<'a>, PathBuf> {
    let mut by_path = Vec::new();
    let mut binds = Vec::new();
    let mut stages = 0usize;
    for m in mappings {
        let host = Path::new(&m.host_path);
        let target = m.path_in_sandbox();
        let from = in_tree(trees, host);
        let Some((tree, rel)) = target_in_tree(trees, &target) else {
            if from.is_some() {
                return Err(host.to_path_buf());
            }
            by_path.push((m, target));
            continue;
        };
        let (source, locked) = match from {
            Some((src, src_rel)) => (
                Source::Tree {
                    mount: src.mount.clone(),
                    name: src.name,
                    rel: src_rel,
                },
                locked_of_host(host),
            ),
            None => {
                let stage = format!("{STAGE}/{stages}");
                stages += 1;
                by_path.push((m, stage.clone()));
                (Source::Staged { stage }, 0)
            }
        };
        binds.push(SessionBind {
            source,
            mount: tree.mount.clone(),
            name: tree.name,
            rel,
            target,
            read_only: m.read_only,
            is_file: m.is_file,
            locked,
        });
    }
    // hakoniwa's own order: sorted by mount point, so a patch nested in
    // another lands on top of it. The sort is stable, so of two mappings
    // onto one mount point the later is on top, as hakoniwa's later entry
    // replaced the earlier.
    binds.sort_by(|a, b| a.target.cmp(&b.target));
    Ok(Plan { by_path, binds })
}

/// The tree `host` is in, with its path relative to the tree: the more
/// specific tree when one is nested in the other, as `mctx` retargets it.
fn in_tree<'t>(trees: &'t [Tree], host: &Path) -> Option<(&'t Tree, PathBuf)> {
    trees
        .iter()
        .filter_map(|t| {
            let rel = host.strip_prefix(&t.host).ok()?;
            Some((t, rel.to_path_buf()))
        })
        .max_by_key(|(t, _)| t.host.as_os_str().len())
}

/// The tree the sandbox path `target` lands in, with its path relative to
/// the tree's mount. The two mounts never nest.
fn target_in_tree<'t>(trees: &'t [Tree], target: &str) -> Option<(&'t Tree, PathBuf)> {
    trees.iter().find_map(|t| {
        let rel = Path::new(target).strip_prefix(&t.mount).ok()?;
        Some((t, rel.to_path_buf()))
    })
}

/// The host directory of `roots` that `host` is in, with its path relative
/// to it: the longest, when one is nested in the other.
pub(crate) fn within<'p>(roots: &[&'p Path], host: &Path) -> Option<(&'p Path, PathBuf)> {
    roots
        .iter()
        .filter_map(|r| Some((*r, host.strip_prefix(r).ok()?.to_path_buf())))
        .max_by_key(|(r, _)| r.as_os_str().len())
}

impl SessionBind {
    /// What the closure was doing when this bind failed with `err` in the
    /// tree `tree`, for `exit_child`'s `<what> failed: <err>` line: a path
    /// that leads out of the tree and a link loop are named as such.
    pub(crate) fn failure(&self, tree: &str, err: &io::Error) -> String {
        let target = &self.target;
        match err.raw_os_error() {
            Some(libc::EXDEV) => format!(
                "binding the patch at `{target}` (its path leads outside the session's {tree}, \
                 through `..` or a symbolic link, and a patch is never mounted from outside it)"
            ),
            Some(libc::ELOOP) => format!(
                "binding the patch at `{target}` (a symbolic link on its path in the session's \
                 {tree} loops, or is a /proc magic link)"
            ),
            _ => format!("binding the patch at `{target}`"),
        }
    }
}

/// Binds every patch in `binds` (sorted by mount point, as [`plan`] leaves
/// them) from the trees and stages the box sees. Runs in the box's pre-exec
/// closure; the first failure is returned with what was being done, and the
/// box must not run.
///
/// Each tree's mount is opened afresh for each step: it is the rootfs's own
/// mount point, not a name the box can change, and a fresh open sees a patch
/// of the tree itself that an earlier bind laid over it.
pub(crate) fn bind_all(binds: &[SessionBind]) -> Result<(), (String, io::Error)> {
    if binds.is_empty() {
        return Ok(());
    }
    // Step 1: every source, before any bind below changes what a name in a
    // tree reaches.
    let mut sources = Vec::with_capacity(binds.len());
    for bind in binds {
        let source = match &bind.source {
            Source::Tree { mount, name, rel } => {
                let root = open_dir(Path::new(mount));
                let root = root.map_err(|e| (format!("opening `{mount}`"), e))?;
                resolve(root.as_fd(), rel).map_err(|e| (bind.failure(name, &e), e))?
            }
            Source::Staged { stage } => match open_path(Path::new(stage), !bind.is_file) {
                Ok(fd) => fd,
                Err(e) => return Err((format!("opening the stage of `{}`", bind.target), e)),
            },
        };
        sources.push(source);
    }
    // Step 2: each mount point, in order, and the source onto it.
    for (bind, source) in binds.iter().zip(&sources) {
        let mount = &bind.mount;
        let root = open_dir(Path::new(mount)).map_err(|e| (format!("opening `{mount}`"), e))?;
        let failed = |e: io::Error| (bind.failure(bind.name, &e), e);
        let target = resolve_or_create(root.as_fd(), &bind.rel, bind.is_file).map_err(failed)?;
        let bound = match bind.source {
            Source::Tree { .. } => bind_clone(
                source.as_fd(),
                target.as_fd(),
                bind.read_only,
                !bind.is_file,
                bind.locked,
            ),
            Source::Staged { .. } => move_onto(source.as_fd(), target.as_fd()),
        };
        bound.map_err(failed)?;
    }
    if any_staged(binds) {
        drop(sources);
        unmount_stage();
    }
    Ok(())
}

/// Resolves `rel` beneath the directory `root` into an `O_PATH` handle: a
/// link that stays beneath `root` is followed, any path that leaves it is
/// refused (`EXDEV`). An empty `rel` is `root` itself.
pub(crate) fn resolve(root: BorrowedFd<'_>, rel: &Path) -> io::Result<OwnedFd> {
    let rel = if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    };
    openat2(root, rel, libc::O_PATH, RESOLVE_IN_TREE)
}

/// [`resolve`], making the path beneath `root` first when it is missing: a
/// mount point hakoniwa used to make with `mkdir_p` or `touch` by path.
fn resolve_or_create(root: BorrowedFd<'_>, rel: &Path, is_file: bool) -> io::Result<OwnedFd> {
    match resolve(root, rel) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            create_beneath_at(root, rel, is_file, b"")?;
            resolve(root, rel)
        }
        other => other,
    }
}

/// Binds a clone of the tree `source` holds onto the object `target` holds,
/// read-only when asked, and always `nosuid` as every bind the sandbox makes
/// is, restating `locked`. Nothing here looks up a name: the tree is cloned
/// from the handle, attached to the other handle, and remounted through the
/// clone's own descriptor.
pub(crate) fn bind_clone(
    source: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    read_only: bool,
    recursive: bool,
    locked: libc::c_ulong,
) -> io::Result<()> {
    let mut flags = OPEN_TREE_CLONE | cloexec() | at_flag(libc::AT_EMPTY_PATH);
    if recursive {
        flags |= at_flag(libc::AT_RECURSIVE);
    }
    // SAFETY: `open_tree(2)` with a live descriptor, a NUL-terminated empty
    // path (`AT_EMPTY_PATH` names the descriptor itself) and plain flags.
    let tree =
        unsafe { libc::syscall(libc::SYS_open_tree, source.as_raw_fd(), c"".as_ptr(), flags) };
    let tree = owned_fd(tree)?;
    move_onto(tree.as_fd(), target)?;
    let mut ms = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | locked;
    if read_only {
        ms |= libc::MS_RDONLY;
    }
    let path = CString::new(format!("/proc/self/fd/{}", tree.as_raw_fd()))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `mount(2)` with a NUL-terminated target and null source, type
    // and data, which a bind remount ignores.
    let remounted = unsafe {
        libc::mount(
            std::ptr::null(),
            path.as_ptr(),
            std::ptr::null(),
            ms,
            std::ptr::null(),
        )
    };
    if remounted == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Moves the mount `mount` holds (a clone, or a staged bind) onto the object
/// `target` holds, both named by their descriptors.
fn move_onto(mount: BorrowedFd<'_>, target: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: `move_mount(2)` with two live descriptors and NUL-terminated
    // empty paths; both `*_EMPTY_PATH` flags make the descriptors the source
    // and the target.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if moved == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Unmounts the emptied [`STAGE`] tmpfs. Best-effort: an empty tmpfs left
/// behind holds nothing, and the root it sits in is read-only, so its
/// directory stays either way.
fn unmount_stage() {
    // SAFETY: `umount2(2)` with a NUL-terminated path and a plain flag.
    unsafe {
        libc::umount2(STAGE_C.as_ptr(), libc::MNT_DETACH);
    }
}

/// The locked flags of the mount `path` is on, as `MS_*` bits: read-only,
/// `nosuid`, `nodev`, `noexec`. Restating one already set changes nothing;
/// a path whose mount cannot be read gives none, and the bind's own remount
/// then says whether one was needed.
pub(crate) fn locked_of(path: &Path) -> libc::c_ulong {
    use nix::sys::statvfs::FsFlags;

    let Ok(stat) = nix::sys::statfs::statfs(path) else {
        return 0;
    };
    let flags = stat.flags();
    let mut ms = 0;
    if flags.contains(FsFlags::ST_RDONLY) {
        ms |= libc::MS_RDONLY;
    }
    if flags.contains(FsFlags::ST_NOSUID) {
        ms |= libc::MS_NOSUID;
    }
    if flags.contains(FsFlags::ST_NODEV) {
        ms |= libc::MS_NODEV;
    }
    if flags.contains(FsFlags::ST_NOEXEC) {
        ms |= libc::MS_NOEXEC;
    }
    ms
}

/// Creates the patch path `rel` beneath the tree at `root` when it does not
/// exist yet: a read-write patch's missing directories and its file or
/// directory, one component at a time, never out of the tree. A file is
/// created holding `contents`; one that appears meanwhile is left as it is.
/// `rel` must be plain names: a `..` is refused.
pub(crate) fn create_beneath(
    root: &Path,
    rel: &Path,
    is_file: bool,
    contents: &[u8],
) -> io::Result<()> {
    let dir = open_dir(root)?;
    create_beneath_at(dir.as_fd(), rel, is_file, contents)
}

/// [`create_beneath`] from a directory already open.
fn create_beneath_at(
    root: BorrowedFd<'_>,
    rel: &Path,
    is_file: bool,
    contents: &[u8],
) -> io::Result<()> {
    let mut names = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => names.push(name),
            Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a patch path in the session must name plain components, without `..`",
                ));
            }
        }
    }
    let Some((last, parents)) = names.split_last() else {
        // The tree itself, which exists.
        return Ok(());
    };
    let mut dir: Option<OwnedFd> = None;
    for name in parents {
        let next = open_or_make_dir(dir.as_ref().map_or(root, AsFd::as_fd), name)?;
        dir = Some(next);
    }
    let at = dir.as_ref().map_or(root, AsFd::as_fd);
    if !is_file {
        return open_or_make_dir(at, last).map(drop);
    }
    let name = c_name(last)?;
    // SAFETY: `openat(2)` with a live directory descriptor, a NUL-terminated
    // name and a mode for `O_CREAT`; `O_EXCL | O_NOFOLLOW` never opens or
    // creates through a link.
    let fd = unsafe {
        libc::openat(
            at.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o666 as libc::c_uint,
        )
    };
    match owned_fd(libc::c_long::from(fd)) {
        Ok(fd) => std::fs::File::from(fd).write_all(contents),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Opens the directory `name` in `dir` beneath it, making it first when it
/// is missing. A directory made meanwhile by someone else is opened all the
/// same; a link out of the tree in its place is refused.
fn open_or_make_dir(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<OwnedFd> {
    let path = Path::new(name);
    match openat2(dir, path, libc::O_PATH | libc::O_DIRECTORY, RESOLVE_IN_TREE) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let c = c_name(name)?;
            // SAFETY: `mkdirat(2)` with a live directory descriptor and a
            // NUL-terminated name; it never follows a link.
            if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o777) } == -1 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
            openat2(dir, path, libc::O_PATH | libc::O_DIRECTORY, RESOLVE_IN_TREE)
        }
        other => other,
    }
}

/// Opens `path`, a directory the daemon or the rootfs owns (not a name in a
/// tree), as an `O_PATH` handle to resolve beneath.
fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    open_path(path, true)
}

/// Opens `path`, a name the box cannot change (a tree's mount, a stage), as
/// an `O_PATH` handle; `dir` asks for a directory.
fn open_path(path: &Path, dir: bool) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if dir {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: `open(2)` with a NUL-terminated path and plain flags.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    owned_fd(libc::c_long::from(fd))
}

/// `openat2(2)` of `path` in `dir` with `flags` (plus `O_CLOEXEC`) and
/// `resolve`, retrying the kernel's `EAGAIN` for a raced `..` a few times.
fn openat2(
    dir: BorrowedFd<'_>,
    path: &Path,
    flags: libc::c_int,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: u64::from((flags | libc::O_CLOEXEC).cast_unsigned()),
        mode: 0,
        resolve,
    };
    let mut tries = 0;
    loop {
        // SAFETY: `openat2(2)` with a live directory descriptor, a
        // NUL-terminated path, and a `struct open_how` that outlives the
        // call, passed with its size.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
                c.as_ptr(),
                &raw const how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        match owned_fd(fd) {
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && tries < RESOLVE_RETRIES => {
                tries += 1;
            }
            result => return result,
        }
    }
}

/// The descriptor a syscall returned, or its errno.
fn owned_fd(ret: libc::c_long) -> io::Result<OwnedFd> {
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(ret).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: the kernel just returned `fd` as a new descriptor this process
    // owns and nothing else holds.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn cloexec() -> libc::c_uint {
    libc::O_CLOEXEC.cast_unsigned()
}

fn at_flag(flag: libc::c_int) -> libc::c_uint {
    flag.cast_unsigned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    /// The `(dev, ino)` of what `fd` holds.
    fn identity(fd: &OwnedFd) -> (u64, u64) {
        let meta = std::fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        (meta.dev(), meta.ino())
    }

    fn identity_of(path: &Path) -> (u64, u64) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    /// A home holding `x/` (token IN), beside an `outside/` (token OUT) the
    /// box must never reach.
    fn home_and_outside() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(home.join("x")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(home.join("x/token"), "IN").unwrap();
        std::fs::write(outside.join("token"), "OUT").unwrap();
        (root, home, outside)
    }

    #[test]
    fn a_plain_patch_path_resolves_to_its_own_object() {
        let (_root, home, _outside) = home_and_outside();
        let home_fd = open_dir(&home).unwrap();
        let handle = resolve(home_fd.as_fd(), Path::new("x")).unwrap();
        assert_eq!(identity(&handle), identity_of(&home.join("x")));
        let whole = resolve(home_fd.as_fd(), Path::new("")).unwrap();
        assert_eq!(
            identity(&whole),
            identity_of(&home),
            "an empty path is the home"
        );
    }

    /// The race itself (inbox#1152): the box swaps the patch path for a link
    /// out of the home after the resolve and before the bind. The handle
    /// still holds the directory that was there, so the bind made from it
    /// cannot reach the link's target.
    #[test]
    fn a_swap_after_the_resolve_does_not_change_the_handle() {
        let (_root, home, outside) = home_and_outside();
        let home_fd = open_dir(&home).unwrap();
        let original = identity_of(&home.join("x"));
        let handle = resolve(home_fd.as_fd(), Path::new("x")).unwrap();

        std::fs::rename(home.join("x"), home.join("d")).unwrap();
        std::os::unix::fs::symlink(&outside, home.join("x")).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("x/token")).unwrap(),
            "OUT",
            "by name, the patch path now leads out of the home"
        );

        assert_eq!(
            identity(&handle),
            original,
            "the handle holds what was resolved"
        );
        assert_ne!(identity(&handle), identity_of(&outside));
        let token = std::fs::read_to_string(format!("/proc/self/fd/{}/token", handle.as_raw_fd()));
        assert_eq!(
            token.unwrap(),
            "IN",
            "through the handle, the original directory"
        );

        let again = resolve(home_fd.as_fd(), Path::new("x")).unwrap_err();
        assert_eq!(
            again.raw_os_error(),
            Some(libc::EXDEV),
            "a fresh resolve refuses the link out of the home"
        );
    }

    /// The whole bind, in a user and mount namespace of its own as the box's
    /// closure runs it: the box swaps the patch path for a link out of the
    /// home between the resolve and the bind. The patch still lands on the
    /// directory that was resolved, read-only, and nothing is mounted over
    /// the link's target. A bind by path at that moment would have followed
    /// the link to `outside`.
    #[test]
    fn a_swap_between_the_resolve_and_the_bind_cannot_change_what_is_mounted() {
        let (root, _home, _outside) = home_and_outside();
        let mut container = hakoniwa::Container::new();
        container.rootfs("/").unwrap();
        container.bindmount_rw(root.path().to_str().unwrap(), "/t");
        // SAFETY: the closure runs in the forked child, which is
        // single-threaded; it makes plain filesystem calls and returns a code.
        let mut command = unsafe {
            container.command_from_closure(|| {
                let Ok(home) = open_dir(Path::new("/t/home")) else {
                    return 10;
                };
                let Ok(handle) = resolve(home.as_fd(), Path::new("x")) else {
                    return 11;
                };
                // The box's swap, after the resolve.
                if std::fs::rename("/t/home/x", "/t/home/d").is_err()
                    || std::os::unix::fs::symlink("/t/outside", "/t/home/x").is_err()
                {
                    return 12;
                }
                let locked = locked_of(Path::new("/t/home"));
                if bind_clone(handle.as_fd(), handle.as_fd(), true, true, locked).is_err() {
                    return 13;
                }
                if std::fs::read_to_string("/t/home/d/token").ok().as_deref() != Some("IN") {
                    return 14;
                }
                match std::fs::write("/t/home/d/probe", "w") {
                    Err(e) if e.raw_os_error() == Some(libc::EROFS) => {}
                    _ => return 15,
                }
                if std::fs::write("/t/outside/probe", "w").is_err() {
                    return 16;
                }
                if std::fs::read_to_string("/t/home/x/token").ok().as_deref() != Some("OUT") {
                    return 17;
                }
                0
            })
        };
        let status = command.status().unwrap();
        assert!(
            status.success(),
            "10 open, 11 resolve, 12 swap, 13 bind, 14 not the resolved directory, \
             15 not read-only, 16 the link's target was covered, 17 the link moved: {status:?}"
        );
    }

    /// [`bind_all`] in a namespace, with the layering hakoniwa's sorted
    /// mounts gave: a staged mapping from outside the home lands at
    /// `/home/a`, and a `~/a/b` patch lands on top of it with the session
    /// home's own `a/b`, not the staged mapping's `b`. Sources are opened
    /// before the first bind; mount points are resolved in order, across the
    /// staged mount.
    #[test]
    fn bind_all_lays_a_home_patch_over_a_staged_mapping_as_hakoniwa_did() {
        let root = tempfile::tempdir().unwrap();
        let t = root.path();
        std::fs::create_dir_all(t.join("home/a/b")).unwrap();
        std::fs::write(t.join("home/a/b/only-home"), "H").unwrap();
        std::fs::create_dir_all(t.join("outside/b")).unwrap();
        std::fs::write(t.join("outside/only-outside"), "O").unwrap();
        std::fs::write(t.join("outside/b/only-outside-b"), "OB").unwrap();
        std::fs::create_dir_all(t.join("stage/0")).unwrap();
        let binds = vec![
            SessionBind {
                source: Source::Staged {
                    stage: "/t/stage/0".into(),
                },
                mount: "/t/home".into(),
                name: "home",
                rel: "a".into(),
                target: "/home/a".into(),
                read_only: true,
                is_file: false,
                locked: 0,
            },
            SessionBind {
                source: Source::Tree {
                    mount: "/t/home".into(),
                    name: "home",
                    rel: "a/b".into(),
                },
                mount: "/t/home".into(),
                name: "home",
                rel: "a/b".into(),
                target: "/home/a/b".into(),
                read_only: true,
                is_file: false,
                locked: locked_of(&t.join("home")),
            },
        ];
        let mut container = hakoniwa::Container::new();
        container.rootfs("/").unwrap();
        container.bindmount_rw(t.to_str().unwrap(), "/t");
        // SAFETY: the closure runs in the forked child, which is
        // single-threaded; it makes plain filesystem and mount calls and
        // returns a code.
        let mut command = unsafe {
            container.command_from_closure(move || {
                // hakoniwa's part: the mapping from outside, bound by path
                // onto its stage (`mount(2)` with NUL-terminated paths and
                // null type and data, which a bind ignores).
                let staged = libc::mount(
                    c"/t/outside".as_ptr(),
                    c"/t/stage/0".as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                );
                if staged == -1 {
                    return 10;
                }
                if bind_all(&binds).is_err() {
                    return 11;
                }
                if !Path::new("/t/home/a/only-outside").exists() {
                    return 12;
                }
                if !Path::new("/t/home/a/b/only-home").exists()
                    || Path::new("/t/home/a/b/only-outside-b").exists()
                {
                    return 13;
                }
                if Path::new("/t/stage/0/only-outside").exists() {
                    return 14;
                }
                0
            })
        };
        let status = command.status().unwrap();
        assert!(
            status.success(),
            "10 stage, 11 bind_all, 12 the staged mapping is not at /home/a, 13 the home's a/b \
             is not on top, 14 the stage still holds the mapping: {status:?}"
        );
    }

    #[test]
    fn a_link_out_of_the_home_is_refused_and_one_inside_it_followed() {
        let (_root, home, outside) = home_and_outside();
        std::os::unix::fs::symlink(&outside, home.join("abs")).unwrap();
        std::os::unix::fs::symlink(home.join("x"), home.join("abs-in")).unwrap();
        std::os::unix::fs::symlink("x", home.join("inside")).unwrap();
        std::os::unix::fs::symlink("../outside", home.join("rel")).unwrap();
        let home_fd = open_dir(&home).unwrap();
        for link in ["abs", "abs-in", "rel", "rel/token"] {
            let err = resolve(home_fd.as_fd(), Path::new(link)).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{link}");
        }
        let inside = resolve(home_fd.as_fd(), Path::new("inside")).unwrap();
        assert_eq!(
            identity(&inside),
            identity_of(&home.join("x")),
            "a relative link that stays in the home is followed"
        );
    }

    #[test]
    fn a_path_out_of_the_home_is_refused() {
        let (_root, home, _outside) = home_and_outside();
        let home_fd = open_dir(&home).unwrap();
        for path in ["../outside", "x/../../outside"] {
            let err = resolve(home_fd.as_fd(), Path::new(path)).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{path}");
        }
        let inside = resolve(home_fd.as_fd(), Path::new("x/../x")).unwrap();
        assert_eq!(
            identity(&inside),
            identity_of(&home.join("x")),
            "`..` inside stays in"
        );
    }

    #[test]
    fn the_failure_names_the_patch_and_the_reason() {
        let bind = SessionBind {
            source: Source::Tree {
                mount: "/home".into(),
                name: "home",
                rel: "x811".into(),
            },
            mount: "/home".into(),
            name: "home",
            rel: "x811".into(),
            target: "/home/x811".into(),
            read_only: true,
            is_file: false,
            locked: 0,
        };
        let escaped = bind.failure("home", &io::Error::from_raw_os_error(libc::EXDEV));
        assert!(
            escaped.contains("`/home/x811`")
                && escaped.contains("outside the session's home")
                && escaped.contains("symbolic link"),
            "{escaped}"
        );
        let looped = bind.failure("workbench", &io::Error::from_raw_os_error(libc::ELOOP));
        assert!(
            looped.contains("symbolic link") && looped.contains("session's workbench"),
            "{looped}"
        );
        assert_eq!(
            bind.failure("home", &io::Error::from_raw_os_error(libc::ENOENT)),
            "binding the patch at `/home/x811`"
        );
    }

    fn mapping(host: &str, sandbox: Option<&str>, is_file: bool) -> common::FsMapping {
        common::FsMapping {
            host_path: host.to_string(),
            sandbox_path: sandbox.map(str::to_string),
            read_only: true,
            is_file,
            create_if_missing: false,
        }
    }

    fn trees() -> Vec<Tree> {
        Tree::session(
            Path::new("/s/home"),
            Path::new("/s/home/proj"),
            "workbench",
        )
    }

    /// Which mappings hakoniwa still binds by path, and which the closure
    /// binds: every mount point in a tree is the closure's, from a tree
    /// source or from a stage; nothing whose source or mount point is in a
    /// tree reaches hakoniwa by that path.
    #[test]
    fn the_plan_keeps_every_tree_path_away_from_hakoniwa() {
        let mappings = vec![
            mapping("/s/home/a/b", Some("/home/a/b"), false),
            mapping("/srv/data", Some("/home/a"), false),
            mapping("/s/home/proj/w", Some("/workbench/w"), false),
            mapping("/s/home/.c.json", Some("/home/.c.json"), true),
            mapping("/etc/app.conf", Some("/etc/app.conf"), true),
            mapping("/opt/homeX", Some("/homeX"), false),
        ];
        let plan = plan(&trees(), &mappings, |_| libc::MS_NODEV).unwrap();
        let by_path: Vec<(&str, &str)> = plan
            .by_path
            .iter()
            .map(|(m, t)| (m.host_path.as_str(), t.as_str()))
            .collect();
        assert_eq!(
            by_path,
            vec![
                ("/srv/data", "/.minimal-patch/0"),
                ("/etc/app.conf", "/etc/app.conf"),
                ("/opt/homeX", "/homeX"),
            ],
            "hakoniwa binds the mapping from outside onto its stage, and the rest outside \
             the trees where they land"
        );
        let targets: Vec<&str> = plan.binds.iter().map(|b| b.target.as_str()).collect();
        assert_eq!(
            targets,
            vec!["/home/.c.json", "/home/a", "/home/a/b", "/workbench/w"],
            "sorted by mount point, so a nested patch lands on top"
        );
        assert!(plan.stages());
        assert_eq!(
            plan.binds[1].source,
            Source::Staged {
                stage: "/.minimal-patch/0".into(),
            }
        );
        assert_eq!(
            plan.binds[1].locked,
            0,
            "a staged mapping keeps hakoniwa's flags"
        );
        assert_eq!(
            plan.binds[2].source,
            Source::Tree {
                mount: "/home".into(),
                name: "home",
                rel: "a/b".into(),
            }
        );
        assert_eq!(
            plan.binds[2].locked,
            libc::MS_NODEV,
            "a tree source's locked flags are read from its own host path"
        );
        assert_eq!(
            plan.binds[3].source,
            Source::Tree {
                mount: "/workbench".into(),
                name: "workbench",
                rel: "w".into(),
            },
            "the more specific tree holds a path in a workbench nested in the home"
        );
        assert!(plan.binds[0].is_file && !plan.binds[2].is_file);
    }

    #[test]
    fn the_plan_refuses_a_tree_path_that_lands_outside_the_trees() {
        let mappings = vec![mapping("/s/home/x", Some("/opt/x"), false)];
        assert_eq!(
            plan(&trees(), &mappings, |_| 0).unwrap_err(),
            PathBuf::from("/s/home/x")
        );
    }

    #[test]
    fn create_beneath_makes_the_missing_path_in_the_home() {
        let (_root, home, _outside) = home_and_outside();
        create_beneath(&home, Path::new("a/b/c"), false, b"").unwrap();
        assert!(home.join("a/b/c").is_dir());
        create_beneath(&home, Path::new("cfg/app.json"), true, b"{}").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("cfg/app.json")).unwrap(),
            "{}"
        );
        create_beneath(&home, Path::new("cfg/app.json"), true, b"[]").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("cfg/app.json")).unwrap(),
            "{}",
            "a file already there is left as it is"
        );
        std::os::unix::fs::symlink("a", home.join("in")).unwrap();
        create_beneath(&home, Path::new("in/made"), false, b"").unwrap();
        assert!(
            home.join("a/made").is_dir(),
            "a link that stays in the home is followed"
        );
    }

    #[test]
    fn create_beneath_never_creates_out_of_the_home() {
        let (_root, home, outside) = home_and_outside();
        std::os::unix::fs::symlink(&outside, home.join("l")).unwrap();
        std::os::unix::fs::symlink("../outside", home.join("r")).unwrap();
        std::os::unix::fs::symlink(outside.join("made.json"), home.join("dangling.json")).unwrap();

        for path in ["l/new", "r/new"] {
            let err = create_beneath(&home, Path::new(path), false, b"").unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{path}");
        }
        create_beneath(&home, Path::new("dangling.json"), true, b"{}").unwrap();
        assert!(
            !outside.join("new").exists() && !outside.join("made.json").exists(),
            "nothing was created outside the home"
        );
        let err = create_beneath(&home, Path::new("x/../../outside/up"), false, b"").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("up").exists());
    }
}
