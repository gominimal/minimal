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
//!    tree's mount, `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`: a relative link
//!    that stays in the tree is followed wherever it points from (a stow
//!    link `~/.config/nvim -> ../dotfiles/nvim/.config/nvim`
//!    climbs above its own directory and stays in the home); `..` or a link
//!    out of the tree, and every absolute link, is refused (`EXDEV`), as is a
//!    `/proc` magic link (`ELOOP`). A refusal is then walked again by
//!    [`walk`] to say which link or `..` it was and what to do ([`Refused`]).
//!    A source outside the trees (a host path whose mount point is under
//!    `/home`) is not the box's: hakoniwa binds it by path, but
//!    onto a stage, [`STAGE`]`/<n>` on a tmpfs of the box's own that nothing
//!    of the box's reaches before it runs, and the closure opens the stage.
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
//! A path that does not exist yet (a read-write patch the daemon creates
//! with [`create_beneath`], a missing mount point the closure makes) is made
//! by [`walk`]: one name at a time, each looked up without following it in
//! a directory opened beneath the tree's root, a link's target spliced into
//! the rest of the path and a `..` taken back up the walked path, never above
//! the tree's root. So a link that stays in the tree is followed from
//! wherever it is, a dangling one gets its target made in the tree, and
//! nothing is made out of it, where `create_dir_all` and `fs::write` would
//! follow a link anywhere.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
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

/// How many symbolic links one [`walk`] follows before it calls them a loop:
/// the kernel's own limit.
const MAX_LINKS: usize = 40;

/// The longest link target [`read_link`] reads (`PATH_MAX`).
const LINK_MAX: usize = 4096;

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

/// How a person sees one of the trees, for a refusal: `~` for the home, its
/// mount (`/workbench`) for the workbench, and the tree's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeView<'a> {
    pub(crate) shown: &'a str,
    pub(crate) name: &'static str,
}

impl<'a> TreeView<'a> {
    /// The view of the tree named `name` that the box sees at `mount`.
    pub(crate) fn of(mount: &'a str, name: &'static str) -> Self {
        let shown = if name == "home" { "~" } else { mount };
        Self { shown, name }
    }
}

/// Why a patch path was refused beneath its tree: what a [`walk`] of it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Why {
    /// A `..` in the patch path itself climbs above the tree.
    Climbs,
    /// The link at `link` (relative to the tree) points at `to`, which climbs
    /// above the tree.
    LinkClimbs { link: PathBuf, to: PathBuf },
    /// The link at `link` points at the absolute path `to`. Whose root an
    /// absolute link is read from (the daemon's or the box's) decides where
    /// it leads, so none is followed, also one that names a place in the tree.
    Absolute { link: PathBuf, to: PathBuf },
    /// More than [`MAX_LINKS`] links on the path: they loop.
    Loop,
    /// The path goes on, by a name or a `..`, after `at` (relative to the
    /// tree), which is not a directory.
    NotDir { at: PathBuf },
    /// The kernel refused the path with this errno (`EXDEV`, `ELOOP`) and a
    /// walk of it afterwards found nothing to blame: a link the box changed
    /// in between, or a `/proc` magic link.
    Kernel(i32),
}

/// A patch path refused beneath its tree, with what to do about it. Carried
/// in an [`io::Error`] (see [`refusal`]), whose text it is, so a failure
/// shows this sentence and not an errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused {
    /// The tree as the person sees it: `~`, `/workbench`.
    pub(crate) shown: String,
    /// The tree's name.
    pub(crate) tree: &'static str,
    /// The patch path, relative to the tree.
    pub(crate) rel: PathBuf,
    pub(crate) why: Why,
}

impl Refused {
    /// The errno the refusal stands for, for the closure's report: `ELOOP`
    /// for a loop, the kernel's own, or `EXDEV`.
    pub(crate) fn errno(&self) -> i32 {
        match self.why {
            Why::Loop => libc::ELOOP,
            Why::NotDir { .. } => libc::ENOTDIR,
            Why::Kernel(errno) => errno,
            Why::Climbs | Why::LinkClimbs { .. } | Why::Absolute { .. } => libc::EXDEV,
        }
    }

    /// `rel` as the person sees it: `~/.config/nvim`.
    fn show(&self, rel: &Path) -> String {
        if rel.as_os_str().is_empty() {
            self.shown.clone()
        } else {
            format!("{}/{}", self.shown, rel.display())
        }
    }

    /// The link at `link`, named with the patch path it is on when that is
    /// not the link itself.
    fn the_link(&self, link: &Path) -> String {
        if link == self.rel {
            format!("`{}`", self.show(link))
        } else {
            format!(
                "`{}`, on the patch path `{}`,",
                self.show(link),
                self.show(&self.rel)
            )
        }
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tree = self.tree;
        let path = self.show(&self.rel);
        match &self.why {
            Why::Climbs => write!(
                f,
                "The patch path `{path}` climbs out of the session's {tree} through `..`. \
                 Name the patch by a path that stays in the {tree}."
            ),
            Why::LinkClimbs { link, to } => write!(
                f,
                "{} is a symbolic link to `{}`. That link climbs out of the session's {tree}. \
                 A patch is reached only through links that stay in the {tree}. Point that \
                 link at a place in the {tree}, or remove it.",
                self.the_link(link),
                to.display()
            ),
            Why::Absolute { link, to } => write!(
                f,
                "{} is a symbolic link to the absolute path `{}`. A patch path follows only \
                 relative links, also when an absolute one names a place in the {tree}. \
                 Replace it with a relative link that stays in the {tree}, or remove it.",
                self.the_link(link),
                to.display()
            ),
            Why::Loop => write!(
                f,
                "The patch path `{path}` goes through more than {MAX_LINKS} symbolic links, \
                 so they loop. Remove the loop among the links on it."
            ),
            Why::NotDir { at } => write!(
                f,
                "`{}`, on the patch path `{path}`, is not a directory, so the path cannot go \
                 on after it. Name the patch by a path through directories.",
                self.show(at)
            ),
            Why::Kernel(libc::ELOOP) => write!(
                f,
                "The patch path `{path}` goes through a /proc magic link or a loop of \
                 symbolic links, which a patch never follows. Remove that link."
            ),
            Why::Kernel(_) => write!(
                f,
                "The patch path `{path}` leads out of the session's {tree} through `..` or a \
                 symbolic link that is absolute or leaves it. A patch is reached only through \
                 relative links that stay in the {tree}. Replace or remove that link."
            ),
        }
    }
}

impl std::error::Error for Refused {}

/// The [`Refused`] an error carries, if it is one.
pub(crate) fn refusal(e: &io::Error) -> Option<&Refused> {
    e.get_ref()?.downcast_ref()
}

/// The errno of `e`, a refusal's included.
pub(crate) fn errno_of(e: &io::Error) -> Option<i32> {
    if let Some(errno) = e.raw_os_error() {
        return Some(errno);
    }
    refusal(e).map(Refused::errno)
}

/// `why` as the error a refused resolve or walk of `rel` returns.
fn refused(view: TreeView<'_>, rel: &Path, why: Why) -> io::Error {
    io::Error::other(Refused {
        shown: view.shown.to_string(),
        tree: view.name,
        rel: rel.to_path_buf(),
        why,
    })
}

/// Which step of [`bind_all`] a failure is in, for its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Opening the patch's source.
    Source,
    /// Resolving, or making, the place it is mounted at, and the mount.
    MountPoint,
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
/// other is hakoniwa's. `locked_of_host` reads the locked flags of a
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
/// The daemon's create of a mapped path reads the same answer
/// (`Config::session_tree_of`), so the two cannot drift.
pub(crate) fn in_tree<'t>(trees: &'t [Tree], host: &Path) -> Option<(&'t Tree, PathBuf)> {
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

impl SessionBind {
    /// What the closure was doing when this bind failed in `step`, for
    /// `exit_child`'s `<what> failed: <err>` line. A refused path is the
    /// error's own text ([`Refused`]), which says what to do.
    pub(crate) fn failure(&self, step: Step) -> String {
        let target = &self.target;
        match (step, &self.source) {
            (Step::Source, Source::Tree { name, .. }) => {
                format!("reading the patch for `{target}` from the session's {name}")
            }
            (Step::Source, Source::Staged { .. }) => {
                format!("reading the patch for `{target}` from outside the session")
            }
            (Step::MountPoint, Source::Tree { .. }) => format!("placing the patch at `{target}`"),
            (Step::MountPoint, Source::Staged { .. }) => {
                format!("placing the patch from outside the session at `{target}`")
            }
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
                let view = TreeView::of(mount, name);
                let source = resolve(root.as_fd(), view, rel);
                source.map_err(|e| (bind.failure(Step::Source), e))?
            }
            Source::Staged { stage } => {
                let staged = open_path(Path::new(stage), !bind.is_file);
                staged.map_err(|e| (bind.failure(Step::Source), e))?
            }
        };
        sources.push(source);
    }
    // Step 2: each mount point, in order, and the source onto it.
    for (bind, source) in binds.iter().zip(&sources) {
        let mount = &bind.mount;
        let root = open_dir(Path::new(mount)).map_err(|e| (format!("opening `{mount}`"), e))?;
        let failed = |e: io::Error| (bind.failure(Step::MountPoint), e);
        let view = TreeView::of(mount, bind.name);
        let target = resolve_or_create(root.as_fd(), view, &bind.rel, bind.is_file);
        let target = target.map_err(failed)?;
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

/// Resolves `rel` beneath the directory `root`, the tree `view`, into an
/// `O_PATH` handle, in one `openat2(2)`: a relative link that stays beneath
/// `root` is followed from wherever it is, and a path the kernel refuses
/// (`..` above `root`, a link out of it, any absolute link, a magic link) is
/// a [`Refused`] that says which and what to do. An empty `rel` is `root`.
pub(crate) fn resolve(root: BorrowedFd<'_>, view: TreeView<'_>, rel: &Path) -> io::Result<OwnedFd> {
    let path = if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    };
    openat2(root, path, libc::O_PATH, RESOLVE_IN_TREE).map_err(|e| explain(root, view, rel, e))
}

/// The kernel's refusal `e` of `rel` (`EXDEV`, `ELOOP`) as a [`Refused`],
/// with the link or `..` a [`walk`] of the path blames; any other error as
/// it is. The walk only reads: what it finds names the cause, and the
/// kernel's refusal stands whatever it finds.
fn explain(root: BorrowedFd<'_>, view: TreeView<'_>, rel: &Path, e: io::Error) -> io::Error {
    let Some(errno @ (libc::EXDEV | libc::ELOOP)) = e.raw_os_error() else {
        return e;
    };
    match walk(root, view, rel, None) {
        Err(walked) if refusal(&walked).is_some() => walked,
        _ => refused(view, rel, Why::Kernel(errno)),
    }
}

/// [`resolve`], making the path beneath `root` first when it is missing: a
/// mount point hakoniwa used to make with `mkdir_p` or `touch` by path. A
/// missing mount point under a link that stays in the tree, a dangling one
/// included, is made where the link leads, in the tree.
fn resolve_or_create(
    root: BorrowedFd<'_>,
    view: TreeView<'_>,
    rel: &Path,
    is_file: bool,
) -> io::Result<OwnedFd> {
    match resolve(root, view, rel) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let make = Make {
                is_file,
                contents: b"",
            };
            walk(root, view, rel, Some(make))?;
            resolve(root, view, rel)
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

/// Creates the patch path `rel` beneath the tree at `root`, the tree
/// `view`, when it does not exist yet: a read-write patch's missing
/// directories and its file or directory, by a [`walk`] that follows a link
/// staying in the tree from wherever it is (a dangling one gets its target
/// made) and never makes anything out of the tree. A file is created holding
/// `contents`; one that appears meanwhile is left as it is. A path out of the
/// tree is a [`Refused`].
pub(crate) fn create_beneath(
    root: &Path,
    view: TreeView<'_>,
    rel: &Path,
    is_file: bool,
    contents: &[u8],
) -> io::Result<()> {
    let dir = open_dir(root)?;
    walk(dir.as_fd(), view, rel, Some(Make { is_file, contents }))
}

/// What a [`walk`] makes of a name missing on its path: a directory, or the
/// file holding `contents` when it is the last name and `is_file`.
#[derive(Debug, Clone, Copy)]
struct Make<'c> {
    is_file: bool,
    contents: &'c [u8],
}

/// One step of a [`walk`]: a name to look up, or a `..` with the link whose
/// target it is in (an index into the walk's links; `None` for the patch
/// path itself), for a refusal.
enum Part {
    Name(OsString),
    Up(Option<usize>),
}

/// Walks `rel` beneath the directory `root`, the tree `view`, one name at a
/// time, making each missing name when `make` asks for it.
///
/// The walk holds the path it has reached as plain names from `root`. Each
/// name is looked up with `O_NOFOLLOW` in that path's directory, opened
/// afresh beneath `root` (`RESOLVE_BENEATH`); a link found there has its
/// target read and spliced in front of the rest of the path, so a relative
/// link is followed from where it is, whatever it climbs, while it stays in
/// the tree; a `..` takes the last name off the path reached. A `..` with no
/// name left to take is above the tree, an absolute link is refused before
/// it is followed, and a name or `..` after something that is not a
/// directory is refused as the kernel would (`ENOTDIR`): each is a
/// [`Refused`], as is a loop.
///
/// The whole path is walked once without making anything first (see
/// [`walk_pass`]), so a refusal anywhere on it leaves nothing behind; only
/// then is it walked again, making each missing name in the directory
/// reached, with `mkdirat(2)` or an `O_EXCL | O_NOFOLLOW` create, neither of
/// which follows a link. Every directory the walk opens or makes in is one
/// the kernel resolved beneath `root`, so whatever the box swaps in
/// meanwhile, nothing is opened or made out of the tree; a swap between the
/// two passes can at most leave a directory made in the tree before the
/// second pass refuses.
fn walk(
    root: BorrowedFd<'_>,
    view: TreeView<'_>,
    rel: &Path,
    make: Option<Make<'_>>,
) -> io::Result<()> {
    walk_pass(root, view, rel, None)?;
    match make {
        Some(make) => walk_pass(root, view, rel, Some(make)),
        None => Ok(()),
    }
}

/// One pass of a [`walk`]. Without `make` it makes nothing: a missing name
/// and every name after it on the reached path are new, so they are taken
/// as plain names with nothing to look up, until a `..` climbs back above
/// them.
fn walk_pass(
    root: BorrowedFd<'_>,
    view: TreeView<'_>,
    rel: &Path,
    make: Option<Make<'_>>,
) -> io::Result<()> {
    let mut todo = Vec::new();
    push_parts(&mut todo, rel, None)?;
    let mut links: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut reached: Vec<OsString> = Vec::new();
    // How many names at the end of `reached` do not exist (a pass without
    // `make` only), and whether the last one is something other than a
    // directory, which nothing may follow.
    let mut fresh = 0usize;
    let mut not_dir = false;
    while let Some(part) = todo.pop() {
        if not_dir {
            let at = reached.iter().collect();
            return Err(refused(view, rel, Why::NotDir { at }));
        }
        let name = match part {
            Part::Name(name) => name,
            Part::Up(from) => {
                if reached.pop().is_none() {
                    let why = match from {
                        None => Why::Climbs,
                        Some(i) => {
                            let (link, to) = links[i].clone();
                            Why::LinkClimbs { link, to }
                        }
                    };
                    return Err(refused(view, rel, why));
                }
                fresh = fresh.saturating_sub(1);
                continue;
            }
        };
        if fresh > 0 {
            reached.push(name);
            fresh += 1;
            continue;
        }
        let dir = open_reached(root, &reached)?;
        let flags = libc::O_PATH | libc::O_NOFOLLOW;
        match openat2(dir.as_fd(), Path::new(&name), flags, RESOLVE_IN_TREE) {
            Ok(fd) => {
                let found = std::fs::File::from(fd);
                let meta = found.metadata()?;
                if !meta.file_type().is_symlink() {
                    not_dir = !meta.is_dir();
                    reached.push(name);
                    continue;
                }
                if links.len() == MAX_LINKS {
                    return Err(refused(view, rel, Why::Loop));
                }
                let link: PathBuf = reached.iter().chain(std::iter::once(&name)).collect();
                let to = read_link(found.as_fd())?;
                if to.has_root() {
                    return Err(refused(view, rel, Why::Absolute { link, to }));
                }
                push_parts(&mut todo, &to, Some(links.len()))?;
                links.push((link, to));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let Some(make) = make else {
                    reached.push(name);
                    fresh = 1;
                    continue;
                };
                if make.is_file && todo.is_empty() {
                    create_file(dir.as_fd(), &name, make.contents)?;
                } else {
                    make_dir(dir.as_fd(), &name)?;
                }
                reached.push(name);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Pushes the steps of `path` onto `todo`, first step last, each `..` marked
/// with the link `from` it came from. An absolute `path` is refused by the
/// caller first; here it is invalid input.
fn push_parts(todo: &mut Vec<Part>, path: &Path, from: Option<usize>) -> io::Result<()> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push(Part::Name(name.to_os_string())),
            Component::ParentDir => parts.push(Part::Up(from)),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        }
    }
    todo.extend(parts.into_iter().rev());
    Ok(())
}

/// The directory a [`walk`] has reached, `reached` from `root`, opened
/// beneath `root`.
fn open_reached(root: BorrowedFd<'_>, reached: &[OsString]) -> io::Result<OwnedFd> {
    let path: PathBuf = if reached.is_empty() {
        PathBuf::from(".")
    } else {
        reached.iter().collect()
    };
    openat2(
        root,
        &path,
        libc::O_PATH | libc::O_DIRECTORY,
        RESOLVE_IN_TREE,
    )
}

/// The target of the link `link` holds (opened `O_PATH | O_NOFOLLOW`).
fn read_link(link: BorrowedFd<'_>) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; LINK_MAX];
    // SAFETY: `readlinkat(2)` with a live descriptor, a NUL-terminated empty
    // path (the descriptor's own link) and a buffer of `buf.len()` writable
    // bytes.
    let n = unsafe {
        libc::readlinkat(
            link.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    if n == buf.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    buf.truncate(n);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Creates the file `name` in `dir` holding `contents`. One that is there
/// already, made meanwhile, is left as it is.
fn create_file(dir: BorrowedFd<'_>, name: &OsStr, contents: &[u8]) -> io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: `openat(2)` with a live directory descriptor, a NUL-terminated
    // name and a mode for `O_CREAT`; `O_EXCL | O_NOFOLLOW` never opens or
    // creates through a link.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
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

/// Makes the directory `name` in `dir`. One that is there already, made
/// meanwhile, is left as it is.
fn make_dir(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    let c = c_name(name)?;
    // SAFETY: `mkdirat(2)` with a live directory descriptor and a
    // NUL-terminated name; it never follows a link.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o777) } == -1 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e);
        }
    }
    Ok(())
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

    /// How the tests' home is shown in a refusal.
    const HOME: TreeView<'static> = TreeView {
        shown: "~",
        name: "home",
    };

    /// The refusal `e` carries; panics, naming `what`, when it carries none.
    fn why<'e>(e: &'e io::Error, what: &str) -> &'e Why {
        &refusal(e)
            .unwrap_or_else(|| panic!("{what}: not a refusal: {e:?}"))
            .why
    }

    /// Whether this host lets the test's child set up the user namespace a
    /// namespace test runs in. A host that denies it (a CI runner restricting
    /// unprivileged user namespaces) skips `test` with the reason printed,
    /// rather than failing on a setup it cannot make or passing silently.
    fn skip_without_userns(test: &str) -> bool {
        let Some(reason) = crate::user_namespaces_restriction() else {
            return false;
        };
        eprintln!(
            "skipping {test}: this host denies the unprivileged user namespace the test's \
             child unshares: {reason}"
        );
        true
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
        let handle = resolve(home_fd.as_fd(), HOME, Path::new("x")).unwrap();
        assert_eq!(identity(&handle), identity_of(&home.join("x")));
        let whole = resolve(home_fd.as_fd(), HOME, Path::new("")).unwrap();
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
        let handle = resolve(home_fd.as_fd(), HOME, Path::new("x")).unwrap();

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

        let again = resolve(home_fd.as_fd(), HOME, Path::new("x")).unwrap_err();
        assert_eq!(
            errno_of(&again),
            Some(libc::EXDEV),
            "a fresh resolve refuses the link out of the home"
        );
        assert!(
            matches!(why(&again, "x"), Why::Absolute { link, .. } if link == Path::new("x")),
            "and names the link: {again}"
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
        if skip_without_userns(
            "a_swap_between_the_resolve_and_the_bind_cannot_change_what_is_mounted",
        ) {
            return;
        }
        let (root, home, _outside) = home_and_outside();
        let locked = crate::locked_ms_flags(&home);
        let mut container = hakoniwa::Container::new();
        container.rootfs("/").unwrap();
        container.bindmount_rw(root.path().to_str().unwrap(), "/t");
        // SAFETY: the closure runs in the forked child, which is
        // single-threaded; it makes plain filesystem calls and returns a code.
        let mut command = unsafe {
            container.command_from_closure(move || {
                let Ok(home) = open_dir(Path::new("/t/home")) else {
                    return 10;
                };
                let Ok(handle) = resolve(home.as_fd(), HOME, Path::new("x")) else {
                    return 11;
                };
                // The box's swap, after the resolve.
                if std::fs::rename("/t/home/x", "/t/home/d").is_err()
                    || std::os::unix::fs::symlink("/t/outside", "/t/home/x").is_err()
                {
                    return 12;
                }
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
        if skip_without_userns("bind_all_lays_a_home_patch_over_a_staged_mapping_as_hakoniwa_did") {
            return;
        }
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
                locked: crate::locked_ms_flags(&t.join("home")),
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
            let err = resolve(home_fd.as_fd(), HOME, Path::new(link)).unwrap_err();
            assert_eq!(errno_of(&err), Some(libc::EXDEV), "{link}");
        }
        let inside = resolve(home_fd.as_fd(), HOME, Path::new("inside")).unwrap();
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
            let err = resolve(home_fd.as_fd(), HOME, Path::new(path)).unwrap_err();
            assert_eq!(errno_of(&err), Some(libc::EXDEV), "{path}");
            assert_eq!(why(&err, path), &Why::Climbs, "{path}");
        }
        let inside = resolve(home_fd.as_fd(), HOME, Path::new("x/../x")).unwrap();
        assert_eq!(
            identity(&inside),
            identity_of(&home.join("x")),
            "`..` inside stays in"
        );
    }

    /// What the closure says it was doing: reading a tree patch's source,
    /// or placing a patch at its mount point, with the patch from outside
    /// the session named as such, so a refused mount point is never told as
    /// a source from outside the home.
    #[test]
    fn the_failure_names_the_step_and_the_patch() {
        let tree = SessionBind {
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
        let staged = SessionBind {
            source: Source::Staged {
                stage: "/.minimal-patch/0".into(),
            },
            ..tree.clone()
        };
        assert_eq!(
            tree.failure(Step::Source),
            "reading the patch for `/home/x811` from the session's home"
        );
        assert_eq!(
            tree.failure(Step::MountPoint),
            "placing the patch at `/home/x811`"
        );
        assert_eq!(
            staged.failure(Step::Source),
            "reading the patch for `/home/x811` from outside the session"
        );
        assert_eq!(
            staged.failure(Step::MountPoint),
            "placing the patch from outside the session at `/home/x811`"
        );
    }

    /// The refusal says what was refused, why, and what to do, with no errno
    /// in its text: an absolute link (also one naming a place in the home),
    /// a link that climbs out, a `..` in the path itself, a loop.
    #[test]
    fn a_refusal_says_what_was_refused_why_and_what_to_do() {
        let (_root, home, _outside) = home_and_outside();
        std::fs::create_dir_all(home.join("dotfiles")).unwrap();
        std::fs::write(home.join("dotfiles/gitconfig"), "[user]").unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/gitconfig"), home.join(".gitconfig"))
            .unwrap();
        std::os::unix::fs::symlink("../../outside", home.join("x/up")).unwrap();
        std::os::unix::fs::symlink("loop-b", home.join("loop-a")).unwrap();
        std::os::unix::fs::symlink("loop-a", home.join("loop-b")).unwrap();
        let home_fd = open_dir(&home).unwrap();
        let refusal_of = |path: &str| {
            let err = resolve(home_fd.as_fd(), HOME, Path::new(path)).unwrap_err();
            let text = err.to_string();
            assert!(!text.contains("os error"), "{path}: no bare errno: {text}");
            (why(&err, path).clone(), text)
        };

        let (absolute, text) = refusal_of(".gitconfig");
        assert_eq!(
            absolute,
            Why::Absolute {
                link: ".gitconfig".into(),
                to: home.join("dotfiles/gitconfig"),
            }
        );
        assert!(
            text.starts_with("`~/.gitconfig` is a symbolic link to the absolute path")
                && text.contains(
                    "Replace it with a relative link that stays in the home, or remove it."
                )
                && !text.contains("outside"),
            "an absolute link into the home is refused as absolute, not as outside: {text}"
        );

        let (climbs, text) = refusal_of("x/up/token");
        assert_eq!(
            climbs,
            Why::LinkClimbs {
                link: "x/up".into(),
                to: "../../outside".into(),
            }
        );
        assert!(
            text.starts_with("`~/x/up`, on the patch path `~/x/up/token`, is a symbolic link")
                && text.contains("climbs out of the session's home")
                && text.contains("Point that link at a place in the home, or remove it."),
            "{text}"
        );

        let (up, text) = refusal_of("x/../../outside");
        assert_eq!(up, Why::Climbs);
        assert!(text.contains("through `..`"), "{text}");

        let (looped, text) = refusal_of("loop-a");
        assert_eq!(looped, Why::Loop);
        assert!(text.contains("loop"), "{text}");
    }

    /// A refusal anywhere on the path leaves nothing behind: the walk makes
    /// nothing until the whole path is known to stay in the home, also when a
    /// missing name comes before the `..`, link or loop that is refused. A
    /// name or `..` after a file is refused as not a directory.
    #[test]
    fn a_refused_create_leaves_nothing_behind() {
        let (_root, home, outside) = home_and_outside();
        std::os::unix::fs::symlink("n/../../outside", home.join("climbs")).unwrap();
        std::os::unix::fs::symlink(&outside, home.join("abs")).unwrap();
        std::os::unix::fs::symlink("m/../loop-b", home.join("loop-a")).unwrap();
        std::os::unix::fs::symlink("m/../loop-a", home.join("loop-b")).unwrap();
        type Case = (&'static str, &'static str, fn(&Why) -> bool);
        let cases: [Case; 5] = [
            ("climbs/new", "n", |w| matches!(w, Why::LinkClimbs { .. })),
            ("x/new/../../..", "x/new", |w| *w == Why::Climbs),
            ("new2/../abs/new", "new2", |w| {
                matches!(w, Why::Absolute { .. })
            }),
            ("loop-a/new", "m", |w| *w == Why::Loop),
            ("x/token/../y", "x/y", |w| matches!(w, Why::NotDir { .. })),
        ];
        for (path, left, kind) in cases {
            for is_file in [false, true] {
                let err = create_beneath(&home, HOME, Path::new(path), is_file, b"{}");
                let err = err.unwrap_err();
                assert!(kind(why(&err, path)), "{path}: {err}");
                assert!(
                    std::fs::symlink_metadata(home.join(left)).is_err(),
                    "{path}: `{left}` was left behind in the home"
                );
            }
        }
        let err = create_beneath(&home, HOME, Path::new("x/token/../y"), false, b"").unwrap_err();
        assert_eq!(errno_of(&err), Some(libc::ENOTDIR));
        assert!(
            err.to_string()
                .starts_with("`~/x/token`, on the patch path `~/x/token/../y`, is not a directory"),
            "{err}"
        );
        assert!(!outside.join("new").exists(), "nothing was made outside");
    }

    /// The stow shape (inbox#1152 review): `~/.config/nvim` is a relative
    /// link that climbs above its own directory and stays in the home. A
    /// patch under it resolves, a missing one is made where it leads, for
    /// the daemon and for a missing mount point alike, and a sibling link
    /// that climbs one level further, out of the home, is still refused.
    #[test]
    fn a_stow_link_that_climbs_within_the_home_is_followed() {
        let (_root, home, outside) = home_and_outside();
        let stowed = home.join("dotfiles/nvim/.config/nvim");
        std::fs::create_dir_all(&stowed).unwrap();
        std::fs::write(stowed.join("init.lua"), "-- in").unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::os::unix::fs::symlink("../dotfiles/nvim/.config/nvim", home.join(".config/nvim"))
            .unwrap();
        let home_fd = open_dir(&home).unwrap();

        let init = resolve(home_fd.as_fd(), HOME, Path::new(".config/nvim/init.lua")).unwrap();
        assert_eq!(identity(&init), identity_of(&stowed.join("init.lua")));

        let plugins = Path::new(".config/nvim/lua/plugins");
        create_beneath(&home, HOME, plugins, false, b"").unwrap();
        assert!(
            stowed.join("lua/plugins").is_dir(),
            "made where the link leads"
        );
        let lazy = Path::new(".config/nvim/lazy.json");
        create_beneath(&home, HOME, lazy, true, b"{}").unwrap();
        assert_eq!(
            std::fs::read_to_string(stowed.join("lazy.json")).unwrap(),
            "{}"
        );

        let rel = Path::new(".config/nvim/after/ftplugin");
        let made = resolve_or_create(home_fd.as_fd(), HOME, rel, false).unwrap();
        assert_eq!(
            identity(&made),
            identity_of(&stowed.join("after/ftplugin")),
            "a missing mount point under the stow link is made in the home, where it leads"
        );

        std::os::unix::fs::symlink("../../outside", home.join(".config/out")).unwrap();
        let err = create_beneath(&home, HOME, Path::new(".config/out/new"), false, b"");
        let err = err.unwrap_err();
        assert!(
            matches!(why(&err, ".config/out"), Why::LinkClimbs { .. }),
            "{err}"
        );
        assert!(!outside.join("new").exists(), "nothing was made outside");
    }

    /// A file patch whose path is a dangling link that stays in the home
    /// (`~/.c.json -> .dotfiles/c.json`, target missing): the daemon makes
    /// the link's target in the home, the missing directory on the way
    /// included, and the patch then resolves through the link. A missing
    /// mount point that is such a link is made the same way.
    #[test]
    fn a_dangling_link_in_the_home_gets_its_target_made_in_the_home() {
        let (_root, home, _outside) = home_and_outside();
        std::os::unix::fs::symlink(".dotfiles/c.json", home.join(".c.json")).unwrap();
        std::os::unix::fs::symlink("x/d.json", home.join(".d.json")).unwrap();
        let home_fd = open_dir(&home).unwrap();

        create_beneath(&home, HOME, Path::new(".c.json"), true, b"{}").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join(".dotfiles/c.json")).unwrap(),
            "{}",
            "the link's target, made in the home"
        );
        let link = home.join(".c.json").symlink_metadata().unwrap();
        assert!(link.is_symlink(), "the link is left as it is");
        let source = resolve(home_fd.as_fd(), HOME, Path::new(".c.json")).unwrap();
        assert_eq!(
            identity(&source),
            identity_of(&home.join(".dotfiles/c.json")),
            "the patch resolves through the link to what was made"
        );

        let point = resolve_or_create(home_fd.as_fd(), HOME, Path::new(".d.json"), true).unwrap();
        assert_eq!(
            identity(&point),
            identity_of(&home.join("x/d.json")),
            "a dangling mount point gets its target made, as a file"
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
        Tree::session(Path::new("/s/home"), Path::new("/s/home/proj"), "workbench")
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
            plan.binds[1].locked, 0,
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
        create_beneath(&home, HOME, Path::new("a/b/c"), false, b"").unwrap();
        assert!(home.join("a/b/c").is_dir());
        create_beneath(&home, HOME, Path::new("cfg/app.json"), true, b"{}").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("cfg/app.json")).unwrap(),
            "{}"
        );
        create_beneath(&home, HOME, Path::new("cfg/app.json"), true, b"[]").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("cfg/app.json")).unwrap(),
            "{}",
            "a file already there is left as it is"
        );
        std::os::unix::fs::symlink("a", home.join("in")).unwrap();
        create_beneath(&home, HOME, Path::new("in/made"), false, b"").unwrap();
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

        std::os::unix::fs::symlink("../outside/rel.json", home.join("dangling-rel.json")).unwrap();

        for path in ["l/new", "r/new", "dangling.json", "dangling-rel.json"] {
            let err = create_beneath(&home, HOME, Path::new(path), true, b"{}").unwrap_err();
            assert_eq!(errno_of(&err), Some(libc::EXDEV), "{path}: {err}");
        }
        assert!(
            !outside.join("new").exists()
                && !outside.join("made.json").exists()
                && !outside.join("rel.json").exists(),
            "nothing was created outside the home"
        );
        let err = create_beneath(&home, HOME, Path::new("x/../../outside/up"), false, b"");
        let err = err.unwrap_err();
        assert_eq!(why(&err, "x/../../outside/up"), &Why::Climbs);
        assert!(!outside.join("up").exists());
    }
}
