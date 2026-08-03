//! SFTP subsystem handler.
//!
//! One [`SftpSession`] is constructed per `sftp` subsystem request and handed
//! to [`russh_sftp::server::run`], which owns the dispatch loop. The handler
//! holds owned per-channel state — no inner actor — because dispatch through
//! `run` is already serialised.
//!
//! The client sees the two directories a session and the daemon share, under
//! the names the sandbox gives them: the session's working tree at
//! [`env::WORKSPACE_ROOT`] and its home at [`env::HOME_ROOT`], side by side
//! below a synthetic root that holds nothing else. Relative paths resolve
//! against the working tree, which is also what `realpath(".")` reports, so a
//! client that never leaves it sees what it saw when the workspace *was* `/`.
//!
//! Every client-supplied path is funnelled through [`SftpSession::resolve`],
//! which normalizes it in that namespace, maps it onto the daemon-side
//! directory it names, and rejects anything landing outside the two — whether
//! spelled with `..` or reached through a symlink.

use std::collections::HashMap;
use std::io::SeekFrom;

use camino::{Utf8Path, Utf8PathBuf};
use paths::{DaemonAbsPath, DaemonRelPath};
use russh::ChannelId;
use russh::server::Session;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use russh_sftp::server::StatusReply;
use sessions::SessionId;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::task::spawn;

use crate::connection::{ConnectionError, ConnectionHandle};
use crate::server::ServerStateHandle;
use crate::sessions::SessionKeyPredicate;
use crate::{MINIMAL_SESSION_ID_ENV, env};

/// The SSH subsystem name used to negotiate an SFTP channel.
pub const SUBSYSTEM_NAME: &str = "sftp";

/// Cap on how many directory entries are returned per `readdir` call.
/// SFTP clients call `readdir` repeatedly until they see `SSH_FX_EOF`, so
/// batching keeps individual packets within typical SFTP size limits.
const READDIR_BATCH: usize = 100;

const MAX_READ_LEN: usize = 128 * 1024;

/// Error returned by SFTP handler methods.
///
/// `russh_sftp` requires `Into<StatusReply>`: every failed request maps to a
/// single `SSH_FXP_STATUS` packet, so we lose any structured detail at the
/// wire boundary regardless. The enum exists so the handler can report the
/// *cause* in logs even though the wire only carries a status code.
///
/// `StatusReply` can also carry a human-readable message, which we
/// deliberately leave unset: `russh_sftp` then falls back to the status
/// code's own text, and an `Io` variant's message can embed host paths that
/// have no business crossing the export boundary.
#[derive(Debug)]
pub enum SftpError {
    Io(std::io::Error),
    /// Client-supplied path resolved outside the exported directories, or
    /// named the synthetic root in a request that can only act on a real file.
    PathTraversal,
    /// Client referenced a handle id this session does not know about.
    UnknownHandle,
    /// Client referenced a handle of the wrong kind (e.g. `read` on a dir).
    WrongHandleType,
    /// End of file or end of directory listing.
    Eof,
    /// SFTP packet recognised but not implemented.
    Unsupported,
}

impl From<std::io::Error> for SftpError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<SftpError> for StatusCode {
    fn from(e: SftpError) -> StatusCode {
        use std::io::ErrorKind;
        match e {
            SftpError::Io(io) => match io.kind() {
                ErrorKind::NotFound => StatusCode::NoSuchFile,
                ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
                ErrorKind::UnexpectedEof => StatusCode::Eof,
                _ => StatusCode::Failure,
            },
            SftpError::PathTraversal => StatusCode::PermissionDenied,
            SftpError::UnknownHandle | SftpError::WrongHandleType => StatusCode::Failure,
            SftpError::Eof => StatusCode::Eof,
            SftpError::Unsupported => StatusCode::OpUnsupported,
        }
    }
}

impl From<SftpError> for StatusReply {
    fn from(e: SftpError) -> StatusReply {
        StatusReply::new(e.into())
    }
}

/// An SFTP handle id refers to either an open file or a snapshot of a
/// directory listing. Using an enum (rather than two parallel maps) keeps
/// "handle id of the wrong kind" representable as a single lookup.
enum OpenHandle {
    File(fs::File),
    /// Remaining unread directory entries; drained in `READDIR_BATCH`-sized
    /// chunks by `readdir`, then `SSH_FX_EOF` on the next call.
    Dir(Vec<File>),
}

/// What a client-supplied path resolved to.
enum Target {
    /// The synthetic root. It has no daemon path of its own: it exists so the
    /// two exports have somewhere to hang, and so a client can list `/` and
    /// walk between them.
    Root,
    /// A path inside one of the exports, already proven to be contained.
    Real(DaemonAbsPath),
}

impl Target {
    /// The daemon path this names, for requests that can only act on a real
    /// file. The synthetic root has nothing on disk to open, create, rename,
    /// remove or chmod, so naming it is refused like any other path outside
    /// the exports.
    fn real(self) -> Result<DaemonAbsPath, SftpError> {
        match self {
            Target::Real(path) => Ok(path),
            Target::Root => Err(SftpError::PathTraversal),
        }
    }
}

/// Per-channel SFTP server scoped to a single session's directories.
pub struct SftpSession {
    /// The session's working tree, presented at [`env::WORKSPACE_ROOT`].
    ///
    /// Canonical, and cached at construction: the session contract guarantees
    /// both directories are stable for the session lifetime, so fetching them
    /// per-request would round-trip through the session actor for nothing.
    workspace: DaemonAbsPath,
    /// The session's home directory, presented at [`env::HOME_ROOT`].
    /// Canonical, for the same reason as [`SftpSession::workspace`].
    home: DaemonAbsPath,
    handles: HashMap<String, OpenHandle>,
    next_handle_id: u64,
}

impl SftpSession {
    /// Constructs a handler scoped to one session's working tree and home.
    ///
    /// Both are canonicalized here rather than per-request: containment is
    /// decided by comparing a canonicalized path against these roots, and a
    /// root reached through a symlink itself (`/var` -> `/private/var`) would
    /// fail that comparison for every path under it.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if either directory cannot be
    /// canonicalized — it is missing, unreadable, or not UTF-8.
    pub async fn new(
        workspace: DaemonAbsPath,
        home: DaemonAbsPath,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            workspace: canonicalize(&workspace).await?,
            home: canonicalize(&home).await?,
            handles: HashMap::new(),
            next_handle_id: 0,
        })
    }

    /// The exported directories, each paired with the client-facing root it
    /// appears under. The only place the two are enumerated.
    fn exports(&self) -> [(&'static str, &DaemonAbsPath); 2] {
        [
            (env::WORKSPACE_ROOT, &self.workspace),
            (env::HOME_ROOT, &self.home),
        ]
    }

    /// Resolves a client-supplied SFTP path to something on the daemon,
    /// rejecting anything that resolves outside the exported directories.
    ///
    /// Normalization happens in the *client's* namespace, before the mapping:
    /// that way `..` is spent against the client-facing root — where
    /// `/workbench/../home` is the other export and `/workbench/../..` is
    /// still `/` — and never against the daemon's filesystem. What survives
    /// names one of the exports, so the mapping is a prefix swap. The
    /// containment check afterwards is about symlinks, which normalization
    /// cannot see.
    async fn resolve(&self, sftp_path: &str) -> Result<Target, SftpError> {
        // A relative path is resolved against the working tree: it is the
        // session's working directory, and what `realpath(".")` hands back.
        let requested = if sftp_path.starts_with('/') {
            Utf8PathBuf::from(sftp_path)
        } else {
            Utf8Path::new(env::WORKSPACE_ROOT).join(sftp_path)
        };
        let requested = env::normalize_absolute(&requested);

        if requested == Utf8Path::new("/") {
            return Ok(Target::Root);
        }

        // `strip_prefix` matches whole components, so `/workbenchevil` is not
        // under `/workbench`.
        let Some((base, rel)) = self
            .exports()
            .into_iter()
            .find_map(|(root, base)| Some((base, requested.strip_prefix(root).ok()?)))
        else {
            return Err(SftpError::PathTraversal);
        };

        let dest = if rel.as_str().is_empty() {
            base.clone()
        } else {
            // The typed join keeps the destination anchored: `join` takes a
            // `DaemonRelPath`, where joining a raw string could replace the
            // root outright. `try_new` re-checks the remainder is relative and
            // `..`-free — normalization above is what makes that hold.
            let rel = DaemonRelPath::try_new(rel).map_err(|_| SftpError::PathTraversal)?;
            base.join(&rel)
        };
        contained(dest, base).await.map(Target::Real)
    }

    /// Resolves a path that a request is about to unlink or move over,
    /// refusing the export roots themselves.
    ///
    /// The two directories are the session's layout, and both the daemon and
    /// the sandbox expect them to stay where they are. Everything *under*
    /// them is the client's to destroy; an empty one would otherwise be a
    /// successful `rmdir` or `rename` away from taking the session with it.
    async fn resolve_below_export(&self, sftp_path: &str) -> Result<DaemonAbsPath, SftpError> {
        let path = self.resolve(sftp_path).await?.real()?;
        if self.exports().iter().any(|(_, base)| **base == path) {
            return Err(SftpError::PathTraversal);
        }
        Ok(path)
    }

    /// Converts a resolved target back into the client-facing form.
    fn client_path(&self, target: &Target) -> String {
        let Target::Real(host) = target else {
            return "/".to_string();
        };
        for (root, base) in self.exports() {
            let Ok(rel) = host.strip_prefix(base) else {
                continue;
            };
            return if rel.as_str().is_empty() {
                root.to_string()
            } else {
                format!("{root}/{rel}")
            };
        }
        // Unreachable: `resolve` only hands back paths under an export.
        "/".to_string()
    }

    fn mint_handle(&mut self, h: OpenHandle) -> String {
        let id = self.next_handle_id;
        self.next_handle_id += 1;
        let key = id.to_string();
        self.handles.insert(key.clone(), h);
        key
    }

    fn file_mut(&mut self, h: &str) -> Result<&mut fs::File, SftpError> {
        match self.handles.get_mut(h) {
            Some(OpenHandle::File(f)) => Ok(f),
            Some(_) => Err(SftpError::WrongHandleType),
            None => Err(SftpError::UnknownHandle),
        }
    }

    fn dir_mut(&mut self, h: &str) -> Result<&mut Vec<File>, SftpError> {
        match self.handles.get_mut(h) {
            Some(OpenHandle::Dir(entries)) => Ok(entries),
            Some(_) => Err(SftpError::WrongHandleType),
            None => Err(SftpError::UnknownHandle),
        }
    }
}

/// Proves `dest` really lives under `base`, and returns it with every symlink
/// on the way already resolved.
///
/// `dest` need not exist — SFTP creates files, and `open` with `CREATE` names
/// one that does not. So the check walks up to the deepest ancestor that does
/// exist, canonicalizes *that*, and re-appends the missing tail: a symlinked
/// parent is refused before anything is created through it, which
/// canonicalizing only existing paths would miss.
///
/// `base` is canonical (see [`SftpSession::new`]), so the comparison is
/// symlink-free on both sides. The walk terminates because `base` exists: it
/// either finds an existing ancestor at or below `base`, or walks past it and
/// is refused.
async fn contained(dest: DaemonAbsPath, base: &DaemonAbsPath) -> Result<DaemonAbsPath, SftpError> {
    let mut probe = dest;
    let mut missing: Vec<String> = Vec::new();
    loop {
        match canonicalize(&probe).await {
            Ok(real) => {
                if !real.starts_with(base) {
                    return Err(SftpError::PathTraversal);
                }
                // `missing` was pushed leaf-last on the way up.
                return Ok(missing
                    .iter()
                    .rev()
                    .fold(real, |path, name| path.sub_path_unchecked(name)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink canonicalizes to `NotFound` while still
                // being a real directory entry. Reading it as "does not exist
                // yet" would hand back the link's own path, and `open` with
                // `CREATE` would then follow it and create the file it points
                // at — outside `base`, which is the whole point of this walk.
                if fs::symlink_metadata(probe.as_str()).await.is_ok() {
                    return Err(SftpError::PathTraversal);
                }
                let (Some(name), Some(parent)) = (probe.file_name(), probe.parent()) else {
                    // Ran out of path before finding anything that exists;
                    // only reachable above `base`, which does exist.
                    return Err(SftpError::PathTraversal);
                };
                missing.push(name.to_string());
                probe = parent;
            }
            Err(e) => return Err(SftpError::Io(e)),
        }
    }
}

/// [`tokio::fs::canonicalize`], keeping the path typed and UTF-8.
async fn canonicalize(path: &DaemonAbsPath) -> Result<DaemonAbsPath, std::io::Error> {
    let canonical = fs::canonicalize(path.as_str()).await?;
    let canonical = Utf8PathBuf::from_path_buf(canonical)
        .map_err(|p| std::io::Error::other(format!("path is not utf-8: {}", p.display())))?;
    // `canonicalize` returns an absolute path by construction.
    Ok(DaemonAbsPath::new_unchecked(canonical))
}

/// Attributes reported for the synthetic root: a read-only directory.
///
/// It has no inode of its own, so mode is the only thing we can honestly
/// state. Everything else — size, uid/gid, atime/mtime — is left unset, and
/// SFTP's per-field flags mean an unset field is absent from the packet
/// rather than zero. `set_dir` writes `S_IFDIR` into the mode, which is what
/// makes a client's `stat("/")` report a directory.
///
/// (Before russh-sftp 2.2, `FileAttributes::default()` supplied dummy zeros
/// rather than absent fields, so root used to advertise size 0, uid/gid 0 and
/// epoch timestamps. `FileAttributes::dummy()` is the name for that now, and
/// this is deliberately not it.)
fn root_attrs() -> FileAttributes {
    let mut attrs = FileAttributes {
        permissions: Some(0o555),
        ..FileAttributes::default()
    };
    attrs.set_dir(true);
    attrs
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError::Unsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = self.resolve(&path).await?;
        Ok(Name {
            id,
            files: vec![File::dummy(self.client_path(&target))],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let attrs = match self.resolve(&path).await? {
            Target::Root => root_attrs(),
            Target::Real(host) => FileAttributes::from(&fs::metadata(host.as_str()).await?),
        };
        Ok(Attrs { id, attrs })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        // A symlink is already gone by the time we get here: `resolve`
        // follows links to decide containment, so this reports the target,
        // as `readdir` does. Nothing under an export can name a link outside
        // it, so there is nothing to describe that `stat` would not.
        let attrs = match self.resolve(&path).await? {
            Target::Root => root_attrs(),
            Target::Real(host) => FileAttributes::from(&fs::symlink_metadata(host.as_str()).await?),
        };
        Ok(Attrs { id, attrs })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let f = self.file_mut(&handle)?;
        let m = f.metadata().await?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let host = self.resolve(&filename).await?.real()?;
        let mut opts = OpenOptions::new();
        // `resolve` proved a path; this opens a *name*, and the two are only
        // the same until something rewrites the leaf. Both exports are
        // bind-mounted read-write into the sandbox, so an in-session process
        // can sit in that gap swapping the leaf for a symlink until an open
        // lands on it — with the daemon, which is not confined to the
        // sandbox, doing the following. `O_NOFOLLOW` refuses that leaf
        // outright. It costs nothing legitimate: `resolve` hands back a
        // canonical path, so a real symlink is already resolved to its
        // target by the time we get here and there is no link left to refuse.
        // A swap higher up the path is not covered here — the ancestor walk
        // in `contained` is what narrows that.
        opts.custom_flags(libc::O_NOFOLLOW);
        opts.read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE))
            .append(pflags.contains(OpenFlags::APPEND))
            .truncate(pflags.contains(OpenFlags::TRUNCATE));
        // EXCLUDE implies CREATE per SFTP semantics; create_new covers both.
        if pflags.contains(OpenFlags::EXCLUDE) {
            opts.create_new(true);
        } else if pflags.contains(OpenFlags::CREATE) {
            opts.create(true);
        }
        let f = opts.open(host.as_str()).await?;
        let handle = self.mint_handle(OpenHandle::File(f));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles
            .remove(&handle)
            .ok_or(SftpError::UnknownHandle)?;
        Ok(ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let f = self.file_mut(&handle)?;
        f.seek(SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; (len as usize).min(MAX_READ_LEN)];
        let n = f.read(&mut buf).await?;
        if n == 0 {
            return Err(SftpError::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let f = self.file_mut(&handle)?;
        f.seek(SeekFrom::Start(offset)).await?;
        f.write_all(&data).await?;
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let host = match self.resolve(&path).await? {
            // The synthetic root holds the two exports and nothing else —
            // no "..", since there is nothing above it.
            Target::Root => {
                let mut entries = vec![File::new(".".to_string(), root_attrs())];
                for (root, base) in self.exports() {
                    let m = fs::metadata(base.as_str()).await?;
                    // The exports' client-facing roots are their names, since
                    // they sit directly under `/`.
                    let name = root.trim_start_matches('/').to_string();
                    entries.push(File::new(name, FileAttributes::from(&m)));
                }
                let handle = self.mint_handle(OpenHandle::Dir(entries));
                return Ok(Handle { id, handle });
            }
            Target::Real(host) => host,
        };
        let mut entries = Vec::new();

        let m = fs::metadata(host.as_str()).await?;
        entries.push(File::new(".".to_string(), FileAttributes::from(&m)));
        // At an export root the parent on disk is a daemon directory the
        // client has no business seeing; ".." there is the synthetic root.
        let parent = host
            .parent()
            .filter(|p| p.starts_with(&self.workspace) || p.starts_with(&self.home));
        let parent_attrs = match parent {
            Some(parent) => FileAttributes::from(&fs::metadata(parent.as_str()).await?),
            None => root_attrs(),
        };
        entries.push(File::new("..".to_string(), parent_attrs));

        let mut read = fs::read_dir(host.as_str()).await?;
        while let Some(e) = read.next_entry().await? {
            let em = e.metadata().await?;
            let name = e.file_name().to_string_lossy().into_owned();
            entries.push(File::new(name, FileAttributes::from(&em)));
        }

        let handle = self.mint_handle(OpenHandle::Dir(entries));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let entries = self.dir_mut(&handle)?;
        if entries.is_empty() {
            return Err(SftpError::Eof);
        }
        let take = entries.len().min(READDIR_BATCH);
        let files = entries.drain(..take).collect();
        Ok(Name { id, files })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let host = self.resolve(&path).await?.real()?;
        fs::create_dir(host.as_str()).await?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let host = self.resolve_below_export(&path).await?;
        fs::remove_dir(host.as_str()).await?;
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let host = self.resolve_below_export(&filename).await?;
        fs::remove_file(host.as_str()).await?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let from = self.resolve_below_export(&oldpath).await?;
        let to = self.resolve_below_export(&newpath).await?;
        fs::rename(from.as_str(), to.as_str()).await?;
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let host = self.resolve(&path).await?.real()?;
        if let Some(perms) = perm_from_mode(attrs.permissions) {
            // `chmod` follows symlinks, so like `open` this re-resolves the
            // leaf by name and a link swapped in after the check would be
            // followed out of the export. The other mutating handlers need no
            // such care: `mkdir`, `rmdir`, `unlink` and `rename` all act on
            // the link itself rather than what it points at.
            //
            // `fchmod` through an `O_NOFOLLOW` handle refuses that leaf the
            // same way `open` does. `O_NONBLOCK` because this open is the
            // only thing standing between a fifo planted in the workspace and
            // a wedged dispatch loop; on a regular file it does nothing.
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(host.as_str())
                .await?;
            // The handle's own `fstat`, not a second lookup by name: it
            // describes exactly the object about to be chmodded.
            let is_dir = file.metadata().await?.is_dir();
            file.set_permissions(keep_owner_access(perms, is_dir))
                .await?;
        }
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if let Some(perms) = perm_from_mode(attrs.permissions) {
            self.file_mut(&handle)?.set_permissions(perms).await?;
        }
        Ok(ok_status(id))
    }
}

/// Strips the file-type bits from an SFTP permissions field and returns a
/// `std::fs::Permissions` carrying only the POSIX mode bits. Returns `None`
/// when the client omitted permissions, so callers leave the attribute
/// untouched.
fn perm_from_mode(mode: Option<u32>) -> Option<std::fs::Permissions> {
    use std::os::unix::fs::PermissionsExt;
    mode.map(|m| std::fs::Permissions::from_mode(m & 0o7777))
}

/// Floors a client's mode at owner `r-x` for directories, `r--` otherwise;
/// every other bit passes through.
///
/// Without it `chmod 000` is irreversible: `setstat` chmods through an open
/// handle, so a file the owner cannot read is one no later request can chmod
/// back. Owner write is not forced — read-only is a thing clients may
/// legitimately want, and it stays undoable.
fn keep_owner_access(perms: std::fs::Permissions, is_dir: bool) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    let floor = if is_dir { 0o500 } else { 0o400 };
    std::fs::Permissions::from_mode(perms.mode() | floor)
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::from("en-US"),
    }
}

/// Handles an `sftp` subsystem request on an SSH channel.
///
/// Looks up the target session via the `MINIMAL_SESSION_ID` env var the
/// client previously set on this channel, fetches its workspace, accepts the
/// subsystem request, and spawns `russh_sftp::server::run` to take over the
/// channel for the lifetime of the SFTP conversation.
pub(crate) async fn handle_sftp_subsystem(
    s: ServerStateHandle,
    c: ConnectionHandle,
    id: ChannelId,
    session: &mut Session,
) -> Result<(), ConnectionError> {
    let mut conn_lock = c.lock().await;
    let Some((channel, config)) = conn_lock.take(id) else {
        session.channel_failure(id)?;
        return Ok(());
    };
    drop(conn_lock);

    let Some(session_id_str) = config.env_vars.get(MINIMAL_SESSION_ID_ENV) else {
        tracing::warn!("sftp subsystem rejected on channel {id}: missing {MINIMAL_SESSION_ID_ENV}",);
        session.channel_failure(id)?;
        return Ok(());
    };
    let Ok(session_id) = SessionId::parse_str(session_id_str) else {
        tracing::warn!(
            value = %session_id_str,
            "sftp subsystem rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
        );
        session.channel_failure(id)?;
        return Ok(());
    };

    let mngr = s.sessions_manager().await;
    let session_handle = match mngr.get_session(SessionKeyPredicate::Id(session_id)).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!(%session_id, "sftp subsystem rejected: unknown session");
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "sftp subsystem rejected: lookup failed");
            session.channel_failure(id)?;
            return Ok(());
        }
    };
    let paths = match session_handle.paths().await {
        Ok(paths) => paths,
        // The actor died between resolve and this call (raced an
        // abort/destroy) — to this channel the session no longer exists.
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "sftp subsystem rejected: session is gone");
            session.channel_failure(id)?;
            return Ok(());
        }
    };

    // Canonicalizing the session's two directories is the one filesystem
    // touch before the channel is accepted: a session whose directories are
    // gone cannot serve any request on this channel anyway.
    let sftp = match SftpSession::new(paths.working, paths.home).await {
        Ok(sftp) => sftp,
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "sftp subsystem rejected: session directories are unusable");
            session.channel_failure(id)?;
            return Ok(());
        }
    };

    session.channel_success(id)?;
    spawn(russh_sftp::server::run(channel.into_stream(), sftp));

    Ok(())
}

#[cfg(test)]
mod tests {
    use russh_sftp::client::SftpSession as SftpClient;
    use russh_sftp::client::error::Error as SftpClientError;
    use russh_sftp::protocol::{OpenFlags, StatusCode};
    use sessions::SessionId;
    use std::os::unix::fs::PermissionsExt;

    use tokio::io::AsyncWriteExt;

    use crate::env;
    use crate::session::SessionPaths;
    use crate::sessions::SessionKeyPredicate;
    use crate::test_harness::TestServer;

    /// Creates a fresh session through the public CreateSession RPC and
    /// returns its uuid, mirroring how a real client would set things up
    /// before opening an SFTP channel.
    async fn fresh_session(client: &mut crate::test_harness::TestClient) -> SessionId {
        crate::test_harness::create_configured_session(client, "sftp-test", "/tmp").await
    }

    /// The daemon-side directories behind a session, so a test can check
    /// *where* a client's write landed rather than only that it round-trips.
    async fn session_paths(server: &TestServer, id: SessionId) -> SessionPaths {
        let mngr = server.state.sessions_manager().await;
        mngr.get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("session was just created")
            .paths()
            .await
            .unwrap()
    }

    /// Writes `payload` through the SFTP channel, failing the test on any
    /// error — the escape tests are the ones interested in error paths.
    async fn write(sftp: &SftpClient, path: &str, payload: &[u8]) {
        let mut file = sftp.create(path).await.unwrap();
        file.write_all(payload).await.unwrap();
        file.shutdown().await.unwrap();
    }

    /// Asserts a request was refused with `SSH_FX_PERMISSION_DENIED`, which
    /// is what every containment failure maps to on the wire.
    fn assert_denied<T>(result: Result<T, SftpClientError>) {
        match result {
            Err(SftpClientError::Status(s)) => {
                assert_eq!(s.status_code, StatusCode::PermissionDenied);
            }
            Err(e) => panic!("expected PermissionDenied, got error {e:?}"),
            Ok(_) => panic!("expected PermissionDenied, but the request succeeded"),
        }
    }

    #[tokio::test]
    async fn sftp_write_then_read_round_trips() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        let payload: &[u8] = b"hello from sftp";
        write(&sftp, "hello.txt", payload).await;

        let read_back = sftp.read("hello.txt").await.unwrap();
        assert_eq!(read_back, payload);

        // A relative path is the session's working tree, not its home.
        let paths = session_paths(&server, session_id).await;
        let on_disk = tokio::fs::read(paths.working.sub_path_unchecked("hello.txt").as_str())
            .await
            .unwrap();
        assert_eq!(on_disk, payload);
    }

    #[tokio::test]
    async fn sftp_presents_the_working_tree_and_home_side_by_side() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        // The two exports are named after the sandbox's own directories.
        assert_eq!(env::WORKSPACE_ROOT, "/workbench");
        assert_eq!(env::HOME_ROOT, "/home");

        write(&sftp, "/workbench/note.txt", b"in the workbench").await;
        write(&sftp, "/home/note.txt", b"in the home").await;

        // Same file name in each tree, and they do not collide.
        assert_eq!(
            sftp.read("/workbench/note.txt").await.unwrap(),
            b"in the workbench"
        );
        assert_eq!(sftp.read("/home/note.txt").await.unwrap(), b"in the home");

        // Each landed in the daemon directory the client's path named.
        let paths = session_paths(&server, session_id).await;
        let working = tokio::fs::read(paths.working.sub_path_unchecked("note.txt").as_str())
            .await
            .unwrap();
        assert_eq!(working, b"in the workbench");
        let home = tokio::fs::read(paths.home.sub_path_unchecked("note.txt").as_str())
            .await
            .unwrap();
        assert_eq!(home, b"in the home");
    }

    #[tokio::test]
    async fn sftp_root_lists_exactly_the_two_exports() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        let mut names: Vec<String> = sftp
            .read_dir("/")
            .await
            .unwrap()
            .map(|e| e.file_name())
            .collect();
        names.sort();
        assert_eq!(names, vec!["home".to_string(), "workbench".to_string()]);

        // The root is synthetic, but it has to look like a directory or
        // clients refuse to descend into it.
        assert!(sftp.metadata("/").await.unwrap().is_dir());
    }

    #[tokio::test]
    async fn sftp_root_states_only_its_mode() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;
        let attrs = sftp.metadata("/").await.unwrap();

        // The root has no inode, so mode is the only field it can honestly
        // state. The rest stay absent rather than being reported as zero —
        // `FileAttributes::default()` supplied dummy zeros before
        // russh-sftp 2.2, and a silent return to that would have root
        // claiming uid 0, size 0 and an epoch mtime.
        assert!(attrs.is_dir());
        assert_eq!(attrs.permissions.unwrap() & 0o7777, 0o555);
        assert_eq!(attrs.size, None);
        assert_eq!(attrs.uid, None);
        assert_eq!(attrs.gid, None);
        assert_eq!(attrs.atime, None);
        assert_eq!(attrs.mtime, None);
    }

    #[tokio::test]
    async fn sftp_realpath_reports_client_facing_paths() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        // SFTP clients ask `realpath(".")` immediately after connect to learn
        // where they start: that is the working tree.
        assert_eq!(sftp.canonicalize(".").await.unwrap(), env::WORKSPACE_ROOT);
        assert_eq!(sftp.canonicalize("/").await.unwrap(), "/");
        assert_eq!(
            sftp.canonicalize("sub/..").await.unwrap(),
            env::WORKSPACE_ROOT
        );
        // `..` is spent in the client's namespace, so the exports are
        // reachable from one another and the root is the ceiling.
        assert_eq!(
            sftp.canonicalize("/workbench/../home").await.unwrap(),
            env::HOME_ROOT
        );
        assert_eq!(sftp.canonicalize("/home/../..").await.unwrap(), "/");
    }

    #[tokio::test]
    async fn sftp_rejects_paths_outside_the_exports() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        // `..` resolves above the working tree, onto the synthetic root,
        // where `escape.txt` is not one of the two exports.
        assert_denied(
            sftp.open_with_flags(
                "../escape.txt",
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            )
            .await,
        );
        // Nothing else on the daemon's filesystem is addressable, spelled
        // absolutely or as a near-miss on an export's name.
        assert_denied(sftp.read("/etc/passwd").await);
        assert_denied(sftp.read("/workbenchevil/loot.txt").await);
        // The root itself is not a file, and cannot be unlinked or replaced.
        assert_denied(sftp.remove_dir("/").await);
        assert_denied(sftp.rename("/workbench", "/elsewhere").await);
    }

    #[tokio::test]
    async fn sftp_refuses_to_unlink_or_move_the_exports_themselves() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        // Both are empty, so the syscalls underneath would happily succeed
        // and take the session's layout with them.
        assert_denied(sftp.remove_dir("/workbench").await);
        assert_denied(sftp.remove_dir("/home").await);
        assert_denied(sftp.remove_file("/home").await);
        assert_denied(sftp.rename("/workbench", "/home").await);

        // Everything under them is still the client's to destroy.
        sftp.create_dir("/workbench/scratch").await.unwrap();
        sftp.remove_dir("/workbench/scratch").await.unwrap();

        let paths = session_paths(&server, session_id).await;
        assert!(tokio::fs::try_exists(paths.working.as_str()).await.unwrap());
        assert!(tokio::fs::try_exists(paths.home.as_str()).await.unwrap());
    }

    #[tokio::test]
    async fn sftp_rejects_paths_leaving_an_export_through_a_symlink() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let paths = session_paths(&server, session_id).await;

        // A directory outside both exports, with something worth stealing in
        // it, and a symlink to it planted in the working tree.
        let outside = paths
            .working
            .parent()
            .unwrap()
            .sub_path_unchecked("outside");
        tokio::fs::create_dir_all(outside.as_str()).await.unwrap();
        tokio::fs::write(outside.sub_path_unchecked("secret.txt").as_str(), b"secret")
            .await
            .unwrap();
        std::os::unix::fs::symlink(
            outside.as_str(),
            paths.working.sub_path_unchecked("escape").as_str(),
        )
        .unwrap();

        let sftp = client.open_sftp(session_id).await;

        // Reading through the link is refused...
        assert_denied(sftp.read("escape/secret.txt").await);
        // ...and so is creating a file through it, which no amount of
        // canonicalizing the target alone would catch: it does not exist yet.
        assert_denied(
            sftp.open_with_flags(
                "escape/planted.txt",
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            )
            .await,
        );
        assert!(
            !tokio::fs::try_exists(outside.sub_path_unchecked("planted.txt").as_str())
                .await
                .unwrap()
        );
    }

    /// `O_NOFOLLOW` on the final open guards the swap-the-leaf race, not
    /// links as such: a link inside an export is resolved by `resolve`, so
    /// what reaches `open` is its target and there is nothing left to refuse.
    #[tokio::test]
    async fn sftp_follows_symlinks_that_stay_inside_an_export() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let paths = session_paths(&server, session_id).await;

        tokio::fs::write(
            paths.working.sub_path_unchecked("target.txt").as_str(),
            b"through the link",
        )
        .await
        .unwrap();
        std::os::unix::fs::symlink(
            "target.txt",
            paths.working.sub_path_unchecked("link.txt").as_str(),
        )
        .unwrap();

        let sftp = client.open_sftp(session_id).await;

        assert_eq!(sftp.read("link.txt").await.unwrap(), b"through the link");
        assert_eq!(
            sftp.canonicalize("link.txt").await.unwrap(),
            "/workbench/target.txt"
        );

        // `setstat` opens the same way, so it lands on the target too.
        let attrs = russh_sftp::protocol::FileAttributes {
            permissions: Some(0o640),
            ..Default::default()
        };
        sftp.set_metadata("link.txt", attrs).await.unwrap();
        let mode = tokio::fs::metadata(paths.working.sub_path_unchecked("target.txt").as_str())
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[tokio::test]
    async fn sftp_setstat_leaves_the_owner_able_to_reach_what_it_chmodded() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let paths = session_paths(&server, session_id).await;

        let sftp = client.open_sftp(session_id).await;
        write(&sftp, "locked.txt", b"still readable").await;
        sftp.create_dir("/workbench/locked").await.unwrap();

        let chmod = async |path: &str, mode: u32| {
            let attrs = russh_sftp::protocol::FileAttributes {
                permissions: Some(mode),
                ..Default::default()
            };
            sftp.set_metadata(path, attrs).await.unwrap();
        };
        let mode_of = async |path: &paths::DaemonAbsPath| {
            tokio::fs::metadata(path.as_str())
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };

        // The door does not lock behind the client: a file keeps owner read,
        // a directory keeps owner list-and-traverse.
        chmod("locked.txt", 0o000).await;
        let file = paths.working.sub_path_unchecked("locked.txt");
        assert_eq!(mode_of(&file).await, 0o400);
        chmod("/workbench/locked", 0o000).await;
        let dir = paths.working.sub_path_unchecked("locked");
        assert_eq!(mode_of(&dir).await, 0o500);

        // Which means the request that undoes it still works...
        chmod("locked.txt", 0o644).await;
        assert_eq!(mode_of(&file).await, 0o644);
        // ...and reads through the floor'd mode never stopped working.
        assert_eq!(sftp.read("locked.txt").await.unwrap(), b"still readable");

        // Everything the client actually asked for survives: group and other
        // bits, write-protection, and the executable bit.
        chmod("locked.txt", 0o751).await;
        assert_eq!(mode_of(&file).await, 0o751);
        chmod("locked.txt", 0o444).await;
        assert_eq!(mode_of(&file).await, 0o444);
    }

    #[tokio::test]
    async fn sftp_rejects_creation_through_a_dangling_symlink() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let paths = session_paths(&server, session_id).await;

        // The link's target does not exist, so nothing on the way to it can
        // be canonicalized — the refusal has to come from the link itself.
        let target = paths
            .working
            .parent()
            .unwrap()
            .sub_path_unchecked("not-there.txt");
        std::os::unix::fs::symlink(
            target.as_str(),
            paths.working.sub_path_unchecked("dangling").as_str(),
        )
        .unwrap();

        let sftp = client.open_sftp(session_id).await;

        assert_denied(
            sftp.open_with_flags(
                "dangling",
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            )
            .await,
        );
        assert!(!tokio::fs::try_exists(target.as_str()).await.unwrap());
    }
}
