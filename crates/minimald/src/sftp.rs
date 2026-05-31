//! SFTP subsystem handler.
//!
//! One [`SftpSession`] is constructed per `sftp` subsystem request and handed
//! to [`russh_sftp::server::run`], which owns the dispatch loop. The handler
//! holds owned per-channel state — no inner actor — because dispatch through
//! `run` is already serialised.
//!
//! Every client-supplied path is funnelled through [`SftpSession::resolve`],
//! which joins it against the session workspace, runs it through
//! [`path_absolutize::Absolutize`], and rejects anything that escapes the
//! workspace prefix. The client therefore sees the workspace as `/`.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use path_absolutize::Absolutize;
use russh::ChannelId;
use russh::server::Session;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use sessions::paths::DaemonAbsPath;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::task::spawn;
use uuid::Uuid;

use crate::connection::{ConnectionError, ConnectionHandle};
use crate::server::ServerStateHandle;
use crate::sessions::SessionKeyPredicate;

/// The SSH subsystem name used to negotiate an SFTP channel.
pub const SUBSYSTEM_NAME: &str = "sftp";

/// Env var that the client must set (via `env_request`) before the SFTP
/// subsystem request, naming which session the SFTP channel attaches to.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Cap on how many directory entries are returned per `readdir` call.
/// SFTP clients call `readdir` repeatedly until they see `SSH_FX_EOF`, so
/// batching keeps individual packets within typical SFTP size limits.
const READDIR_BATCH: usize = 100;

const MAX_READ_LEN: usize = 128 * 1024;

/// Error returned by SFTP handler methods.
///
/// `russh_sftp` requires only `Into<StatusCode>`: every failed request maps
/// to a single `SSH_FXP_STATUS` packet, so we lose any structured detail at
/// the wire boundary regardless. The enum exists so the handler can report
/// the *cause* in logs even though the wire only carries a status code.
#[derive(Debug)]
pub enum SftpError {
    Io(std::io::Error),
    /// Client-supplied path resolved outside the workspace root.
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

/// An SFTP handle id refers to either an open file or a snapshot of a
/// directory listing. Using an enum (rather than two parallel maps) keeps
/// "handle id of the wrong kind" representable as a single lookup.
enum OpenHandle {
    File(fs::File),
    /// Remaining unread directory entries; drained in `READDIR_BATCH`-sized
    /// chunks by `readdir`, then `SSH_FX_EOF` on the next call.
    Dir(Vec<File>),
}

/// Per-channel SFTP server scoped to a single session's workspace.
pub struct SftpSession {
    /// Cached at construction because the session contract guarantees
    /// `workspace_path()` is stable for the session lifetime — fetching it
    /// per-request would round-trip through the session actor for nothing.
    workspace: DaemonAbsPath,
    handles: HashMap<String, OpenHandle>,
    next_handle_id: u64,
}

impl SftpSession {
    /// Construct a handler scoped to the given session workspace.
    pub fn new(workspace: DaemonAbsPath) -> Self {
        Self {
            workspace,
            handles: HashMap::new(),
            next_handle_id: 0,
        }
    }

    /// Resolves a client-supplied SFTP path to a host path, rejecting any
    /// resolution that escapes the workspace root.
    ///
    /// SFTP clients address the workspace as if it were the filesystem root,
    /// so a leading `/` is purely cosmetic and is stripped before joining.
    /// `absolutize` collapses interior `.`/`..` without touching the disk;
    /// the prefix check then guarantees the result is still under workspace.
    async fn resolve(&self, sftp_path: &str) -> Result<PathBuf, SftpError> {
        let workspace: &Path = self.workspace.as_ref();
        let rel = sftp_path.trim_start_matches('/');
        let candidate = workspace.join(rel);
        let resolved = candidate.absolutize().map_err(SftpError::Io)?;
        if !resolved.starts_with(workspace) {
            return Err(SftpError::PathTraversal);
        }
        // Canonicalize, but ignore file not found errors.
        match tokio::fs::canonicalize(&resolved).await {
            Ok(canon_path) => {
                if !canon_path.starts_with(workspace) {
                    Err(SftpError::PathTraversal)
                } else {
                    Ok(canon_path)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(resolved.into_owned()),
            Err(e) => Err(SftpError::Io(e)),
        }
    }

    /// Converts a resolved host path back into the client-facing form, with
    /// the workspace appearing as `/`.
    fn client_path(&self, host: &Path) -> String {
        let workspace: &Path = self.workspace.as_ref();
        match host.strip_prefix(workspace) {
            Ok(rel) if rel.as_os_str().is_empty() => "/".to_string(),
            Ok(rel) => format!("/{}", rel.to_string_lossy()),
            Err(_) => "/".to_string(),
        }
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

impl russh_sftp::server::Handler for SftpSession {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError::Unsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let host = self.resolve(&path).await?;
        Ok(Name {
            id,
            files: vec![File::dummy(self.client_path(&host))],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let host = self.resolve(&path).await?;
        let m = fs::metadata(host).await?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let host = self.resolve(&path).await?;
        let m = fs::symlink_metadata(host).await?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
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
        let host = self.resolve(&filename).await?;
        let mut opts = OpenOptions::new();
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
        let f = opts.open(host).await?;
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
        let host = self.resolve(&path).await?;
        let mut entries = Vec::new();

        let m = fs::metadata(&host).await?;
        entries.push(File::new(".".to_string(), FileAttributes::from(&m)));
        if let Some(parent) = host.parent() {
            let workspace: &Path = self.workspace.as_ref();
            // Omit ".." at the workspace root so the client can't see it
            // exists above its root.
            if parent.starts_with(workspace) {
                let pm = fs::metadata(parent).await?;
                entries.push(File::new("..".to_string(), FileAttributes::from(&pm)));
            }
        }

        let mut read = fs::read_dir(&host).await?;
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
        let host = self.resolve(&path).await?;
        fs::create_dir(host).await?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let host = self.resolve(&path).await?;
        fs::remove_dir(host).await?;
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let host = self.resolve(&filename).await?;
        fs::remove_file(host).await?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let from = self.resolve(&oldpath).await?;
        let to = self.resolve(&newpath).await?;
        fs::rename(from, to).await?;
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let host = self.resolve(&path).await?;
        if let Some(perms) = perm_from_mode(attrs.permissions) {
            fs::set_permissions(host, perms).await?;
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
    let Ok(session_uuid) = Uuid::parse_str(session_id_str) else {
        tracing::warn!(
            value = %session_id_str,
            "sftp subsystem rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
        );
        session.channel_failure(id)?;
        return Ok(());
    };

    let mngr = s.sessions_manager().await;
    let session_handle = match mngr
        .get_session(SessionKeyPredicate::Id(session_uuid))
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!(%session_uuid, "sftp subsystem rejected: unknown session");
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(%session_uuid, error = %e, "sftp subsystem rejected: lookup failed");
            session.channel_failure(id)?;
            return Ok(());
        }
    };
    let workspace = session_handle.workspace_path().await;

    session.channel_success(id)?;
    spawn(russh_sftp::server::run(
        channel.into_stream(),
        SftpSession::new(workspace),
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use russh_sftp::client::error::Error as SftpClientError;
    use russh_sftp::protocol::{OpenFlags, StatusCode};
    use sessions::paths::HostAbsPath;
    use tokio::io::AsyncWriteExt;
    use uuid::Uuid;

    use crate::rpc::{CreateSession, CreateSessionRequest};
    use crate::test_harness::TestServer;

    /// Creates a fresh session through the public CreateSession RPC and
    /// returns its uuid, mirroring how a real client would set things up
    /// before opening an SFTP channel.
    async fn fresh_session(client: &mut crate::test_harness::TestClient) -> Uuid {
        client
            .call::<CreateSession>(&CreateSessionRequest {
                record: sessions::Record {
                    id: Uuid::nil(),
                    name: Some("sftp-test".to_string()),
                    username: None,
                    project_path: HostAbsPath::try_new("/tmp").unwrap(),
                    attrs: Default::default(),
                },
            })
            .await
            .id
    }

    #[tokio::test]
    async fn sftp_write_then_read_round_trips() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        let payload: &[u8] = b"hello from sftp";
        let mut file = sftp.create("hello.txt").await.unwrap();
        file.write_all(payload).await.unwrap();
        file.shutdown().await.unwrap();

        let read_back = sftp.read("hello.txt").await.unwrap();
        assert_eq!(read_back, payload);
    }

    #[tokio::test]
    async fn sftp_realpath_root_is_workspace_root() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        // SFTP clients ask `realpath(".")` immediately after connect to learn
        // their root; the server should always present the workspace as `/`.
        let resolved = sftp.canonicalize(".").await.unwrap();
        assert_eq!(resolved, "/");
    }

    #[tokio::test]
    async fn sftp_rejects_paths_escaping_workspace() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let sftp = client.open_sftp(session_id).await;

        // `..` resolves above the workspace root; the resolver must reject
        // it before any open()/stat() touches the host filesystem.
        let result = sftp
            .open_with_flags(
                "../escape.txt",
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            )
            .await;
        match result {
            Err(SftpClientError::Status(s)) => {
                assert_eq!(s.status_code, StatusCode::PermissionDenied);
            }
            Err(e) => panic!("expected PermissionDenied, got error {e:?}"),
            Ok(_) => panic!("expected PermissionDenied, but open succeeded"),
        }
    }
}
