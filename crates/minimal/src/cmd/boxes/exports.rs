//! The copy of a box's declared `[[file_exports]]` back into its project,
//! made by the command that waited for the box to end (BOX-185). Each
//! export is a file or a folder at `/workbench/<path>` in the box's
//! retained filesystem, read through the same file service `min box cp`
//! reads. It is written to the same `<path>` under the project root.
//!
//! A folder export creates each folder of the tree, empty ones too, and
//! deletes nothing in the project (BOX-187). Each file goes to a temporary
//! name beside its destination and is then renamed into place (BOX-188).

use super::*;

/// The box's copy of the project, as `min box cp` names it.
const BOX_PROJECT_DIR: &str = "/workbench";

/// What a path in the box is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportKind {
    /// A file, or a link to one.
    File,
    /// A folder, or a link to one.
    Dir,
}

/// Why a read from the box failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExportReadError {
    /// Nothing is at the path.
    NotFound,
    /// The read failed. The text is the reason, as the stderr line says it.
    Failed(String),
}

/// The files of an ended box that an export reads.
pub(crate) trait ExportSource {
    /// What is at `path`, after links. [`ExportReadError::NotFound`] when
    /// nothing is there.
    async fn kind(&mut self, path: &str) -> Result<ExportKind, ExportReadError>;

    /// Each name in the folder `path`, with what it is. A name that is
    /// neither a file nor a folder is left out.
    async fn list(&mut self, path: &str) -> Result<Vec<(String, ExportKind)>, ExportReadError>;

    /// Writes all of the file `path` to `out`, and returns its bytes.
    async fn read_into(
        &mut self,
        path: &str,
        out: &mut (dyn std::io::Write + Send),
    ) -> Result<u64, ExportReadError>;

    /// One name for the folder `path` that two paths to the same folder
    /// share, so a walk through links visits each folder once. `None`
    /// when the source cannot tell, and then the path itself is used.
    async fn identity(&mut self, _path: &str) -> Option<String> {
        None
    }
}

/// One file an export wrote under the project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportedFile {
    /// The file's path, relative to the project root.
    pub path: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its sha256, in lowercase hex.
    pub sha256: String,
}

/// How one export went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportOutcome {
    /// The export's path, as the spec declares it.
    pub path: String,
    /// Whether every file and folder of the export was written.
    pub copied: bool,
    /// Each file this copy wrote for the export.
    pub files: Vec<ExportedFile>,
}

/// The export paths of a stored spec, in list order: each
/// `[[file_exports]]` item's `path`, or the item itself when it is a
/// string, as the expansion reads them ([`mfile::expand::file_export_path`]).
pub(crate) fn stored_export_paths(spec: &serde_json_lenient::Value) -> Vec<String> {
    let Some(items) = spec.get("file_exports").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item {
            serde_json_lenient::Value::String(path) => Some(path.clone()),
            serde_json_lenient::Value::Object(table) => table
                .get("path")
                .and_then(|p| p.as_str())
                .map(str::to_owned),
            _ => None,
        })
        .collect()
}

/// `path` with its `.` components and its trailing `/` taken out, as the
/// parts below the project root, or `None` for a path that the expansion
/// refuses (BOX-189).
fn export_parts(path: &str) -> Option<Vec<String>> {
    if !mfile::expand::export_path_in_project(path) {
        return None;
    }
    let parts = std::path::Path::new(path)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    Some(parts)
}

/// The tree of a folder export: each folder and each file below it, as
/// paths relative to the export, in the order the walk found them.
#[derive(Debug, Default)]
struct ExportTree {
    dirs: Vec<String>,
    files: Vec<String>,
}

/// Reads the whole tree below the folder `root` in the box before anything
/// is written. A folder reached twice, through a link, is read once.
async fn read_tree<S: ExportSource>(
    source: &mut S,
    root: &str,
) -> Result<ExportTree, ExportReadError> {
    let mut tree = ExportTree::default();
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(
        source
            .identity(root)
            .await
            .unwrap_or_else(|| root.to_owned()),
    );
    let mut pending = std::collections::VecDeque::from([String::new()]);
    while let Some(rel) = pending.pop_front() {
        let dir = if rel.is_empty() {
            root.to_owned()
        } else {
            format!("{root}/{rel}")
        };
        let mut names = source.list(&dir).await?;
        names.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, kind) in names {
            if name == "." || name == ".." || name.contains('/') {
                continue;
            }
            let child = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            match kind {
                ExportKind::File => tree.files.push(child),
                ExportKind::Dir => {
                    let full = format!("{root}/{child}");
                    let id = source.identity(&full).await.unwrap_or(full);
                    if seen.insert(id) {
                        tree.dirs.push(child.clone());
                        pending.push_back(child);
                    }
                }
            }
        }
    }
    Ok(tree)
}

/// A writer that counts and hashes what passes through it.
struct HashingWriter<'a> {
    inner: &'a mut std::fs::File,
    hasher: sha2::Sha256,
    bytes: u64,
}

impl std::io::Write for HashingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        let written = buf.get(..n).unwrap_or_default();
        sha2::Digest::update(&mut self.hasher, written);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Writes the box's file `src` to `dest`: to a new file beside `dest`
/// under a temporary name, renamed into place once the whole file is
/// there (BOX-188). A copy that fails leaves `dest` as it was and removes
/// the temporary file.
async fn write_file_atomically<S: ExportSource>(
    source: &mut S,
    src: &str,
    dest: &std::path::Path,
) -> Result<(u64, String), String> {
    let dir = match dest.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => std::path::Path::new("."),
    };
    let name = dest
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let prefix = format!(".{name}.min-export-");
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    // The umask applies to this mode, as it does to `File::create`, so the
    // file gets the default mode and not the 0600 of a temporary file.
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
    let (mut file, partial) = builder
        .tempfile_in(dir)
        .map_err(|e| format!("could not write {}: {e}", dest.display()))?
        .into_parts();
    let mut out = HashingWriter {
        inner: &mut file,
        hasher: <sha2::Sha256 as sha2::Digest>::new(),
        bytes: 0,
    };
    match source.read_into(src, &mut out).await {
        Ok(_) => {}
        Err(ExportReadError::NotFound) => {
            return Err(format!("{src} is no longer in the box"));
        }
        Err(ExportReadError::Failed(reason)) => return Err(reason),
    }
    std::io::Write::flush(&mut out)
        .map_err(|e| format!("could not write {}: {e}", dest.display()))?;
    let bytes = out.bytes;
    let sha256 = hex::encode(sha2::Digest::finalize(out.hasher));
    drop(file);
    partial
        .persist(dest)
        .map_err(|e| format!("could not write {}: {}", dest.display(), e.error))?;
    Ok((bytes, sha256))
}

/// Copies each export in `paths` from `source` to the same path under
/// `project_root`, and returns how each one went. A skipped or failed
/// export gets one line on `err` that names its path, and the copy goes on
/// with the next export. `label` names the box in those lines.
pub(crate) async fn copy_exports<S, E>(
    source: &mut S,
    paths: &[String],
    project_root: &std::path::Path,
    label: &str,
    err: &mut E,
) -> Vec<ExportOutcome>
where
    S: ExportSource,
    E: std::io::Write,
{
    let mut outcomes = Vec::with_capacity(paths.len());
    for path in paths {
        let mut outcome = ExportOutcome {
            path: path.clone(),
            copied: false,
            files: Vec::new(),
        };
        let reason = copy_one(source, path, project_root, &mut outcome).await;
        match &reason {
            None => outcome.copied = true,
            Some(line) => {
                let _ = writeln!(err, "{}", line.text(path, label));
            }
        }
        tracing::info!(
            box_label = label,
            export = %path,
            copied = outcome.copied,
            files = outcome.files.len(),
            "file export"
        );
        outcomes.push(outcome);
    }
    outcomes
}

/// Why an export was not copied, as its stderr line says it.
enum NotCopied {
    /// The path points outside the project folder.
    Outside,
    /// The box has nothing at the path.
    NotFound,
    /// A read or a write failed, with the reason.
    Failed(String),
}

impl NotCopied {
    fn text(&self, path: &str, label: &str) -> String {
        match self {
            NotCopied::Outside => format!(
                "min did not copy `{path}` from box {label}, because the path points \
                 outside the folder that holds minimal.toml."
            ),
            NotCopied::NotFound => format!(
                "min did not copy `{path}` from box {label}, because it was not found in the box."
            ),
            NotCopied::Failed(reason) => {
                format!("min did not copy all of `{path}` from box {label}: {reason}.")
            }
        }
    }
}

/// Copies the one export `path`, and adds each file it wrote to `outcome`.
async fn copy_one<S: ExportSource>(
    source: &mut S,
    path: &str,
    project_root: &std::path::Path,
    outcome: &mut ExportOutcome,
) -> Option<NotCopied> {
    let Some(parts) = export_parts(path) else {
        return Some(NotCopied::Outside);
    };
    let rel = parts.join("/");
    let src = format!("{BOX_PROJECT_DIR}/{rel}");
    let dest = parts
        .iter()
        .fold(project_root.to_path_buf(), |dest, part| dest.join(part));
    let kind = match source.kind(&src).await {
        Ok(kind) => kind,
        Err(ExportReadError::NotFound) => return Some(NotCopied::NotFound),
        Err(ExportReadError::Failed(reason)) => return Some(NotCopied::Failed(reason)),
    };
    match kind {
        ExportKind::File => {
            if let Some(parent) = dest.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return Some(NotCopied::Failed(format!(
                    "could not create the folder {}: {e}",
                    parent.display()
                )));
            }
            match write_file_atomically(source, &src, &dest).await {
                Ok((size, sha256)) => {
                    outcome.files.push(ExportedFile {
                        path: rel,
                        size,
                        sha256,
                    });
                    None
                }
                Err(reason) => Some(NotCopied::Failed(reason)),
            }
        }
        ExportKind::Dir => {
            let tree = match read_tree(source, &src).await {
                Ok(tree) => tree,
                Err(ExportReadError::NotFound) => {
                    return Some(NotCopied::Failed(format!(
                        "a folder inside {src} is no longer in the box"
                    )));
                }
                Err(ExportReadError::Failed(reason)) => return Some(NotCopied::Failed(reason)),
            };
            let mut failed = None;
            if let Err(e) = std::fs::create_dir_all(&dest) {
                return Some(NotCopied::Failed(format!(
                    "could not create the folder {}: {e}",
                    dest.display()
                )));
            }
            for dir in &tree.dirs {
                let target = dest.join(dir);
                if let Err(e) = std::fs::create_dir_all(&target) {
                    failed.get_or_insert_with(|| {
                        format!("could not create the folder {}: {e}", target.display())
                    });
                }
            }
            for file in &tree.files {
                let target = dest.join(file);
                match write_file_atomically(source, &format!("{src}/{file}"), &target).await {
                    Ok((size, sha256)) => outcome.files.push(ExportedFile {
                        path: format!("{rel}/{file}"),
                        size,
                        sha256,
                    }),
                    Err(reason) => {
                        failed.get_or_insert(reason);
                    }
                }
            }
            failed.map(NotCopied::Failed)
        }
    }
}

/// The box's files, read through the box's file service, as `min box cp`
/// reads them.
struct BoxFiles {
    sftp: russh_sftp::client::SftpSession,
}

/// The reason a read from the box failed, for the stderr line.
fn read_error(path: &str, e: &russh_sftp::client::error::Error) -> ExportReadError {
    use russh_sftp::protocol::StatusCode;
    match e {
        russh_sftp::client::error::Error::Status(status)
            if status.status_code == StatusCode::NoSuchFile =>
        {
            ExportReadError::NotFound
        }
        russh_sftp::client::error::Error::Status(status)
            if status.status_code == StatusCode::PermissionDenied =>
        {
            ExportReadError::Failed(format!("the box did not allow min to read {path}"))
        }
        other => {
            tracing::warn!(path, "read the box's file: {other}");
            ExportReadError::Failed(format!("could not read {path} from the box"))
        }
    }
}

impl ExportSource for BoxFiles {
    async fn kind(&mut self, path: &str) -> Result<ExportKind, ExportReadError> {
        let meta = self
            .sftp
            .metadata(path)
            .await
            .map_err(|e| read_error(path, &e))?;
        if meta.file_type().is_dir() {
            Ok(ExportKind::Dir)
        } else {
            Ok(ExportKind::File)
        }
    }

    async fn list(&mut self, path: &str) -> Result<Vec<(String, ExportKind)>, ExportReadError> {
        let entries = self
            .sftp
            .read_dir(path)
            .await
            .map_err(|e| read_error(path, &e))?;
        let mut names = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let file_type = entry.file_type();
            let kind = if file_type.is_dir() {
                ExportKind::Dir
            } else if file_type.is_file() {
                ExportKind::File
            } else if file_type.is_symlink() {
                // The file service refuses a link that leaves the box's
                // folders, so a link it follows stays inside them.
                match self.kind(&format!("{path}/{name}")).await {
                    Ok(kind) => kind,
                    Err(e) => return Err(e),
                }
            } else {
                tracing::debug!(
                    path,
                    name,
                    "a file export skips an entry that is not a file or a folder"
                );
                continue;
            };
            names.push((name, kind));
        }
        Ok(names)
    }

    async fn read_into(
        &mut self,
        path: &str,
        out: &mut (dyn std::io::Write + Send),
    ) -> Result<u64, ExportReadError> {
        let mut file = self
            .sftp
            .open(path)
            .await
            .map_err(|e| read_error(path, &e))?;
        let mut buf = vec![0_u8; 64 * 1024];
        let mut copied = 0_u64;
        loop {
            let n = file.read(&mut buf).await.map_err(|e| {
                tracing::warn!(path, copied, "read the box's file: {e}");
                ExportReadError::Failed(format!("could not read all of {path} from the box"))
            })?;
            let Some(chunk) = buf.get(..n).filter(|chunk| !chunk.is_empty()) else {
                break;
            };
            out.write_all(chunk)
                .map_err(|e| ExportReadError::Failed(format!("could not write {path}: {e}")))?;
            copied += n as u64;
        }
        drop(file.shutdown().await);
        Ok(copied)
    }

    async fn identity(&mut self, path: &str) -> Option<String> {
        self.sftp.canonicalize(path).await.ok()
    }
}

/// Copies the declared exports of the ended box `id` on `host` into
/// `project_root`, the project the box came from (BOX-185). `label` names
/// the box on `err`. A box whose spec declares no export copies nothing,
/// and reads nothing more from its host.
pub(crate) async fn copy_box_exports_on_host<E: std::io::Write>(
    host: &crate::cmd::list::LocalHost,
    id: boxes::SessionId,
    label: &str,
    project_root: Option<&std::path::Path>,
    err: &mut E,
) -> Vec<ExportOutcome> {
    let mut client = match box_host_client(host).await {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: could not reach the box's host: {e:#}");
            return Vec::new();
        }
    };
    copy_box_exports(&mut client, id, label, project_root, err).await
}

/// [`copy_box_exports_on_host`] over a connected `client`.
pub(crate) async fn copy_box_exports<E: std::io::Write>(
    client: &mut client::Client,
    id: boxes::SessionId,
    label: &str,
    project_root: Option<&std::path::Path>,
    err: &mut E,
) -> Vec<ExportOutcome> {
    use minimald_rpc::{Errorable, GetBoxSpec, GetBoxSpecRequest};

    let spec = match client
        .oneshot_rpc::<GetBoxSpec>(GetBoxSpecRequest { id })
        .await
    {
        Ok(Errorable::Ok(reply)) => reply.spec,
        Ok(Errorable::Err { error }) => {
            // A box that its host removed, such as a task with no spec of
            // its own, keeps no files to copy.
            tracing::info!(box_id = %id, "file exports: the box's spec is not readable: {error}");
            None
        }
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: could not read the box's spec: {e:#}");
            None
        }
    };
    let paths = spec.as_ref().map(stored_export_paths).unwrap_or_default();
    if paths.is_empty() {
        return Vec::new();
    }
    let not_copied = |err: &mut E, reason: &str| {
        for path in &paths {
            let _ = writeln!(
                err,
                "min did not copy `{path}` from box {label}, because {reason}."
            );
        }
        paths
            .iter()
            .map(|path| ExportOutcome {
                path: path.clone(),
                copied: false,
                files: Vec::new(),
            })
            .collect::<Vec<_>>()
    };
    let Some(project_root) = project_root else {
        tracing::warn!(box_id = %id, "file exports: the box's record names no project folder");
        return not_copied(err, "the box's record names no project folder");
    };
    let channel = match client.open_box_subsystem(id, "sftp").await {
        Ok(channel) => channel,
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: open the box's files: {e:#}");
            return not_copied(err, "min could not read the box's files");
        }
    };
    let sftp = match russh_sftp::client::SftpSession::new(channel.into_stream()).await {
        Ok(sftp) => sftp,
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: start the file conversation: {e}");
            return not_copied(err, "min could not read the box's files");
        }
    };
    let mut files = BoxFiles { sftp };
    copy_exports(&mut files, &paths, project_root, label, err).await
}
