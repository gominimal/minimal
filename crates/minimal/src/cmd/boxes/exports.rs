//! The copy of a box's declared `[[file_exports]]` back into its project,
//! made by the command that waited for the box to end (BOX-185). Each
//! export is a file or a folder at `/workbench/<path>` in the box's
//! retained filesystem, read through the same file service `min box cp`
//! reads. It is written to the same `<path>` under the project root.
//!
//! A folder export creates each folder of the tree, empty ones too, and
//! deletes nothing in the project (BOX-187). Each file goes to a temporary
//! name beside its destination and is then renamed into place (BOX-188).
//!
//! The copy claims the exports of the box's end from the box's host first,
//! and copies only those the host grants (BOX-198). It reports each export
//! it finishes, and the host records a `file_exported` event (BOX-195).

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
    /// share, so a walk through links stops at a link to an ancestor. `None`
    /// when the source cannot tell, and then the path itself is used.
    async fn identity(&mut self, _path: &str) -> Option<String> {
        None
    }

    /// The permission bits of the file `path`, after links. `None` when
    /// the source cannot tell.
    async fn mode(&mut self, _path: &str) -> Option<u32> {
        None
    }

    /// The path in the box that `path` leads to after every link in it.
    async fn resolve(&mut self, path: &str) -> Result<String, ExportReadError> {
        Ok(path.to_owned())
    }
}

/// Whether the resolved path `path` in the box is in the box's copy of the
/// project (BOX-196).
fn in_box_project(path: &str) -> bool {
    path == BOX_PROJECT_DIR
        || path
            .strip_prefix(BOX_PROJECT_DIR)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `path` with each `..` taken out against the part before it, and each
/// `.` taken out, with no look at the disk.
fn lexical(path: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// The path on this machine that a write to `path` reaches: the deepest
/// part of `path` that exists, with every link in it resolved, and the
/// rest of `path` after it. A link to nothing is followed to its target.
/// `None` when a link cannot be resolved, as for a loop.
fn resolve_dest(path: &std::path::Path, links: u8) -> Option<std::path::PathBuf> {
    for part in path.ancestors() {
        if part.as_os_str().is_empty() {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(part) else {
            continue;
        };
        let rest = path.strip_prefix(part).ok()?;
        return match std::fs::canonicalize(part) {
            Ok(real) => Some(lexical(&real.join(rest))),
            Err(_) if meta.file_type().is_symlink() && links > 0 => {
                let target = std::fs::read_link(part).ok()?;
                let target = match part.parent() {
                    Some(parent) if target.is_relative() => parent.join(target),
                    _ => target,
                };
                resolve_dest(&target.join(rest), links - 1)
            }
            Err(_) => None,
        };
    }
    None
}

/// Checks that each of `dests` reaches a path inside `project_root` after
/// links (BOX-192). `Some` is why the export is not copied.
fn check_dests(project_root: &std::path::Path, dests: &[std::path::PathBuf]) -> Option<NotCopied> {
    let root = match std::fs::canonicalize(project_root) {
        Ok(root) => root,
        Err(e) => {
            return Some(NotCopied::Failed(format!(
                "could not read the project folder {}: {e}",
                project_root.display()
            )));
        }
    };
    for dest in dests {
        match resolve_dest(dest, 40) {
            Some(real) if real.starts_with(&root) && real != root => {}
            Some(real) => {
                tracing::info!(
                    dest = %dest.display(),
                    resolved = %real.display(),
                    "a file export destination leads outside the project folder"
                );
                return Some(NotCopied::LeadsOutsideProject);
            }
            None => {
                return Some(NotCopied::Failed(format!(
                    "could not resolve the links in {}",
                    dest.display()
                )));
            }
        }
    }
    None
}

/// Checks that each of `srcs` in the box leads to a path in the box's copy
/// of the project after links (BOX-196). `Some` is why the export is not
/// copied.
async fn check_sources<S: ExportSource>(source: &mut S, srcs: &[String]) -> Option<NotCopied> {
    for src in srcs {
        match source.resolve(src).await {
            Ok(real) if in_box_project(&real) => {}
            Ok(real) => {
                tracing::info!(
                    src = %src,
                    resolved = %real,
                    "a file export source leads outside /workbench"
                );
                return Some(NotCopied::LeadsOutsideBox);
            }
            Err(ExportReadError::NotFound) => {
                return Some(NotCopied::Failed(format!("{src} is no longer in the box")));
            }
            Err(ExportReadError::Failed(reason)) => return Some(NotCopied::Failed(reason)),
        }
    }
    None
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

/// The exit code of a command whose box's entrypoint exited 0 when the
/// command skipped one of the box's exports (BOX-193). It is the code
/// that a run-style command gives to a failure on `min`'s side.
pub(crate) const EXPORT_SKIPPED_EXIT_CODE: u8 = 125;

/// Whether any export in `outcomes` was skipped. An export that wrote
/// only part of its files is skipped (BOX-191).
pub(crate) fn any_export_skipped(outcomes: &[ExportOutcome]) -> bool {
    outcomes.iter().any(|outcome| !outcome.copied)
}

/// The exit code of a command that copied a box's exports, from `code`,
/// the code it gives without exports. `entrypoint_succeeded` is true only
/// when the box's entrypoint exited 0, and the box did not time out, run
/// out of memory or get stopped. Then a skipped export turns `code` into
/// [`EXPORT_SKIPPED_EXIT_CODE`] (BOX-193). Every other code stands
/// (BOX-194). The box's record keeps the entrypoint's own code (BOX-197).
pub(crate) fn exit_code_after_exports(
    code: i32,
    entrypoint_succeeded: bool,
    outcomes: &[ExportOutcome],
) -> i32 {
    if code == 0 && entrypoint_succeeded && any_export_skipped(outcomes) {
        tracing::info!(
            skipped = outcomes.iter().filter(|outcome| !outcome.copied).count(),
            "a file export was skipped; the command exits 125 in place of 0"
        );
        i32::from(EXPORT_SKIPPED_EXIT_CODE)
    } else {
        code
    }
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
/// is written. Each path to a folder is read, so a link to a sibling folder
/// copies that folder under both names (BOX-187). A link back to a folder on
/// the current path, an ancestor, is not followed, so a loop ends.
async fn read_tree<S: ExportSource>(
    source: &mut S,
    root: &str,
) -> Result<ExportTree, ExportReadError> {
    let mut tree = ExportTree::default();
    let root_id = source
        .identity(root)
        .await
        .unwrap_or_else(|| root.to_owned());
    // Each folder still to read, with the identities of the folders on its
    // path from `root`, itself included.
    let mut pending = std::collections::VecDeque::from([(String::new(), vec![root_id])]);
    while let Some((rel, ancestors)) = pending.pop_front() {
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
                    if ancestors.contains(&id) {
                        tracing::info!(
                            path = %child,
                            "a folder export link leads back to a folder above it, not followed"
                        );
                        continue;
                    }
                    let mut path = ancestors.clone();
                    path.push(id);
                    tree.dirs.push(child.clone());
                    pending.push_back((child, path));
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
    // The file gets the permission bits of the box's file, so an exported
    // executable stays executable. When the box does not say, the file
    // gets the default mode and not the 0600 of a temporary file. The
    // umask applies to either mode, as it does to `cp`.
    let mode = source.mode(src).await.map_or(0o666, |mode| mode & 0o777);
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(mode));
    #[cfg(not(unix))]
    let _ = mode;
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

/// Where a copy sends how each export went (BOX-195).
pub(crate) trait ExportReporter {
    /// Reports `outcome`. `Err` holds the reason, for the log.
    async fn report(&mut self, outcome: &ExportOutcome) -> Result<(), String>;
}

/// A reporter that tells no one, for a copy that claimed nothing.
#[cfg(test)]
pub(crate) struct NoReport;

#[cfg(test)]
impl ExportReporter for NoReport {
    async fn report(&mut self, _outcome: &ExportOutcome) -> Result<(), String> {
        Ok(())
    }
}

/// Copies each export in `paths` from `source` to the same path under
/// `project_root`, and returns how each one went. A skipped or failed
/// export gets one line on `err` that names its path, and the copy goes on
/// with the next export. `label` names the box in those lines. It
/// reports nothing.
#[cfg(test)]
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
    copy_and_report_exports(source, paths, project_root, label, err, &mut NoReport).await
}

/// [`copy_exports`], with each export reported to `reporter` as soon as it
/// is done (BOX-195). A report that fails gets one line on `err` that
/// names the export (BOX-200), and the export keeps its outcome. The copy
/// then stops, because the command cannot tell a lost report from a lost
/// connection, and a lost connection releases the claim on each export
/// not yet reported (BOX-202). Each export not copied for this reason gets
/// one line on `err`, and no outcome.
pub(crate) async fn copy_and_report_exports<S, E, R>(
    source: &mut S,
    paths: &[String],
    project_root: &std::path::Path,
    label: &str,
    err: &mut E,
    reporter: &mut R,
) -> Vec<ExportOutcome>
where
    S: ExportSource,
    E: std::io::Write,
    R: ExportReporter,
{
    let mut outcomes = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let mut outcome = ExportOutcome {
            path: path.clone(),
            copied: false,
            files: Vec::new(),
        };
        let reason = copy_one(source, path, project_root, &mut outcome).await;
        match &reason {
            None => outcome.copied = true,
            Some(line) => {
                let _ = writeln!(err, "{}", line.text(path));
            }
        }
        tracing::info!(
            box_label = label,
            export = %path,
            copied = outcome.copied,
            files = outcome.files.len(),
            "file export"
        );
        let reported = reporter.report(&outcome).await;
        outcomes.push(outcome);
        if let Err(reason) = reported {
            tracing::warn!(
                box_label = label,
                export = %path,
                "file export: the report to the box's host failed, so the copy stops: {reason}"
            );
            let _ = writeln!(err, "{}", report_lost_line(path, label));
            for rest in paths.iter().skip(index + 1) {
                let _ = writeln!(err, "{}", copy_stopped_line(rest, label));
            }
            break;
        }
    }
    outcomes
}

/// Names each granted export in `paths` on `err` as not copied, for
/// `reason`, and reports each one to `reporter` with no files (BOX-195).
/// A report that fails gets one line on `err` (BOX-200), and the reports
/// stop there: the end of the connection releases the rest (BOX-202).
pub(crate) async fn report_not_copied<E, R>(
    reporter: &mut R,
    paths: &[String],
    label: &str,
    reason: &str,
    err: &mut E,
) -> Vec<ExportOutcome>
where
    E: std::io::Write,
    R: ExportReporter,
{
    let mut outcomes = Vec::with_capacity(paths.len());
    let mut reporting = true;
    for path in paths {
        let _ = writeln!(err, "Export {path} was not copied: {reason}.");
        let outcome = ExportOutcome {
            path: path.clone(),
            copied: false,
            files: Vec::new(),
        };
        if reporting && let Err(why) = reporter.report(&outcome).await {
            tracing::warn!(
                box_label = label,
                export = %path,
                "file export: the report to the box's host failed: {why}"
            );
            let _ = writeln!(err, "{}", report_lost_line(path, label));
            reporting = false;
        }
        outcomes.push(outcome);
    }
    outcomes
}

/// The stderr line for an export whose report the box's host did not
/// confirm (BOX-200).
pub(crate) fn report_lost_line(path: &str, label: &str) -> String {
    format!(
        "min could not confirm that the record of box {label} holds an entry for export `{path}`."
    )
}

/// The stderr line for an export that a copy did not reach, because an
/// earlier report failed (BOX-202). The command's connection ends when it
/// exits, and that releases the export for the next wait.
pub(crate) fn copy_stopped_line(path: &str, label: &str) -> String {
    format!(
        "Export {path} was not copied: min could not confirm an earlier export with \
         the box's host. Run `min box wait {label}` in this project to copy it."
    )
}

/// The stderr line for an export that another command claimed for this
/// end of the box (BOX-201). The other command holds the claim or reported
/// the export, copied or not, so the line does not say that it was copied.
pub(crate) fn claimed_elsewhere_line(path: &str, label: &str) -> String {
    format!(
        "Export {path} was not copied: another min command holds it or has already \
         reported its result. Run `min box events {label}` to see that result."
    )
}

/// Why an export was not copied, as its stderr line says it.
enum NotCopied {
    /// The path points outside the project folder.
    Outside,
    /// A destination leads through a link outside the project folder
    /// (BOX-192).
    LeadsOutsideProject,
    /// A source in the box leads through a link outside `/workbench`
    /// (BOX-196).
    LeadsOutsideBox,
    /// The box has nothing at the path.
    NotFound,
    /// A read or a write failed, with the reason.
    Failed(String),
}

impl NotCopied {
    // BOX-190, BOX-191: every skip line has the one form
    // `Export <path> was not copied: <why>.`
    fn text(&self, path: &str) -> String {
        let why = match self {
            NotCopied::Outside | NotCopied::LeadsOutsideProject => {
                "it leads outside the project folder"
            }
            NotCopied::LeadsOutsideBox => "it leads outside the box's copy of the project",
            NotCopied::NotFound => "it was not found in the box",
            NotCopied::Failed(reason) => reason.as_str(),
        };
        format!("Export {path} was not copied: {why}.")
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
            if let Some(refused) = check_sources(source, std::slice::from_ref(&src)).await {
                return Some(refused);
            }
            if let Some(refused) = check_dests(project_root, std::slice::from_ref(&dest)) {
                return Some(refused);
            }
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
            // Every source and every destination is checked before the
            // first write, so a refused export writes nothing.
            let srcs: Vec<String> = std::iter::once(src.clone())
                .chain(tree.dirs.iter().map(|dir| format!("{src}/{dir}")))
                .chain(tree.files.iter().map(|file| format!("{src}/{file}")))
                .collect();
            if let Some(refused) = check_sources(source, &srcs).await {
                return Some(refused);
            }
            let dests: Vec<std::path::PathBuf> = std::iter::once(dest.clone())
                .chain(tree.dirs.iter().map(|dir| dest.join(dir)))
                .chain(tree.files.iter().map(|file| dest.join(file)))
                .collect();
            if let Some(refused) = check_dests(project_root, &dests) {
                return Some(refused);
            }
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
                // A link to nothing has no content to copy. It is left
                // out, so the other files of the folder still come back.
                match self.kind(&format!("{path}/{name}")).await {
                    Ok(kind) => kind,
                    Err(ExportReadError::NotFound) => {
                        tracing::debug!(
                            path,
                            name,
                            "a file export skips a link that points to nothing"
                        );
                        continue;
                    }
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

    async fn mode(&mut self, path: &str) -> Option<u32> {
        self.sftp.metadata(path).await.ok()?.permissions
    }

    async fn resolve(&mut self, path: &str) -> Result<String, ExportReadError> {
        self.sftp
            .canonicalize(path)
            .await
            .map_err(|e| read_error(path, &e))
    }
}

/// Copies the declared exports of the ended box `id` on `host` into
/// `project_root`, the project the box came from (BOX-185). `here` is the
/// project root of the command that waited, and nothing is copied unless
/// it is `project_root` (BOX-199). Then it gives no outcome, so the exit
/// code does not change (BOX-194). `label` names the box on `err`. A box
/// whose spec declares no export copies nothing, and reads nothing more
/// from its host.
pub(crate) async fn copy_box_exports_on_host<E: std::io::Write>(
    host: &crate::cmd::list::LocalHost,
    id: boxes::SessionId,
    label: &str,
    project_root: Option<&std::path::Path>,
    here: Option<&std::path::Path>,
    err: &mut E,
) -> Vec<ExportOutcome> {
    let mut client = match box_host_client(host).await {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: could not reach the box's host: {e:#}");
            return Vec::new();
        }
    };
    copy_box_exports(&mut client, id, label, project_root, here, err).await
}

/// Whether the box `id` on `host` declares an export. A host that does not
/// answer, or a spec that is not readable, declares none.
pub(crate) async fn box_declares_exports_on_host(
    host: &crate::cmd::list::LocalHost,
    id: boxes::SessionId,
) -> bool {
    use minimald_rpc::{Errorable, GetBoxSpec, GetBoxSpecRequest};

    let Ok(mut client) = box_host_client(host).await else {
        return false;
    };
    match client
        .oneshot_rpc::<GetBoxSpec>(GetBoxSpecRequest { id })
        .await
    {
        Ok(Errorable::Ok(reply)) => reply
            .spec
            .as_ref()
            .is_some_and(|spec| !stored_export_paths(spec).is_empty()),
        _ => false,
    }
}

/// The stderr line for a box whose exports a command in another project
/// does not copy (BOX-199).
pub(crate) fn exports_elsewhere_line(label: &str, project_root: &std::path::Path) -> String {
    format!(
        "Box {label} was created in {}, so its exports were not copied here.",
        project_root.display()
    )
}

/// [`copy_box_exports_on_host`] over a connected `client`.
///
/// The copy first claims the exports of the box's end from its host
/// (BOX-198). It copies only the exports the host grants, and names each
/// refused one on `err` (BOX-201). A refused export has no outcome, so it
/// changes no exit code, and a later command on the same end does not
/// return 125 for an export that an earlier command reported. Each copied
/// or skipped export is reported to the host, which records a
/// `file_exported` event for it (BOX-195).
///
/// The callers set their exit code from the outcomes, with
/// [`exit_code_after_exports`] (BOX-193, BOX-194).
pub(crate) async fn copy_box_exports<E: std::io::Write>(
    client: &mut client::Client,
    id: boxes::SessionId,
    label: &str,
    project_root: Option<&std::path::Path>,
    here: Option<&std::path::Path>,
    err: &mut E,
) -> Vec<ExportOutcome> {
    copy_box_exports_from(client, id, label, project_root, here, err, open_box_files).await
}

/// Opens the files of box `id` on its host for a copy. `Err` is logged
/// here, and the copy names each granted export on stderr.
async fn open_box_files(client: &mut client::Client, id: boxes::SessionId) -> Result<BoxFiles, ()> {
    let channel = match client.open_box_subsystem(id, "sftp").await {
        Ok(channel) => channel,
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: open the box's files: {e:#}");
            return Err(());
        }
    };
    match russh_sftp::client::SftpSession::new(channel.into_stream()).await {
        Ok(sftp) => Ok(BoxFiles { sftp }),
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: start the file conversation: {e}");
            Err(())
        }
    }
}

/// [`copy_box_exports_on_host`], with an open of the box's files that
/// fails after the grant, as a lost connection to the box's files does.
#[cfg(test)]
pub(crate) async fn copy_box_exports_unreadable_on_host<E: std::io::Write>(
    host: &crate::cmd::list::LocalHost,
    id: boxes::SessionId,
    label: &str,
    project_root: Option<&std::path::Path>,
    here: Option<&std::path::Path>,
    err: &mut E,
) -> Vec<ExportOutcome> {
    let mut client = box_host_client(host).await.expect("the box's host");
    let unreadable = async |_: &mut client::Client, _: boxes::SessionId| Err::<BoxFiles, ()>(());
    copy_box_exports_from(&mut client, id, label, project_root, here, err, unreadable).await
}

/// [`copy_box_exports`], with `open` to open the box's files after the
/// claim. When `open` fails, each granted export is reported with no
/// files, so the record holds an entry for it (BOX-195).
async fn copy_box_exports_from<E, S, F>(
    client: &mut client::Client,
    id: boxes::SessionId,
    label: &str,
    project_root: Option<&std::path::Path>,
    here: Option<&std::path::Path>,
    err: &mut E,
    open: F,
) -> Vec<ExportOutcome>
where
    E: std::io::Write,
    S: ExportSource,
    F: AsyncFnOnce(&mut client::Client, boxes::SessionId) -> Result<S, ()>,
{
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
    let none_copied = |which: &[String]| {
        which
            .iter()
            .map(|path| ExportOutcome {
                path: path.clone(),
                copied: false,
                files: Vec::new(),
            })
            .collect::<Vec<_>>()
    };
    let not_copied = |err: &mut E, which: &[String], reason: &str| {
        for path in which {
            let _ = writeln!(err, "Export {path} was not copied: {reason}.");
        }
        none_copied(which)
    };
    let Some(project_root) = project_root else {
        tracing::warn!(box_id = %id, "file exports: the box's record names no project folder");
        return not_copied(err, &paths, "the box's record names no project folder");
    };
    // BOX-199: a box's exports are copied only in the project that made it.
    if here != Some(project_root) {
        tracing::info!(
            box_id = %id,
            record_root = %project_root.display(),
            here = ?here,
            "file exports: the waiting command is in another project"
        );
        let _ = writeln!(err, "{}", exports_elsewhere_line(label, project_root));
        // No outcome: this is not a skipped export, and it changes no exit
        // code (BOX-194).
        return Vec::new();
    }
    // BOX-198: the claim comes after the project check of BOX-199, so a
    // command in another project never claims the end.
    let claim = match claim_exports(client, id, &paths).await {
        Ok(claim) => claim,
        Err(reason) => return not_copied(err, &paths, &reason),
    };
    for path in &claim.refused {
        let _ = writeln!(err, "{}", claimed_elsewhere_line(path, label));
    }
    let (end, granted) = (claim.end, claim.granted);
    if granted.is_empty() {
        return Vec::new();
    }
    let Ok(mut files) = open(client, id).await else {
        let unreadable = "min could not read the box's files";
        let mut reporter = HostReport { client, id, end };
        return report_not_copied(&mut reporter, &granted, label, unreadable, err).await;
    };
    let mut reporter = HostReport { client, id, end };
    copy_and_report_exports(
        &mut files,
        &granted,
        project_root,
        label,
        err,
        &mut reporter,
    )
    .await
}

/// Claims the exports `paths` of the last end of box `id` from its host
/// (BOX-198). `Ok` is the end with the granted and the refused paths.
/// `Err` is the reason for the stderr line when the host grants nothing.
async fn claim_exports(
    client: &mut client::Client,
    id: boxes::SessionId,
    paths: &[String],
) -> Result<minimald_rpc::ClaimExportsResponse, String> {
    use minimald_rpc::{ClaimExports, ClaimExportsRequest, Errorable};

    match client
        .oneshot_rpc::<ClaimExports>(ClaimExportsRequest {
            id,
            paths: paths.to_vec(),
        })
        .await
    {
        Ok(Errorable::Ok(reply)) => Ok(reply),
        Ok(Errorable::Err { error }) => {
            tracing::info!(box_id = %id, "file exports: the claim was refused: {error}");
            Err(error)
        }
        Err(e) => {
            tracing::warn!(box_id = %id, "file exports: the claim did not reach the host: {e:#}");
            Err("min could not reach the box's host".to_owned())
        }
    }
}

/// Reports each export to the box's host over the connection that holds
/// its claim (BOX-195).
struct HostReport<'a> {
    client: &'a mut client::Client,
    id: boxes::SessionId,
    end: u64,
}

impl ExportReporter for HostReport<'_> {
    async fn report(&mut self, outcome: &ExportOutcome) -> Result<(), String> {
        use minimald_rpc::{Errorable, ExportedFileReport, ReportExport, ReportExportRequest};

        let request = ReportExportRequest {
            id: self.id,
            end: self.end,
            path: outcome.path.clone(),
            copied: outcome.copied,
            files: outcome
                .files
                .iter()
                .map(|file| ExportedFileReport {
                    path: file.path.clone(),
                    size: file.size,
                    sha256: file.sha256.clone(),
                })
                .collect(),
        };
        match self.client.oneshot_rpc::<ReportExport>(request).await {
            Ok(Errorable::Ok(_)) => Ok(()),
            Ok(Errorable::Err { error }) => Err(error),
            Err(e) => Err(format!("{e:#}")),
        }
    }
}
