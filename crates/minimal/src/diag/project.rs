//! Project scope for the `min bug` bundle: which project this bundle is
//! *about*.
//!
//! Every other collector describes a machine. A machine hosts many projects,
//! so a bundle that describes only the machine cannot be filed against the
//! project that produced the complaint, and gets attributed to whichever one
//! the reader guesses (#1211). `project/project.json`, plus the same identity
//! in `manifest.json`, closes that gap: a reader learns the project from the
//! first file they open.
//!
//! Only the project's identity is recorded — its root, its config file's
//! relative path, and the directory the command ran from. No configuration
//! *values* leave the machine here; the redacted config itself is collected
//! separately, under the policy in [`crate::diag::redact`].

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Serialize;

use diagnostics::{BundleWriter, ProjectIdentity, ProjectScope, Redaction};

/// Bundle path of the project identity.
const PROJECT_DEST: &str = "project/project.json";

/// `project/project.json` and the manifest's project scope.
///
/// Never fails on account of there being no project: `min bug` is run from
/// wherever the user happens to be standing, and "not inside a project" is a
/// finding the manifest records rather than a collector error.
pub async fn project(
    w: &mut BundleWriter,
    cwd: &Path,
    repo_dir: Option<&Path>,
) -> Result<(), anyhow::Error> {
    // `resolve` is a synchronous walk of the filesystem — a `std::fs::read`
    // per ancestor — so it goes on a blocking thread, the same discipline the
    // rest of the diagnostics collectors keep (`diagnostics::listing`,
    // `diagnostics::kmsg`). A wedged filesystem must strand a blocking thread,
    // never the worker whose `collect_step!` timeout is the failsafe: this
    // collector runs before its own first `await`, so a blocked resolver on
    // the runtime would outlast the deadline meant to catch it.
    let (cwd_owned, repo_owned) = (cwd.to_path_buf(), repo_dir.map(Path::to_path_buf));
    let (resolved, invoked_from) = tokio::task::spawn_blocking(move || {
        // The cwd is resolved on this thread too, for the same reason:
        // `canonicalize` is one more filesystem call, and the point of the
        // thread is that none of them run on the worker.
        let invoked_from = absolute(&cwd_owned);
        (resolve(&cwd_owned, repo_owned.as_deref()), invoked_from)
    })
    .await
    .context("project worker")?;

    let project = match resolved {
        Ok(project) => project,
        Err(reason) => {
            w.set_project(ProjectScope::Unknown {
                reason: reason.clone(),
            });
            w.skip(PROJECT_DEST, reason);
            return Ok(());
        }
    };

    let root = project.root.display().to_string();
    let invoked_from = invoked_from.display().to_string();
    w.set_project(ProjectScope::Identified(ProjectIdentity::new(
        &project.name,
        &root,
        &project.config,
    )));
    let report = ProjectReport {
        name: &project.name,
        root: &root,
        config: &project.config,
        // Which directory the command was run from, which is not the project
        // root whenever `min bug` was run in a subdirectory. Worth stating
        // outright: it is the difference between "minimal read no config" and
        // "minimal read the config one level up".
        invoked_from: &invoked_from,
    };
    let json = serde_json_lenient::to_vec_pretty(&report)?;
    w.add_bytes(PROJECT_DEST, &json, Redaction::None).await
}

/// The project a bundle is attributable to.
struct Project {
    /// The project root's directory name.
    name: String,
    /// Absolute path of the project root.
    root: PathBuf,
    /// The config file, relative to the root.
    config: String,
}

/// `project/project.json`.
#[derive(Serialize)]
struct ProjectReport<'a> {
    name: &'a str,
    root: &'a str,
    config: &'a str,
    invoked_from: &'a str,
}

/// The path resolved against the filesystem, or left exactly as given when it
/// cannot be.
///
/// Falling back rather than failing keeps the diagnostic honest: a
/// `--repo-dir` that does not exist is the "no project here" finding below,
/// reported against the path the user actually typed, not a collector error
/// about `canonicalize`.
fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Resolves the project, or the reason there is none to resolve.
///
/// Uses the same resolver the rest of the CLI loads config with, and honors
/// `--repo-dir` the same way: a bundle must name the project the command
/// would have acted on, not a different one.
fn resolve(cwd: &Path, repo_dir: Option<&Path>) -> Result<Project, String> {
    // `--repo-dir` names the root outright; without it, `min` walks up from
    // the cwd to the nearest config, so the bundle must too.
    //
    // Either input can be relative — `--repo-dir ../other-checkout` verbatim,
    // and `cwd` when `current_dir()` failed and the caller fell back to `"."`
    // — so both are made absolute first. `ProjectIdentity::root` is
    // documented as an absolute path on the producing host, and a relative
    // one means nothing to a reader on a different machine. The established
    // step for a `--repo-dir` about to be treated as a root: `attach.rs`,
    // `cmd_activate`, and `cmd_task_run` all canonicalize the same way.
    let (found, searched) = match repo_dir {
        Some(dir) => {
            let dir = absolute(dir);
            (mfile::File::from_dir(&dir), format!("in {}", dir.display()))
        }
        None => {
            let cwd = absolute(cwd);
            (
                mfile::File::from_dir_recursive(&cwd),
                format!("at or above {}", cwd.display()),
            )
        }
    };
    let file = found.map_err(|e| {
        let name = mfile::MFILE_NAME;
        match e {
            mfile::Error::NotFound => {
                format!("no {name} {searched} — the bundle was not collected inside a project")
            }
            // A TOML parse error quotes the line it choked on, which is a
            // line of the user's config. The fact that the file is malformed
            // is the diagnostic; the offending text is not this collector's
            // to publish.
            mfile::Error::Format(_) => format!("the {name} {searched} is not valid TOML"),
            e => format!("the {name} {searched} could not be read: {e}"),
        }
    })?;

    // `repo_path` and `file_path` are `Some` for any mfile that came off
    // disk; a `None` here means the file was parsed from memory, which this
    // path never does. Report it rather than unwrapping into a panic inside
    // a diagnostic collector.
    let (Some(root), Some(config)) = (file.repo_path(), file.file_path()) else {
        return Err(format!(
            "the {name} found {searched} has no path on disk",
            name = mfile::MFILE_NAME,
        ));
    };
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.display().to_string());
    let config = config
        .strip_prefix(root)
        .unwrap_or(config.as_path())
        .display()
        .to_string();
    Ok(Project {
        name,
        root: root.to_path_buf(),
        config,
    })
}
