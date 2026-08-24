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
    let project = match resolve(cwd, repo_dir) {
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
    let invoked_from = cwd.display().to_string();
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

/// Resolves the project, or the reason there is none to resolve.
///
/// Uses the same resolver the rest of the CLI loads config with, and honors
/// `--repo-dir` the same way: a bundle must name the project the command
/// would have acted on, not a different one.
fn resolve(cwd: &Path, repo_dir: Option<&Path>) -> Result<Project, String> {
    // `--repo-dir` names the root outright; without it, `min` walks up from
    // the cwd to the nearest config, so the bundle must too.
    let (found, searched) = match repo_dir {
        Some(dir) => (mfile::File::from_dir(dir), format!("in {}", dir.display())),
        None => (
            mfile::File::from_dir_recursive(cwd),
            format!("at or above {}", cwd.display()),
        ),
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
