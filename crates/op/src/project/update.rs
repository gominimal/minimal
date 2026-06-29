//! The `update` operation: refresh upstream/sideload checkouts and re-pin them
//! in the project's `minimal.toml`.

use anyhow::anyhow;
use mfile::LinkConfig;
use toml_edit::{DocumentMut, value};

use super::{ProjectEnv, ProjectOp};
use crate::Error;

/// Refreshes a project's upstream and sideload checkouts to the head of their
/// tracking branches and re-pins the new commits in `minimal.toml`.
///
/// Downloading any newly-reachable packages is deliberately left to the caller:
/// this operation only concerns the `minimal.toml` and its checkouts.
#[derive(Debug, Default, Clone, Copy)]
pub struct UpdateProject;

/// A single pin that moved during an update.
#[derive(Debug, Clone)]
pub struct RevChange {
    /// The repository whose pin changed.
    pub repo: String,
    /// The tracking branch the new commit was taken from.
    pub branch: String,
    /// The previously pinned commit, if any (`None` when previously unpinned).
    pub from: Option<String>,
    /// The newly pinned commit.
    pub to: String,
}

/// A summary of what [`UpdateProject`] changed, for the caller to report.
#[derive(Debug, Default, Clone)]
pub struct UpdateReport {
    /// The upstream pin, if it moved.
    pub upstream: Option<RevChange>,
    /// Any sideload pins that moved.
    pub sideloads: Vec<RevChange>,
}

impl ProjectOp for UpdateProject {
    type Result = UpdateReport;

    fn run<E: ProjectEnv>(&mut self, env: &mut E) -> Result<UpdateReport, Error> {
        // Snapshot everything we need from the minimal file before taking the
        // mutable borrows the checkout/update calls require.
        let Some(mfile) = env.minimal_file() else {
            // No minimal file to re-pin; still refresh checkouts best-effort.
            env.invalidate_remote_index();
            env.update_checkouts()?;
            return Ok(UpdateReport::default());
        };
        let mfile_path = mfile.file_path().cloned();

        let upstream: Option<(String, Option<String>, Option<String>)> =
            match mfile.upstream.as_ref().map(|u| &u.link) {
                Some(LinkConfig::Git {
                    repo,
                    branch,
                    locked_commit,
                }) => Some((repo.clone(), branch.clone(), locked_commit.clone())),
                Some(LinkConfig::Dir { .. }) | None => None,
            };

        // Preserve index alignment with the on-disk `[[upstream.sideload]]`
        // array: non-git / branchless sideloads stay as `None`.
        let sideloads: Vec<Option<(String, String, Option<String>)>> = mfile
            .upstream
            .as_ref()
            .map(|u| u.sideloads())
            .unwrap_or_default()
            .iter()
            .map(|s| match s.link() {
                LinkConfig::Git {
                    repo,
                    branch: Some(branch),
                    locked_commit,
                } => Some((repo.clone(), branch.clone(), locked_commit.clone())),
                _ => None,
            })
            .collect();

        // best effort, yeet any cached remote index so a fresh fetch occurs
        env.invalidate_remote_index();
        env.update_checkouts()?;

        // If a tracking branch is specified for the upstream, check out its head.
        let new_up_rev = if let Some((repo, Some(b), commit)) = &upstream {
            let new_git_ref = env.checkout_branch(repo, b)?;
            (Some(&new_git_ref) != commit.as_ref()).then_some(new_git_ref)
        } else {
            None
        };

        // Update all the sideloads, if present.
        let sideload_updates = sideloads
            .iter()
            .map(|s| match s {
                Some((repo, branch, locked_commit)) => {
                    let new_git_ref = env.checkout_branch(repo, branch)?;
                    Ok((Some(&new_git_ref) != locked_commit.as_ref()).then_some(new_git_ref))
                }
                None => Ok(None),
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let mut report = UpdateReport::default();

        // If theres a minimal file on disk with at least one new rev, write the
        // revs to the minimal file.
        let Some(p) = mfile_path else {
            return Ok(report);
        };

        let toml = std::fs::read_to_string(&p)
            .map_err(|e| Error::Other(anyhow!("reading {} for update: {e}", p.display())))?;
        let mut doc = toml
            .parse::<DocumentMut>()
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?;

        if new_up_rev.is_some() || sideload_updates.iter().any(|u| u.is_some()) {
            if let Some(new_rev) = new_up_rev {
                doc["upstream"]["locked_commit"] = value(new_rev.clone());
                // `new_up_rev` is only set when the upstream has a tracking branch.
                let (repo, branch, from) = upstream.expect("upstream present for new rev");
                report.upstream = Some(RevChange {
                    repo,
                    branch: branch.expect("tracking branch present for new rev"),
                    from,
                    to: new_rev,
                });
            }

            for (i, rev) in sideload_updates.into_iter().enumerate() {
                if let Some(new_rev) = rev {
                    if let Some((repo, branch, from)) = &sideloads[i] {
                        report.sideloads.push(RevChange {
                            repo: repo.clone(),
                            branch: branch.clone(),
                            from: from.clone(),
                            to: new_rev.clone(),
                        });
                    }
                    doc["upstream"]["sideload"][i]["locked_commit"] = value(new_rev);
                }
            }

            std::fs::write(&p, doc.to_string())
                .map_err(|e| Error::Other(anyhow!("writing {}: {e}", p.display())))?;
        }

        Ok(report)
    }
}
