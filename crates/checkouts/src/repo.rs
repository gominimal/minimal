use crate::{Checkout, Error, GitRef};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tracing::{debug, trace};

/// Information about a git worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedWorktreeInfo {
    /// The path to the worktree.
    pub path: PathBuf,
    /// The commit hash (HEAD) of the worktree.
    pub head: String,
    /// The branch name, if the worktree is on a branch.
    pub branch: Option<String>,
}

/// A git repository of some remote, with some number of checkouts.
pub struct Repo {
    /// The path to the bare repository.
    bare: PathBuf,
    /// The remote URL of the repository.
    url: String,

    /// Worktrees at specific revisions.
    pub(crate) checkouts: HashMap<PathBuf, Checkout>,
}

impl Repo {
    /// Creates a new repository for the given URL and bare repository. The
    /// given path with be re-used if it is already a bare repository, and any
    /// worktrees it is linked to will be populated.
    pub fn new<S: Into<String>, P: Into<PathBuf>>(url: S, base: P) -> Result<Self, Error> {
        let url = url.into();
        let base = base.into();

        if base.exists() {
            // Double-check its the right remote
            let output = Command::new("git")
                .args(["remote", "get-url", "origin"])
                .current_dir(&base)
                .output()?;

            if output.status.success() {
                let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return if remote != url {
                    Err(Error::InvalidPath)
                } else {
                    let mut out = Self {
                        url,
                        bare: base,
                        checkouts: HashMap::new(),
                    };
                    for worktree in out.list_worktrees()? {
                        out.checkouts.insert(
                            worktree.path,
                            Checkout {
                                version: match worktree.branch {
                                    Some(b) => GitRef::Branch(b),
                                    None => GitRef::Commit(worktree.head.clone()),
                                },
                                rev: worktree.head,
                            },
                        );
                    }
                    Ok(out)
                };
            }
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = base.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Clone the repository
        let output = Command::new("git")
            .args([
                "clone",
                "--quiet",
                "--bare",
                &url,
                base.to_str().ok_or(Error::InvalidPath)?,
            ])
            .output()?;
        if !output.status.success() {
            return Err(Error::GitCommandFailed {
                command: "clone".to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(Self {
            url,
            bare: base,
            checkouts: HashMap::new(),
        })
    }

    /// Returns the path to the bare git repository.
    pub fn bare_repo_path(&self) -> &Path {
        &self.bare
    }

    /// Returns the remote URL of the repository.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetches updates from the remote repository.
    ///
    /// This updates the remote-tracking branches but does not modify any checkouts.
    pub fn fetch(&self) -> Result<(), Error> {
        debug!("Fetching updates for {}", self.bare_repo_path().display());
        self.run_git_bare(&["fetch", "--quiet", "origin"])?;
        for (checkout_path, c) in &self.checkouts {
            if let GitRef::Branch(b) = &c.version {
                self.run_git_checkout(checkout_path, &["checkout", b.as_str()])?;
            }
        }
        Ok(())
    }

    /// Returns the current commit hash of the repositories' default branch.
    pub fn bare_revision(&self) -> Result<String, Error> {
        let output = self.run_git_bare(&["rev-parse", "HEAD"])?;
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(commit)
    }

    /// Returns the path to an existing working tree containing the given ref.
    pub fn checkout_of(&self, git_ref: &GitRef) -> Option<(PathBuf, String)> {
        self.checkouts
            .iter()
            .find(|(_, c)| &c.version == git_ref)
            .map(|(p, c)| (p.clone(), c.rev.clone()))
    }

    pub fn checkout_to(&mut self, path: PathBuf, git_ref: GitRef) -> Result<Checkout, Error> {
        self.run_git_bare(&[
            "worktree",
            "add",
            "-f",
            "--checkout",
            path.to_str().unwrap(),
            git_ref.as_str(),
        ])?;
        let output = self.run_git_checkout(&path, &["rev-parse", "HEAD"])?;

        let checkout = Checkout {
            version: git_ref,
            rev: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        };
        self.checkouts.insert(path, checkout.clone());
        Ok(checkout)
    }

    /// Returns a list of all tags in the repository.
    pub fn list_tags(&self) -> Result<Vec<String>, Error> {
        let output = self.run_git_bare(&["tag", "--list"])?;
        let tags = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();
        Ok(tags)
    }

    /// Returns a list of all remote branches.
    pub fn list_remote_branches(&self) -> Result<Vec<String>, Error> {
        let output = self.run_git_bare(&["branch", "--remote", "--list"])?;
        let branches = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|s| {
                let trimmed = s.trim();
                // Skip HEAD pointer
                if trimmed.starts_with("origin/HEAD") {
                    None
                } else {
                    // Remove "origin/" prefix
                    trimmed.strip_prefix("origin/").map(|b| b.to_string())
                }
            })
            .collect();
        Ok(branches)
    }

    /// Lists all non-bare worktrees in the repository.
    ///
    /// Parses the output of `git worktree list --porcelain` and returns information
    /// about each worktree, excluding bare worktrees.
    fn list_worktrees(&self) -> Result<Vec<ParsedWorktreeInfo>, Error> {
        let output = self.run_git_bare(&["worktree", "list", "--porcelain"])?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut worktrees = Vec::new();
        let mut current_worktree: Option<PathBuf> = None;
        let mut current_head: Option<String> = None;
        let mut current_branch: Option<String> = None;
        let mut is_bare = false;

        for line in stdout.lines() {
            let line = line.trim();

            if line.is_empty() {
                // Empty line signals end of a worktree entry
                if let (Some(path), Some(head)) = (current_worktree.take(), current_head.take()) {
                    if !is_bare {
                        worktrees.push(ParsedWorktreeInfo {
                            path,
                            head,
                            branch: current_branch.take(),
                        });
                    }
                }
                // Reset state for next worktree
                current_branch = None;
                is_bare = false;
                continue;
            }

            if let Some(path_str) = line.strip_prefix("worktree ") {
                current_worktree = Some(PathBuf::from(path_str));
            } else if let Some(head_str) = line.strip_prefix("HEAD ") {
                current_head = Some(head_str.to_string());
            } else if let Some(branch_str) = line.strip_prefix("branch ") {
                current_branch = Some(if branch_str.starts_with("refs/heads/") {
                    branch_str.strip_prefix("refs/heads/").unwrap().to_string()
                } else {
                    branch_str.to_string()
                });
            } else if line == "bare" {
                is_bare = true;
            }
        }

        // Handle the last entry if there's no trailing empty line
        if let (Some(path), Some(head)) = (current_worktree, current_head) {
            if !is_bare {
                worktrees.push(ParsedWorktreeInfo {
                    path,
                    head,
                    branch: current_branch,
                });
            }
        }

        Ok(worktrees)
    }

    /// Runs a git command in the bare repository directory.
    fn run_git_bare(&self, args: &[&str]) -> Result<Output, Error> {
        trace!("Running bare git command: git {}", args.join(" "));

        let output = Command::new("git")
            .current_dir(self.bare_repo_path())
            .args(args)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(Error::GitCommandFailed {
                command: args.join(" "),
                stderr,
            });
        }
        Ok(output)
    }

    /// Runs a git command in a specific checkout directory.
    fn run_git_checkout<P: AsRef<Path>>(
        &self,
        checkout: P,
        args: &[&str],
    ) -> Result<Output, Error> {
        trace!("Running worktree git command: git {}", args.join(" "));

        let output = Command::new("git")
            .current_dir(checkout)
            .args(args)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(Error::GitCommandFailed {
                command: args.join(" "),
                stderr,
            });
        }
        Ok(output)
    }
}

impl std::fmt::Debug for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repo")
            .field("url", &self.url)
            .field("bare", &self.bare)
            .field("checkouts", &self.checkouts)
            .finish()
    }
}
