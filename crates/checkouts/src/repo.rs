use crate::{Checkout, Error, GitRef};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tracing::trace;

/// A git repository of some remote.
pub struct Repo {
    /// The path to the bare repository.
    bare: PathBuf,
    /// The remote URL of the repository.
    url: String,
}

impl Repo {
    /// Creates a new repository for the given URL and bare repository. The
    /// given path with be re-used if it is already initialized.
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
                    Ok(Self { url, bare: base })
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

        Ok(Self { url, bare: base })
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
    pub fn fetch(&mut self) -> Result<(), Error> {
        self.run_git_bare(&[
            "fetch",
            "--quiet",
            "origin",
            "+refs/heads/*:refs/remotes/origin/*",
        ])?;
        Ok(())
    }

    /// Returns the current commit hash of the repositories' default branch.
    pub fn bare_revision(&self) -> Result<String, Error> {
        let output = self.run_git_bare(&["rev-parse", "HEAD"])?;
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(commit)
    }

    /// Checks out the given ref in the given worktree, returning the git hash.
    pub fn worktree_checkout(
        &self,
        worktree_path: &Path,
        git_ref: &GitRef,
    ) -> Result<String, Error> {
        match git_ref {
            GitRef::Branch(b) => self.run_git_checkout(
                worktree_path,
                &["checkout", format!("origin/{}", b).as_str()],
            ),
            GitRef::Commit(s) | GitRef::Tag(s) => {
                self.run_git_checkout(worktree_path, &["checkout", s])
            }
        }?;

        let output = self.run_git_checkout(worktree_path, &["rev-parse", "HEAD"])?;
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(commit)
    }

    /// Creates a new worktree at the given path, checked-out to the given ref.
    pub fn new_worktree(&mut self, path: PathBuf, git_ref: GitRef) -> Result<Checkout, Error> {
        if let GitRef::Branch(b) = &git_ref {
            self.run_git_bare(&[
                "worktree",
                "add",
                "-f",
                "--track",
                "-B",
                b.as_str(),
                path.to_str().unwrap(),
                b.as_str(),
            ])?;
        } else {
            self.run_git_bare(&[
                "worktree",
                "add",
                "-f",
                "--checkout",
                path.to_str().unwrap(),
                git_ref.as_str(),
            ])?;
        }

        let output = self.run_git_checkout(&path, &["rev-parse", "HEAD"])?;
        Ok(Checkout {
            version: git_ref,
            rev: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        })
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
            .finish()
    }
}
