//! Git repository checkout management for source operations.
//!
//! This crate provides abstractions for creating and maintaining checkouts of git repositories
//! at specific versions.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use tempfile::tempdir_in;
use tracing::trace;

mod error;
pub use error::Error;
mod repo;
pub use repo::Repo;

/// Reference to a specific version in a git repository.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GitRef {
    /// A branch name (e.g., "main", "develop")
    Branch(String),
    /// A tag (e.g., "v1.0.0")
    Tag(String),
    /// A specific commit hash (full or abbreviated)
    Commit(String),
}

impl GitRef {
    /// Returns the string representation suitable for git commands.
    pub fn as_str(&self) -> &str {
        match self {
            GitRef::Branch(s) | GitRef::Tag(s) | GitRef::Commit(s) => s,
        }
    }

    /// Returns the [common::repo_spec::Repo] representation.
    pub fn as_repo<U: Into<String>, H: Into<String>>(
        &self,
        url: U,
        checkout_git_hash: H,
    ) -> common::repo_spec::Repo {
        common::repo_spec::Repo::Git {
            url: url.into(),
            rev: checkout_git_hash.into(),
            tracking: match self {
                GitRef::Branch(b) => Some(common::repo_spec::GitRef::Branch(b.clone())),
                GitRef::Tag(t) => Some(common::repo_spec::GitRef::Tag(t.clone())),
                GitRef::Commit(_) => None,
            },
        }
    }
}

/// Converts from an (Upstream)[mfile::Upstream] stanza in the minimal-file
/// to a [GitRef].
impl TryFrom<&mfile::LinkConfig> for GitRef {
    type Error = ();
    fn try_from(upstream: &mfile::LinkConfig) -> Result<Self, Self::Error> {
        match upstream {
            mfile::LinkConfig::Git {
                repo: _,
                branch,
                locked_commit,
            } => Ok(match (&locked_commit, &branch) {
                (Some(hash), _) => GitRef::Commit(hash.clone()),
                (None, Some(branch)) => GitRef::Branch(branch.clone()),
                (None, None) => GitRef::Branch("main".to_string()),
            }),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for GitRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitRef::Branch(b) => write!(f, "branch:{}", b),
            GitRef::Tag(t) => write!(f, "tag:{}", t),
            GitRef::Commit(c) => write!(f, "commit:{}", c),
        }
    }
}

/// Describes the version of a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Checkout {
    pub version: GitRef,
    pub rev: String,
}

/// State of a specific git repo thats being managed.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RepoState {
    remote: String,
    // Maps subdirs to specific checkouts.
    checkouts: HashMap<String, Checkout>,
}

/// State of the manager serialized to disk.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManagerState {
    // Maps a remote string to an ID.
    pub git_remotes: HashMap<String, String>,
    // Maps IDs to the corresponding Repo.
    pub repos: HashMap<String, RepoState>,
}

impl ManagerState {
    /// attempts to read the state file if it exists, otherwise initializes an empty state.
    fn in_dir_or_default(dir: &Path) -> Result<Self, Error> {
        let path = dir.join("state.json");
        if path.exists() {
            let f = fs::File::open(path)?;
            Ok(serde_json::from_reader(f).map_err(Error::StatefileInvalid)?)
        } else {
            Ok(Default::default())
        }
    }

    /// serializes the state to the statefile in the given base directory.
    fn write_to(&self, dir: &Path) -> Result<(), Error> {
        let path = dir.join("state.json");
        let f = fs::File::create(path)?;
        match serde_json::to_writer(f, self) {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.is_io() {
                    Err(std::io::Error::new(
                        e.io_error_kind().unwrap(),
                        format!("writing state: {}", dir.join("state.json").display()),
                    )
                    .into())
                } else {
                    todo!("serde error: {:?}", e)
                }
            }
        }
    }
}

fn create_unique_id_and_dir(base_dir: &Path, prefix: String) -> std::io::Result<(String, PathBuf)> {
    let candidate = base_dir.join(&prefix);
    if !candidate.exists() {
        fs::create_dir(&candidate)?;
        return Ok((prefix, candidate));
    }

    // If prefix exists, try adding random suffixes
    use rand::RngExt;
    let mut rng = rand::rng();
    const MAX_ATTEMPTS: u32 = 1000;

    for _ in 0..MAX_ATTEMPTS {
        // Generate a random suffix (8 alphanumeric characters)
        let suffix: String = (0..8)
            .map(|_| {
                let idx = rng.random_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();

        let dir_name = format!("{}-{}", prefix, suffix);
        let candidate = base_dir.join(&dir_name);
        if !candidate.exists() {
            fs::create_dir(&candidate)?;
            return Ok((dir_name, candidate));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "Could not create unique directory with prefix '{}' after {} attempts",
            prefix, MAX_ATTEMPTS
        ),
    ))
}

/// Manages source-code checkouts.
#[derive(Debug)]
pub struct Manager {
    base_dir: PathBuf,
    state: ManagerState,
    repos: HashMap<String, Repo>,
}

impl Manager {
    /// Initializes the checkouts manager in the given directory.
    pub fn new<P: Into<PathBuf>>(base_dir: P) -> Result<Self, Error> {
        let base_dir = base_dir.into();
        let db_path = base_dir.join("git").join("db");
        fs::create_dir_all(&db_path)?;
        fs::create_dir_all(base_dir.join("git").join("checkouts"))?;

        let state = ManagerState::in_dir_or_default(&base_dir)?;
        let mut repos = HashMap::new();
        for (remote, id) in state.git_remotes.iter() {
            repos.insert(id.clone(), Repo::new(remote, db_path.join(id))?);
        }

        // For now we depend on the git command line tool. Shelling out when git doesn't exist
        // gives an incomprehensible NotFound error, so lets explicitly check that git is in PATH
        // and give a reasonable error if it is not.
        if !common::command_exists("git")? {
            return Err(Error::Other(
                "The git command was not found in path - is it installed?".into(),
            ));
        }

        let manager = Manager {
            base_dir,
            state,
            repos,
        };
        Ok(manager)
    }

    fn git_checkouts_dir(&self) -> PathBuf {
        self.base_dir.join("git").join("checkouts")
    }
    fn git_bares_dir(&self) -> PathBuf {
        self.base_dir.join("git").join("db")
    }

    /// Updates all repos to latest - does nothing for refs which arent symbolic (i.e. commits).
    pub fn update(&mut self) -> Result<(), Error> {
        let checkouts_dir = self.git_checkouts_dir();
        for (_remote, id) in self.state.git_remotes.iter_mut() {
            let repo = self.repos.get_mut(id).unwrap();
            trace!("updating repo {}", repo.url());
            repo.fetch()?;
            for (dir, checkout) in self.state.repos.get_mut(id).unwrap().checkouts.iter_mut() {
                checkout.rev =
                    repo.worktree_checkout(&checkouts_dir.join(dir), &checkout.version)?;
            }
        }
        self.state.write_to(&self.base_dir)?;
        Ok(())
    }

    /// Returns the path to a checkout described by the given parameters, as well as the
    /// commit hash at the given ref.
    pub fn checkout_of(&mut self, remote: &str, at: GitRef) -> Result<(PathBuf, String), Error> {
        trace!("checkout_of {} at {:?}", remote, at);

        let out = match self.state.git_remotes.get(remote) {
            // This remote is already managed
            Some(id) => {
                // See if theres already a checkout of this ref
                for (dir, checkout) in self.state.repos[id].checkouts.iter() {
                    if checkout.version == at {
                        return Ok((self.git_checkouts_dir().join(dir), checkout.rev.clone()));
                    }
                    // Its possible to have a checkout thats tracking a branch, but right now it points
                    // to a commit which was requested. We can just use that checkout rather than making
                    // one that points to just a commit in this case.
                    if let GitRef::Commit(ref rev) = at
                        && &checkout.rev == rev
                    {
                        return Ok((self.git_checkouts_dir().join(dir), rev.clone()));
                    }
                }
                // There's not a checkout of this ref, lets create it.
                let checkout_dir = tempdir_in(self.git_checkouts_dir()).unwrap().keep();
                let relative_dir = checkout_dir.strip_prefix(self.git_checkouts_dir()).unwrap();
                let repo = self.repos.get_mut(id).unwrap();
                repo.fetch()?;
                let checkout = repo.new_worktree(checkout_dir.clone(), at.clone())?;
                let git_hash = checkout.rev.clone();

                self.state
                    .repos
                    .get_mut(id)
                    .unwrap()
                    .checkouts
                    .insert(relative_dir.to_str().unwrap().to_string(), checkout);

                Ok((checkout_dir, git_hash))
            }
            // New remote, need to create
            None => {
                // Make id/directory for bare repository
                let prefix = match remote.to_lowercase().rsplit_once("/") {
                    None => "checkout".to_string(),
                    Some((_before, after)) => after.trim_end_matches(".git").to_string(),
                };
                // Make repo
                let (id, dir) = create_unique_id_and_dir(&self.git_bares_dir(), prefix)?;
                let mut repo = Repo::new(remote, dir)?;
                // Make checkout
                let checkout_dir = tempdir_in(self.git_checkouts_dir()).unwrap().keep();
                let relative_dir = checkout_dir.strip_prefix(self.git_checkouts_dir()).unwrap();
                let checkout = repo.new_worktree(checkout_dir.clone(), at.clone())?;
                let git_hash = checkout.rev.clone();

                self.state
                    .git_remotes
                    .insert(remote.to_string(), id.clone());
                self.state.repos.insert(
                    id.clone(),
                    RepoState {
                        remote: remote.to_string(),
                        checkouts: [(relative_dir.to_str().unwrap().to_string(), checkout)].into(),
                    },
                );
                self.repos.insert(id, repo);

                Ok((checkout_dir, git_hash))
            }
        };
        self.state.write_to(&self.base_dir)?;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn gitref_as_str() {
        assert_eq!(GitRef::Branch("main".to_string()).as_str(), "main");
        assert_eq!(GitRef::Tag("v1.0.0".to_string()).as_str(), "v1.0.0");
        assert_eq!(GitRef::Commit("abc123".to_string()).as_str(), "abc123");
    }

    #[test]
    #[ignore]
    fn manager() {
        let remote = "https://github.com/octocat/Spoon-Knife";
        let base_dir = tempdir().unwrap();
        let mut manager = Manager::new(base_dir.path()).unwrap();

        let (checkout, hash) = manager
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .unwrap();

        // Expect bare checkout to be at db/spoon-knife
        assert!(
            base_dir
                .path()
                .join("git")
                .join("db")
                .join("spoon-knife")
                .exists()
        );
        assert_eq!(hash, "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string());
        // Expect the README.md to exist from the checkout
        assert!(checkout.join("README.md").exists());
        // Expect runtime to be updated
        assert!(manager.repos.contains_key("spoon-knife"));
        // Expect serialized state to be updated
        assert_eq!(
            manager.state.git_remotes.get(remote).unwrap(),
            "spoon-knife"
        );
        assert_eq!(
            manager.state.repos.get("spoon-knife").unwrap().remote,
            remote,
        );
        assert_eq!(
            manager
                .state
                .repos
                .get("spoon-knife")
                .unwrap()
                .checkouts
                .values()
                .next()
                .unwrap(),
            &Checkout {
                version: GitRef::Branch("main".to_string()),
                rev: "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
            },
        );
        // Make sure state-file was written to disk
        assert!(base_dir.path().join("state.json").exists());
        // Make sure a fresh checkout request points to the same path.
        let (checkout2, hash2) = manager
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(&checkout, &checkout2);
        assert_eq!(
            hash2,
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string()
        );
        // Make sure even a freshly-initialized manager does the same
        let (checkout3, hash3) = Manager::new(base_dir.path())
            .unwrap()
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(&checkout, &checkout3);
        assert_eq!(
            hash3,
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string()
        );
    }

    #[test]
    #[ignore]
    fn repo_integration_smoketest() {
        // Fresh clone
        let clone_dir = tempdir().unwrap();
        let mut repo =
            Repo::new("https://github.com/octocat/Spoon-Knife", clone_dir.path()).unwrap();
        assert_eq!(
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
            repo.bare_revision().unwrap()
        );
        repo.list_remote_branches().unwrap();
        repo.list_tags().unwrap();

        let checkout_dir = tempdir().unwrap();
        repo.new_worktree(
            checkout_dir.path().to_path_buf(),
            GitRef::Branch("main".to_string()),
        )
        .unwrap();

        // Not fresh clone
        let mut repo =
            Repo::new("https://github.com/octocat/Spoon-Knife", clone_dir.path()).unwrap();
        repo.fetch().unwrap();
        assert_eq!(
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
            repo.worktree_checkout(checkout_dir.path(), &GitRef::Branch("main".to_string()))
                .unwrap()
        );
    }
}
