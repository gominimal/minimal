//! Git repository checkout management for source operations.
//!
//! This crate provides abstractions for creating and maintaining checkouts of git repositories
//! at specific versions. The main type is [`Repo`], which handles cloning, fetching, and
//! checking out specific revisions.

mod error;
pub use error::Error;

/// Reference to a specific version in a git repository.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GitRef {
    /// A branch name (e.g., "main", "develop")
    Branch(String),
    /// A tag (e.g., "v1.0.0")
    Tag(String),
    /// A specific commit hash (full or abbreviated)
    Commit(String),
}

/// Describes the version of a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Checkout {
    pub version: GitRef,
    pub rev: String,
}

impl GitRef {
    /// Returns the string representation suitable for git commands.
    pub fn as_str(&self) -> &str {
        match self {
            GitRef::Branch(s) | GitRef::Tag(s) | GitRef::Commit(s) => s,
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

mod repo;
pub use repo::Repo;

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
        repo.checkout_to(
            checkout_dir.path().to_path_buf(),
            GitRef::Branch("main".to_string()),
        )
        .unwrap();

        // Not fresh clone
        let repo = Repo::new("https://github.com/octocat/Spoon-Knife", clone_dir.path()).unwrap();
        repo.fetch().unwrap();

        // Make sure the worktree was automatically initialized
        assert_eq!(
            repo.checkouts[&checkout_dir.path().to_path_buf()],
            Checkout {
                rev: "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
                version: GitRef::Branch("main".to_string()),
            }
        )
    }
}
