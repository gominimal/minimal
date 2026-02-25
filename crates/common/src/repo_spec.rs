/// Describes a repository which contains something.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Repo {
    Git {
        /// The remote URL the git repo can be fetched from.
        url: String,
        /// The git commit hash.
        rev: String,
        /// If relevant, the name of the ref that the git commit hash refers to.
        tracking: Option<GitRef>,
    },
}

/// A ref in a git repository.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum GitRef {
    Branch(String),
    Tag(String),
}

/// Identifies a build-spec from a repo.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RepoSpec {
    repo: Repo,
    build_spec: String,
}
