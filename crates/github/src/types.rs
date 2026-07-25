//! Core domain value types: [`RepoSpec`], [`BranchSpec`], [`GrantId`], and
//! [`AuthChoice`].
//!
//! Parsing is strict and fail-closed: malformed input is rejected at the
//! boundary so the rest of the system only ever handles well-formed values.

use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// A repository to pre-prime in a session, parsed from `owner/repo[@branch[:base]]`
/// (spec R2.1–R2.2).
///
/// The optional branch — and the base branch it may be created from — are
/// modelled together in [`BranchSpec`] so that a base branch without a working
/// branch is unrepresentable.
///
/// ```
/// use github::RepoSpec;
/// let spec: RepoSpec = "octocat/hello@feat/x:main".parse().unwrap();
/// assert_eq!(spec.owner(), "octocat");
/// assert_eq!(spec.repo(), "hello");
/// assert_eq!(spec.branch(), Some("feat/x"));
/// assert_eq!(spec.base(), Some("main"));
/// assert_eq!(spec.to_string(), "octocat/hello@feat/x:main");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoSpec {
    owner: String,
    repo: String,
    branch: Option<BranchSpec>,
}

/// A working branch and, optionally, the base branch it is created from when it
/// does not yet exist on the remote (checkout-or-create, spec R2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BranchSpec {
    name: String,
    base: Option<String>,
}

impl RepoSpec {
    /// Builds a [`RepoSpec`] from already-validated parts, validating each
    /// component. Prefer parsing from a string via [`str::parse`].
    pub fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        branch: Option<BranchSpec>,
    ) -> Result<Self, Error> {
        let owner = owner.into();
        let repo = repo.into();
        validate_owner(&owner)?;
        validate_repo(&repo)?;
        Ok(Self {
            owner,
            repo,
            branch,
        })
    }

    /// The repository owner (user or org).
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The repository name.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// The working branch, if one was requested.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        self.branch.as_ref().map(|b| b.name())
    }

    /// The base branch the working branch is created from, if specified.
    #[must_use]
    pub fn base(&self) -> Option<&str> {
        self.branch.as_ref().and_then(BranchSpec::base)
    }

    /// The full `BranchSpec`, if a branch was requested.
    #[must_use]
    pub fn branch_spec(&self) -> Option<&BranchSpec> {
        self.branch.as_ref()
    }
}

impl BranchSpec {
    /// Builds a [`BranchSpec`], validating the branch and (optional) base as git
    /// ref names.
    pub fn new(name: impl Into<String>, base: Option<String>) -> Result<Self, Error> {
        let name = name.into();
        validate_ref(&name)?;
        if let Some(base) = &base {
            validate_ref(base)?;
        }
        Ok(Self { name, base })
    }

    /// The working branch name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The base branch name, if specified.
    #[must_use]
    pub fn base(&self) -> Option<&str> {
        self.base.as_deref()
    }
}

impl fmt::Display for RepoSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)?;
        if let Some(branch) = &self.branch {
            write!(f, "@{branch}")?;
        }
        Ok(())
    }
}

impl fmt::Display for BranchSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(base) = &self.base {
            write!(f, ":{base}")?;
        }
        Ok(())
    }
}

impl FromStr for RepoSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let reject = |reason: &str| Error::InvalidRepoSpec {
            input: s.to_string(),
            reason: reason.to_string(),
        };

        // Split owner/repo from the optional `@branch[:base]` suffix on the
        // first `@`; `@` is not permitted inside a ref name (see validate_ref),
        // so this split is unambiguous.
        let (repo_part, branch_part) = match s.split_once('@') {
            Some((repo_part, branch_part)) => (repo_part, Some(branch_part)),
            None => (s, None),
        };

        let (owner, repo) = repo_part
            .split_once('/')
            .ok_or_else(|| reject("expected `owner/repo`"))?;
        if repo.contains('/') {
            return Err(reject("owner/repo must contain exactly one `/`"));
        }
        validate_owner(owner).map_err(|_| reject("owner has invalid characters"))?;
        validate_repo(repo).map_err(|_| reject("repo has invalid characters"))?;

        let branch = match branch_part {
            None => None,
            Some(bp) => {
                // `:` separates branch from base; a ref name never contains `:`,
                // so the first `:` is the separator.
                let (name, base) = match bp.split_once(':') {
                    Some((name, base)) => (name, Some(base)),
                    None => (bp, None),
                };
                if name.is_empty() {
                    return Err(reject("branch is empty after `@`"));
                }
                validate_ref(name).map_err(|_| reject("branch is not a valid ref name"))?;
                let base = match base {
                    None => None,
                    Some(base) => {
                        if base.is_empty() {
                            return Err(reject("base is empty after `:`"));
                        }
                        validate_ref(base).map_err(|_| reject("base is not a valid ref name"))?;
                        Some(base.to_string())
                    }
                };
                Some(BranchSpec {
                    name: name.to_string(),
                    base,
                })
            }
        };

        Ok(Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            branch,
        })
    }
}

/// Opaque identifier of a stored authentication grant (spec R6.4 reuse-or-mint).
///
/// A grant id is not itself secret — it names a grant, it is not the token — so
/// it is safe in logs and `attrs`. Non-empty by construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantId(String);

impl GrantId {
    /// Wraps a non-empty grant id.
    pub fn new(id: impl Into<String>) -> Result<Self, Error> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(Error::InvalidGrantId {
                reason: "grant id must not be empty".to_string(),
            });
        }
        Ok(Self(id))
    }

    /// The grant id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for GrantId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// The user's reuse-or-mint decision when a subsequent sandbox is created (spec
/// R6.4): reuse an existing authentication grant, or mint a fresh,
/// separately-scoped one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthChoice {
    /// Reuse the existing stored grant.
    Reuse,
    /// Mint a fresh grant with its own scoping.
    Mint,
}

/// Validates a GitHub owner (user or org) login: 1–39 chars of ASCII
/// alphanumerics and hyphens, no leading/trailing hyphen, no `--` run.
fn validate_owner(owner: &str) -> Result<(), Error> {
    let reject = || Error::InvalidRepoSpec {
        input: owner.to_string(),
        reason: "invalid owner".to_string(),
    };
    if owner.is_empty() || owner.len() > 39 {
        return Err(reject());
    }
    if owner.starts_with('-') || owner.ends_with('-') || owner.contains("--") {
        return Err(reject());
    }
    if !owner
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(reject());
    }
    Ok(())
}

/// Validates a GitHub repository name: 1–100 chars of ASCII alphanumerics, `-`,
/// `_`, `.`; not `.` or `..`.
fn validate_repo(repo: &str) -> Result<(), Error> {
    let reject = || Error::InvalidRepoSpec {
        input: repo.to_string(),
        reason: "invalid repo".to_string(),
    };
    if repo.is_empty() || repo.len() > 100 || repo == "." || repo == ".." {
        return Err(reject());
    }
    if !repo
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(reject());
    }
    Ok(())
}

/// Validates a git ref name (branch or base) strictly enough that it is safe to
/// use unquoted as a git argument and as a `,`-separated `attrs` element.
///
/// Rejects: empty; any whitespace or ASCII control; any of `~^:?*[\@,` and space;
/// a `..` run; leading/trailing `/` or `.`; a trailing `.lock`. This is stricter
/// than git itself (which permits `@` and `,`), which is intentional: fail-closed
/// keeps the value shell-safe and unambiguous in the codecs that use `@`, `:`,
/// and `,` as delimiters.
fn validate_ref(name: &str) -> Result<(), Error> {
    let reject = || Error::InvalidRepoSpec {
        input: name.to_string(),
        reason: "invalid ref name".to_string(),
    };
    if name.is_empty()
        || name.contains("..")
        || name.starts_with('/')
        || name.ends_with('/')
        || name.starts_with('.')
        || name.ends_with('.')
        || name.ends_with(".lock")
    {
        return Err(reject());
    }
    let forbidden = |c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\' | '@' | ',')
    };
    if name.chars().any(forbidden) {
        return Err(reject());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_shapes() {
        for input in [
            "octocat/hello",
            "octocat/hello@feat/x",
            "octocat/hello@feat/x:main",
            "my-org/my.repo_name@release/1.2:develop",
        ] {
            let spec: RepoSpec = input.parse().unwrap();
            assert_eq!(spec.to_string(), input, "round-trip for {input}");
        }
    }

    #[test]
    fn parses_components() {
        let spec: RepoSpec = "octocat/hello@feat/x:main".parse().unwrap();
        assert_eq!(spec.owner(), "octocat");
        assert_eq!(spec.repo(), "hello");
        assert_eq!(spec.branch(), Some("feat/x"));
        assert_eq!(spec.base(), Some("main"));

        let bare: RepoSpec = "octocat/hello".parse().unwrap();
        assert_eq!(bare.branch(), None);
        assert_eq!(bare.base(), None);
    }

    #[test]
    fn rejects_malformed() {
        let bad = [
            "",                     // empty
            "noslash",              // missing repo
            "owner/",               // empty repo
            "/repo",                // empty owner
            "a/b/c",                // too many slashes
            "owner/repo@",          // empty branch
            "owner/repo@feat:",     // empty base
            "-owner/repo",          // leading hyphen owner
            "owner-/repo",          // trailing hyphen owner
            "ow--ner/repo",         // double hyphen owner
            "own er/repo",          // space in owner
            "owner/re po",          // space in repo
            "owner/repo@fe at",     // space in branch
            "owner/repo@feat~x",    // tilde in branch
            "owner/repo@..",        // dotdot branch
            "owner/repo@/feat",     // leading slash branch
            "owner/.",              // repo is a dot
            "owner/repo@feat@more", // second @ becomes branch char, rejected
        ];
        for input in bad {
            assert!(
                input.parse::<RepoSpec>().is_err(),
                "should reject {input:?}",
            );
        }
    }

    #[test]
    fn base_without_branch_is_unrepresentable() {
        // There is no constructor and no parse path that yields a base without a
        // branch: base lives inside BranchSpec, which requires a name.
        let spec = RepoSpec::new("o", "r", None).unwrap();
        assert_eq!(spec.base(), None);
    }

    #[test]
    fn grant_id_round_trip_and_rejects_empty() {
        let id: GrantId = "grant-123".parse().unwrap();
        assert_eq!(id.as_str(), "grant-123");
        assert_eq!(id.to_string(), "grant-123");
        assert!("".parse::<GrantId>().is_err());
        assert!("   ".parse::<GrantId>().is_err());
    }
}
