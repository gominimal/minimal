//! The GitHub authorization choke point (spec R5.4).
//!
//! This module holds:
//!
//! * typed read/write of the `github.*` `attrs` on a session's
//!   [`minimald_rpc::SessionConfig`] / [`sessions::Record`] — thin wrappers
//!   over the shared [`github::attrs::GithubAttrs`] codec, so no other module
//!   in `minimald` hand-rolls the `attrs` key names or string encodings;
//! * [`Permission`], the small typed vocabulary of "what an operation needs"
//!   (a [`Scope`] plus the [`github::Permission`] level), so call sites read
//!   as intent (`Permission::push()`) rather than a bare scope/level pair;
//! * [`authorize`], the single choke point every authenticated GitHub
//!   operation (`min git`/`min api` facade verbs, repo pre-priming, push, PR
//!   creation) MUST call before touching the network or a token.
//!
//! `authorize` is a pure decision function over a session's `attrs`: it never
//! performs I/O and never sees a token. See its doc comment for the
//! mandatory "caller must hold a live-session handle" contract.
//!
//! Sibling modules `prime`, `push_pr`, and `facade` (spec 10's fan-out —
//! see `super`'s module docs) are the intended callers of everything public
//! here, but land as separate tasks and are still doc-only stubs in this
//! tree. Until they call in, nothing in this crate reaches `authorize`,
//! `Permission`, or `AuthzError`, so `dead_code` is allowed at the module
//! level rather than left to fail the clippy gate for a fact of DAG
//! ordering, not a real defect; the exhaustive test suite below is this
//! module's actual usage proof in the meantime.
#![allow(dead_code)]

use std::fmt;

use github::attrs::GithubAttrs;
use github::{GrantId, RepoSpec, Scope};
use sessions::Record;

/// A GitHub permission requirement: a [`Scope`] plus the minimum
/// [`github::Permission`] level an operation needs. This is the single
/// currency [`authorize`] checks a session's resolved scope set against
/// (spec R5.4).
///
/// Named constructors spell out the concrete operations the daemon performs
/// (spec R5.1's default scope set), so a call site reads as "this is a push"
/// rather than a bare `(Scope, Permission)` pair; [`Permission::new`] covers
/// anything not named below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    scope: Scope,
    level: github::Permission,
}

impl Permission {
    /// Builds a requirement from an explicit scope/level pair.
    #[must_use]
    pub fn new(scope: Scope, level: github::Permission) -> Self {
        Self { scope, level }
    }

    /// `contents:read` — required to clone or fetch (spec R2.3, R2.4).
    #[must_use]
    pub fn read_contents() -> Self {
        Self::new(Scope::Contents, github::Permission::Read)
    }

    /// `contents:write` — required to push commits or branches (spec R3.4).
    #[must_use]
    pub fn push() -> Self {
        Self::new(Scope::Contents, github::Permission::Write)
    }

    /// `pull_requests:read` — required to detect an existing PR (spec R4.5).
    #[must_use]
    pub fn read_pull_requests() -> Self {
        Self::new(Scope::PullRequests, github::Permission::Read)
    }

    /// `pull_requests:write` — required to open or update a PR (spec R4.3).
    #[must_use]
    pub fn create_pr() -> Self {
        Self::new(Scope::PullRequests, github::Permission::Write)
    }

    /// `issues:read` — required for a GitHub MCP issue read.
    #[must_use]
    pub fn read_issues() -> Self {
        Self::new(Scope::Issues, github::Permission::Read)
    }

    /// `issues:write` — required for a GitHub MCP issue mutation.
    #[must_use]
    pub fn write_issues() -> Self {
        Self::new(Scope::Issues, github::Permission::Write)
    }

    /// The scope this requirement is against.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The minimum level required for [`Permission::scope`].
    #[must_use]
    pub fn level(&self) -> github::Permission {
        self.level
    }
}

impl fmt::Display for Permission {
    /// Renders as `scope:level`, e.g. `contents:rw` — matching
    /// [`github::ScopeSet::render_for_consent`]'s per-entry format, so this
    /// reads identically wherever it shows up in an error or a span.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scope, self.level)
    }
}

/// Errors from [`authorize`] and the `attrs` codec helpers in this module
/// (spec R5.4, R8.1). Every variant is safe to log or surface to a user: no
/// token material, only repo names, scope names, and grant ids (which are
/// identifiers, not secrets — see [`GrantId`]'s docs).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthzError {
    /// The session's stored `github.*` attrs failed to decode (a malformed
    /// grant id, repo spec, or scope string). This should not happen for
    /// attrs this module itself wrote, but a session's attrs can in
    /// principle be edited out from under it, so decode failure is handled
    /// rather than panicked on.
    #[error("session GitHub configuration could not be read: {0}")]
    InvalidAttrs(#[source] github::Error),

    /// The session has no GitHub grant bound at all — either it was never
    /// configured for GitHub, or pre-priming has not run yet.
    #[error(
        "this session has no GitHub authentication bound; declare a repo and \
         sign in with `min github login`"
    )]
    NoGrantBound,

    /// `repo` is not in the session's declared repo allow-list (spec R2.1).
    /// The exact wording here is depended on by tests and is the canonical
    /// deny message for this case.
    #[error("repo {owner}/{repo} not declared for this session")]
    RepoNotDeclared {
        /// The repository owner (user or org) that was requested.
        owner: String,
        /// The repository name that was requested.
        repo: String,
    },

    /// The session's resolved scope set does not grant the required
    /// permission at the required level (spec R5.4).
    #[error(
        "required GitHub permission `{required}` not granted for this \
         session (resolved scopes: {resolved})"
    )]
    MissingScope {
        /// The permission that was required, rendered `scope:level`.
        required: String,
        /// The session's full resolved scope set, for context. Scope names
        /// and levels are not secret.
        resolved: String,
    },
}

impl From<github::Error> for AuthzError {
    fn from(err: github::Error) -> Self {
        Self::InvalidAttrs(err)
    }
}

/// Decodes the GitHub-relevant `attrs` off a session record via the shared
/// [`github::attrs::GithubAttrs`] codec (spec R7.1). A session with no
/// GitHub involvement decodes to [`GithubAttrs::default`] (all fields
/// absent), which downstream [`authorize`] calls reject as
/// [`AuthzError::NoGrantBound`] rather than treating as "anything goes".
///
/// # Errors
///
/// [`AuthzError::InvalidAttrs`] if a present `github.*` key does not parse.
pub fn read_github_attrs(record: &Record) -> Result<GithubAttrs, AuthzError> {
    GithubAttrs::decode(&record.attrs).map_err(AuthzError::from)
}

/// Writes the GitHub-relevant fields into a session-creation request's
/// `attrs` (spec R7.1), via the same shared codec. Any unrelated key already
/// present is left untouched (see [`GithubAttrs::encode_into`]).
pub fn write_github_attrs(config: &mut minimald_rpc::SessionConfig, attrs: &GithubAttrs) {
    attrs.encode_into(&mut config.attrs);
}

/// The single authorization choke point (spec R5.4). Every authenticated
/// GitHub operation a session performs — `min git`/`min api` facade verbs,
/// repo pre-priming, explicit push, PR creation — MUST call this before
/// touching the network or obtaining a token. Checks, in order:
///
/// 1. **Bound.** The session has a GitHub grant bound at all
///    ([`AuthzError::NoGrantBound`] otherwise).
/// 2. **Declared.** `repo` is present in the session's declared repo
///    allow-list ([`AuthzError::RepoNotDeclared`] otherwise) — this is what
///    makes it impossible for a facade operation to reach a repository the
///    user did not consent to at launch (spec R2.1, G6).
/// 3. **Scoped.** `perm` is contained in the session's resolved scope set at
///    a sufficient level ([`AuthzError::MissingScope`] otherwise) — e.g. a
///    push needs `contents:write`, PR creation needs `pull_requests:write`
///    (spec R5.1, R5.4).
///
/// On success, returns the session's bound [`GrantId`]; the caller then
/// resolves that id to a live token via `GithubService::grants` (this
/// function never touches a token or the network itself — it is a pure
/// decision over `record.attrs`).
///
/// # Contract: callers must hold a live-session handle
///
/// `record` MUST be obtained from a **live** session actor — the
/// `mngr.get_session(SessionKeyPredicate::Id(..))` → `SessionHandle`
/// pattern used by the exec-channel dispatch (see
/// `crate::exec::handle_channel_exec`) — and not a `Record` read directly
/// from the on-disk store. The on-disk record for a **destroyed** session
/// can still be fetched by id long after the sandbox — and with it, the
/// facade channel that mediated access was bound to (spec R3.5, R6.3) — is
/// gone; nothing in a bare `Record` distinguishes "session is live" from
/// "session used to exist". `authorize` therefore cannot detect a destroyed
/// session on its own: **the caller resolving a live `SessionHandle` first
/// is the mechanism that makes a destroyed session's id authorize nothing.**
/// Every RPC/facade entry point in this daemon must look the session up via
/// the session manager and pass in the record obtained from that handle
/// (e.g. `SessionHandle::record()`), never a value cached across an
/// await point or read straight from `crate::store`.
///
/// # Errors
///
/// See [`AuthzError`]'s variants.
pub fn authorize(
    record: &Record,
    repo: &RepoSpec,
    perm: Permission,
) -> Result<GrantId, AuthzError> {
    let attrs = read_github_attrs(record)?;

    let grant_id = attrs.grant_id.ok_or(AuthzError::NoGrantBound)?;

    let declared = attrs
        .repos
        .iter()
        .any(|declared| declared.owner() == repo.owner() && declared.repo() == repo.repo());
    if !declared {
        return Err(AuthzError::RepoNotDeclared {
            owner: repo.owner().to_string(),
            repo: repo.repo().to_string(),
        });
    }

    let resolved = attrs.scopes.unwrap_or_default();
    let granted = resolved.permission(perm.scope());
    if granted.is_none_or(|level| level < perm.level()) {
        return Err(AuthzError::MissingScope {
            required: perm.to_string(),
            resolved: resolved.render_for_consent(),
        });
    }

    Ok(grant_id)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use github::{Permission as GhPermission, ScopeSet};
    use paths::HostAbsPath;
    use sessions::{NetworkMode, SessionId, SessionPolicy, SessionStatus};

    use super::*;

    /// A syntactically valid absolute host path for tests that need one but
    /// don't exercise path behavior.
    fn dummy_path() -> HostAbsPath {
        HostAbsPath::try_new("/tmp/minimald-authz-test").expect("literal absolute path")
    }

    /// Builds a bare `Record` with the given `attrs`, otherwise minimal.
    fn record_with_attrs(attrs: BTreeMap<String, String>) -> Record {
        Record {
            id: SessionId::nil(),
            name: None,
            username: None,
            project_path: dummy_path(),
            network: NetworkMode::default(),
            policy: SessionPolicy::default(),
            status: SessionStatus::default(),
            attrs,
        }
    }

    fn repo(spec: &str) -> RepoSpec {
        spec.parse().expect("valid repo spec literal in test")
    }

    fn bound_record(repos: &[&str], scopes: ScopeSet) -> Record {
        let mut attrs = BTreeMap::new();
        GithubAttrs {
            grant_id: Some(GrantId::new("grant-1").unwrap()),
            repos: repos.iter().map(|r| repo(r)).collect(),
            scopes: Some(scopes),
        }
        .encode_into(&mut attrs);
        record_with_attrs(attrs)
    }

    #[test]
    fn happy_path_returns_grant_id() {
        let record = bound_record(&["octocat/hello"], ScopeSet::defaults());
        let grant = authorize(&record, &repo("octocat/hello"), Permission::push())
            .expect("declared repo + sufficient scope must authorize");
        assert_eq!(grant.as_str(), "grant-1");
    }

    #[test]
    fn happy_path_with_multiple_declared_repos() {
        let record = bound_record(&["octocat/hello", "my-org/api"], ScopeSet::defaults());
        assert!(authorize(&record, &repo("octocat/hello"), Permission::create_pr()).is_ok());
        assert!(authorize(&record, &repo("my-org/api"), Permission::create_pr()).is_ok());
    }

    #[test]
    fn unbound_session_is_denied() {
        // No grant_id at all: an empty-attrs session (never touched GitHub).
        let record = record_with_attrs(BTreeMap::new());
        let err = authorize(&record, &repo("octocat/hello"), Permission::push())
            .expect_err("no grant bound must deny");
        assert!(matches!(err, AuthzError::NoGrantBound));
    }

    #[test]
    fn unbound_session_is_denied_even_with_declared_repos_and_scopes() {
        // Repos/scopes present but no grant_id: still must deny, since there is
        // no token to authorize against.
        let mut attrs = BTreeMap::new();
        GithubAttrs {
            grant_id: None,
            repos: vec![repo("octocat/hello")],
            scopes: Some(ScopeSet::defaults()),
        }
        .encode_into(&mut attrs);
        let record = record_with_attrs(attrs);

        let err = authorize(&record, &repo("octocat/hello"), Permission::push())
            .expect_err("missing grant_id must deny regardless of repos/scopes");
        assert!(matches!(err, AuthzError::NoGrantBound));
    }

    #[test]
    fn undeclared_repo_is_denied() {
        let record = bound_record(&["octocat/hello"], ScopeSet::defaults());
        let err = authorize(&record, &repo("other-owner/other-repo"), Permission::push())
            .expect_err("repo not in the allow-list must deny");
        match err {
            AuthzError::RepoNotDeclared { owner, repo } => {
                assert_eq!(owner, "other-owner");
                assert_eq!(repo, "other-repo");
            }
            other => panic!("expected RepoNotDeclared, got {other:?}"),
        }
    }

    #[test]
    fn declared_repo_branch_is_irrelevant_to_the_allow_list_match() {
        // The declared repo carries a branch/base; authorize matches on
        // owner/repo only, since the branch is a prime-time detail, not part
        // of the identity of "which repo may this session touch".
        let record = bound_record(&["octocat/hello@feat/x:main"], ScopeSet::defaults());
        assert!(authorize(&record, &repo("octocat/hello"), Permission::push()).is_ok());
    }

    #[test]
    fn missing_scope_is_denied_per_permission_push() {
        // Scopes present, but contents is read-only: a push needs write.
        let scopes = ScopeSet::empty().with(Scope::Contents, GhPermission::Read);
        let record = bound_record(&["octocat/hello"], scopes);
        let err = authorize(&record, &repo("octocat/hello"), Permission::push())
            .expect_err("read-only contents must deny a push");
        match err {
            AuthzError::MissingScope { required, resolved } => {
                assert_eq!(required, "contents:rw");
                assert_eq!(resolved, "contents:read");
            }
            other => panic!("expected MissingScope, got {other:?}"),
        }
    }

    #[test]
    fn missing_scope_is_denied_per_permission_create_pr() {
        // pull_requests scope entirely absent from the resolved set.
        let scopes = ScopeSet::empty().with(Scope::Contents, GhPermission::Write);
        let record = bound_record(&["octocat/hello"], scopes);
        let err = authorize(&record, &repo("octocat/hello"), Permission::create_pr())
            .expect_err("absent pull_requests scope must deny PR creation");
        assert!(matches!(err, AuthzError::MissingScope { .. }));
    }

    #[test]
    fn no_resolved_scopes_denies_everything() {
        // Grant bound, repo declared, but scopes were never resolved: fail
        // closed rather than treat "no scopes recorded" as "anything goes".
        let mut attrs = BTreeMap::new();
        GithubAttrs {
            grant_id: Some(GrantId::new("grant-1").unwrap()),
            repos: vec![repo("octocat/hello")],
            scopes: None,
        }
        .encode_into(&mut attrs);
        let record = record_with_attrs(attrs);

        let err = authorize(&record, &repo("octocat/hello"), Permission::read_contents())
            .expect_err("no resolved scopes must deny even a read");
        assert!(matches!(err, AuthzError::MissingScope { .. }));
    }

    #[test]
    fn write_permission_satisfies_a_read_requirement() {
        // GitHub's write implies read; a resolved `contents:write` must
        // satisfy a `contents:read` requirement (e.g. a clone/fetch).
        let scopes = ScopeSet::empty().with(Scope::Contents, GhPermission::Write);
        let record = bound_record(&["octocat/hello"], scopes);
        assert!(authorize(&record, &repo("octocat/hello"), Permission::read_contents()).is_ok());
    }

    #[test]
    fn malformed_attrs_are_rejected_not_panicked_on() {
        let mut attrs = BTreeMap::new();
        attrs.insert(
            github::attrs::ATTR_REPOS.to_string(),
            "not a valid repo spec".to_string(),
        );
        let record = record_with_attrs(attrs);
        let err = authorize(&record, &repo("octocat/hello"), Permission::push())
            .expect_err("malformed attrs must be a decode error, not a panic");
        assert!(matches!(err, AuthzError::InvalidAttrs(_)));
    }

    #[test]
    fn error_messages_are_actionable_and_secret_free() {
        let messages = [
            AuthzError::NoGrantBound.to_string(),
            AuthzError::RepoNotDeclared {
                owner: "owner".to_string(),
                repo: "x".to_string(),
            }
            .to_string(),
            AuthzError::MissingScope {
                required: "contents:rw".to_string(),
                resolved: "contents:read".to_string(),
            }
            .to_string(),
        ];
        assert_eq!(messages[1], "repo owner/x not declared for this session");
        for message in messages {
            assert!(!message.is_empty());
            // No token material — and nothing that could plausibly be one —
            // ever appears in a deny message (spec R6.2, R8.1).
            for needle in ["ghu_", "gho_", "ghp_", "access_token", "refresh_token"] {
                assert!(
                    !message.contains(needle),
                    "message must not contain {needle:?}: {message}"
                );
            }
        }
    }

    #[test]
    fn read_and_write_github_attrs_round_trip_through_session_config() {
        let original = GithubAttrs {
            grant_id: Some(GrantId::new("grant-42").unwrap()),
            repos: vec![repo("octocat/hello")],
            scopes: Some(ScopeSet::defaults()),
        };

        let mut config = minimald_rpc::SessionConfig {
            name: None,
            project_path: dummy_path(),
            network: NetworkMode::default(),
            policy: SessionPolicy::default(),
            attrs: BTreeMap::new(),
        };
        write_github_attrs(&mut config, &original);

        let record = record_with_attrs(config.attrs);
        let decoded = read_github_attrs(&record).expect("round-tripped attrs must decode");
        assert_eq!(decoded, original);
    }
}
