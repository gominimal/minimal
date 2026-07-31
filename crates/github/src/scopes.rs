//! Typed GitHub App permission model (spec R5).
//!
//! The set of representable permissions is closed to exactly what the MVP needs.
//! Crucially, there is **no** `workflows` variant: the GitHub Actions workflow
//! permission is unrepresentable by construction, so no code path — not even a
//! typo — can request it (spec NG6). A request for `workflows` in a config
//! string is rejected as an unknown scope.

use std::collections::BTreeMap;
use std::fmt;

use crate::error::Error;

/// A GitHub App repository permission.
///
/// Ordering is the canonical consent-render order (`contents`, `pull_requests`,
/// `issues`, `metadata`) so a [`ScopeSet`] backed by a `BTreeMap` renders
/// deterministically.
///
/// `#[non_exhaustive]`: more permissions may be added, but `workflows` will not
/// be (spec NG6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// Repository contents: clone, fetch, push, branches, commits.
    Contents,
    /// Pull requests: open and update PRs.
    PullRequests,
    /// Issues: standard dev work via the GitHub MCP.
    Issues,
    /// Repository metadata: the mandatory read-only baseline.
    Metadata,
}

impl Scope {
    /// The canonical wire/consent name of this permission.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Contents => "contents",
            Scope::PullRequests => "pull_requests",
            Scope::Issues => "issues",
            Scope::Metadata => "metadata",
        }
    }

    /// Parses a canonical scope name. Unknown names — including the deliberately
    /// excluded `workflows` (spec NG6) — are rejected.
    pub fn parse(name: &str) -> Result<Self, Error> {
        match name {
            "contents" => Ok(Scope::Contents),
            "pull_requests" => Ok(Scope::PullRequests),
            "issues" => Ok(Scope::Issues),
            "metadata" => Ok(Scope::Metadata),
            other => Err(Error::InvalidScope {
                input: other.to_string(),
                reason: "unknown or unsupported permission".to_string(),
            }),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The access level requested for a [`Scope`]. `Write` implies read (GitHub's
/// `write` permission subsumes `read`), rendered `rw` for consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// Read-only access.
    Read,
    /// Read/write access (rendered `rw`).
    Write,
}

impl Permission {
    /// The canonical consent/wire rendering: `read` or `rw`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Write => "rw",
        }
    }

    /// Parses a permission token. Accepts `read`, and `rw`/`write` for write.
    pub fn parse(token: &str) -> Result<Self, Error> {
        match token {
            "read" => Ok(Permission::Read),
            "rw" | "write" => Ok(Permission::Write),
            other => Err(Error::InvalidScope {
                input: other.to_string(),
                reason: "permission must be `read` or `rw`".to_string(),
            }),
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolved set of permissions to request, one level per [`Scope`].
///
/// The backing map keys on `Scope`, whose ordering is the consent-render order,
/// so [`ScopeSet::render_for_consent`] and [`ScopeSet::to_attr_value`] are
/// deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet {
    perms: BTreeMap<Scope, Permission>,
}

impl ScopeSet {
    /// An empty scope set.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            perms: BTreeMap::new(),
        }
    }

    /// The R5.1 default scope set: `contents:rw`, `pull_requests:rw`,
    /// `issues:rw`, `metadata:read`. `workflows` is excluded (spec NG6) and is
    /// not even representable here.
    #[must_use]
    pub fn defaults() -> Self {
        let mut perms = BTreeMap::new();
        perms.insert(Scope::Contents, Permission::Write);
        perms.insert(Scope::PullRequests, Permission::Write);
        perms.insert(Scope::Issues, Permission::Write);
        perms.insert(Scope::Metadata, Permission::Read);
        Self { perms }
    }

    /// Sets the permission for a scope, returning the updated set (builder style).
    #[must_use]
    pub fn with(mut self, scope: Scope, permission: Permission) -> Self {
        self.perms.insert(scope, permission);
        self
    }

    /// The requested permission for `scope`, if any.
    #[must_use]
    pub fn permission(&self, scope: Scope) -> Option<Permission> {
        self.perms.get(&scope).copied()
    }

    /// Whether the set requests any level for `scope`.
    #[must_use]
    pub fn contains(&self, scope: Scope) -> bool {
        self.perms.contains_key(&scope)
    }

    /// Iterates the `(scope, permission)` pairs in consent-render order.
    pub fn iter(&self) -> impl Iterator<Item = (Scope, Permission)> + '_ {
        self.perms.iter().map(|(s, p)| (*s, *p))
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.perms.is_empty()
    }

    /// Human-facing consent line, e.g. `contents:rw, pull_requests:rw,
    /// issues:rw, metadata:read` (spec R5.3). Comma-and-space separated.
    #[must_use]
    pub fn render_for_consent(&self) -> String {
        self.perms
            .iter()
            .map(|(s, p)| format!("{s}:{p}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Compact, parseable form for session `attrs`, e.g.
    /// `contents:rw,pull_requests:rw,issues:rw,metadata:read` (no spaces).
    #[must_use]
    pub fn to_attr_value(&self) -> String {
        self.perms
            .iter()
            .map(|(s, p)| format!("{s}:{p}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Parses the compact `attrs` form produced by [`ScopeSet::to_attr_value`].
    /// Rejects unknown scopes (including `workflows`) and malformed entries.
    pub fn from_attr_value(value: &str) -> Result<Self, Error> {
        let mut perms = BTreeMap::new();
        for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (scope, perm) = entry.split_once(':').ok_or_else(|| Error::InvalidScope {
                input: entry.to_string(),
                reason: "expected `scope:permission`".to_string(),
            })?;
            perms.insert(Scope::parse(scope)?, Permission::parse(perm)?);
        }
        Ok(Self { perms })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_r5_1() {
        let set = ScopeSet::defaults();
        assert_eq!(set.permission(Scope::Contents), Some(Permission::Write));
        assert_eq!(set.permission(Scope::PullRequests), Some(Permission::Write));
        assert_eq!(set.permission(Scope::Issues), Some(Permission::Write));
        assert_eq!(set.permission(Scope::Metadata), Some(Permission::Read));
    }

    #[test]
    fn defaults_render_in_canonical_order() {
        assert_eq!(
            ScopeSet::defaults().render_for_consent(),
            "contents:rw, pull_requests:rw, issues:rw, metadata:read"
        );
    }

    #[test]
    fn workflows_is_unrepresentable_and_rejected() {
        // Not a known scope: parsing any config that names it fails closed.
        assert!(Scope::parse("workflows").is_err());
        assert!(ScopeSet::from_attr_value("workflows:read").is_err());
        assert!(ScopeSet::from_attr_value("contents:rw,workflows:rw").is_err());
        // And the defaults never carry it.
        assert!(
            !ScopeSet::defaults()
                .render_for_consent()
                .contains("workflows")
        );
    }

    #[test]
    fn attr_value_round_trips() {
        let set = ScopeSet::defaults();
        let encoded = set.to_attr_value();
        assert_eq!(
            encoded,
            "contents:rw,pull_requests:rw,issues:rw,metadata:read"
        );
        assert_eq!(ScopeSet::from_attr_value(&encoded).unwrap(), set);
    }

    #[test]
    fn rejects_malformed_scope_entries() {
        assert!(ScopeSet::from_attr_value("contents").is_err()); // no permission
        assert!(ScopeSet::from_attr_value("contents:sideways").is_err()); // bad perm
        assert!(ScopeSet::from_attr_value("nope:rw").is_err()); // bad scope
    }
}
