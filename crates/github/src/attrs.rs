//! Codec between the GitHub domain types and `SessionConfig.attrs` (spec R7.1).
//!
//! Repo pre-priming and scope selection are carried first as free-form string
//! `attrs` (a `BTreeMap<String, String>` on the session config/record) and
//! promotable to typed fields later. This module is the one place that knows the
//! key names and the string encodings, so encode/decode stay in lockstep.
//!
//! Keys:
//! * `github.grant_id` — the reused/minted grant id (spec R6.4).
//! * `github.repos` — comma-separated `owner/repo[@branch[:base]]` specs (spec R2.1).
//! * `github.scopes` — the compact [`ScopeSet`] encoding (spec R5).

use std::collections::BTreeMap;
use std::str::FromStr;

use crate::error::Error;
use crate::scopes::ScopeSet;
use crate::types::{GrantId, RepoSpec};

/// `attrs` key for the grant id.
pub const ATTR_GRANT_ID: &str = "github.grant_id";
/// `attrs` key for the repo pre-priming list.
pub const ATTR_REPOS: &str = "github.repos";
/// `attrs` key for the resolved scope set.
pub const ATTR_SCOPES: &str = "github.scopes";

/// The GitHub-relevant slice of a session's `attrs`, decoded into typed values.
///
/// All fields are optional so a session with no GitHub involvement decodes to an
/// empty value and encodes to nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GithubAttrs {
    /// The reused or minted grant id, if any.
    pub grant_id: Option<GrantId>,
    /// The repositories to pre-prime.
    pub repos: Vec<RepoSpec>,
    /// The resolved scope set, if one was recorded.
    pub scopes: Option<ScopeSet>,
}

impl GithubAttrs {
    /// Whether this carries no GitHub configuration at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grant_id.is_none() && self.repos.is_empty() && self.scopes.is_none()
    }

    /// Writes the present fields into `attrs`. Absent fields are left untouched;
    /// an empty repo list writes no key (so it round-trips with `decode`).
    pub fn encode_into(&self, attrs: &mut BTreeMap<String, String>) {
        if let Some(grant_id) = &self.grant_id {
            attrs.insert(ATTR_GRANT_ID.to_string(), grant_id.to_string());
        }
        if !self.repos.is_empty() {
            let joined = self
                .repos
                .iter()
                .map(RepoSpec::to_string)
                .collect::<Vec<_>>()
                .join(",");
            attrs.insert(ATTR_REPOS.to_string(), joined);
        }
        if let Some(scopes) = &self.scopes {
            attrs.insert(ATTR_SCOPES.to_string(), scopes.to_attr_value());
        }
    }

    /// Reads the GitHub fields from `attrs`, parsing each value. Absent keys
    /// yield the empty/`None` default; present-but-malformed values are an error.
    pub fn decode(attrs: &BTreeMap<String, String>) -> Result<Self, Error> {
        let grant_id = match attrs.get(ATTR_GRANT_ID) {
            Some(value) => Some(GrantId::from_str(value)?),
            None => None,
        };
        let repos = match attrs.get(ATTR_REPOS) {
            Some(value) => value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(RepoSpec::from_str)
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let scopes = match attrs.get(ATTR_SCOPES) {
            Some(value) => Some(ScopeSet::from_attr_value(value)?),
            None => None,
        };
        Ok(Self {
            grant_id,
            repos,
            scopes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_full_set() {
        let original = GithubAttrs {
            grant_id: Some(GrantId::new("grant-abc").unwrap()),
            repos: vec![
                "octocat/hello@feat/x:main".parse().unwrap(),
                "my-org/api".parse().unwrap(),
            ],
            scopes: Some(ScopeSet::defaults()),
        };

        let mut map = BTreeMap::new();
        original.encode_into(&mut map);

        assert_eq!(map.get(ATTR_GRANT_ID).unwrap(), "grant-abc");
        assert_eq!(
            map.get(ATTR_REPOS).unwrap(),
            "octocat/hello@feat/x:main,my-org/api"
        );

        let decoded = GithubAttrs::decode(&map).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn empty_encodes_to_nothing_and_round_trips() {
        let empty = GithubAttrs::default();
        assert!(empty.is_empty());
        let mut map = BTreeMap::new();
        empty.encode_into(&mut map);
        assert!(map.is_empty());
        assert_eq!(GithubAttrs::decode(&map).unwrap(), empty);
    }

    #[test]
    fn preserves_unrelated_attrs() {
        let mut map = BTreeMap::new();
        map.insert("other.key".to_string(), "value".to_string());
        GithubAttrs {
            grant_id: Some(GrantId::new("g").unwrap()),
            ..Default::default()
        }
        .encode_into(&mut map);
        assert_eq!(map.get("other.key").unwrap(), "value");
    }

    #[test]
    fn decode_rejects_malformed_values() {
        let mut map = BTreeMap::new();
        map.insert(ATTR_REPOS.to_string(), "not a repo spec".to_string());
        assert!(GithubAttrs::decode(&map).is_err());

        let mut map = BTreeMap::new();
        map.insert(ATTR_SCOPES.to_string(), "workflows:rw".to_string());
        assert!(GithubAttrs::decode(&map).is_err());
    }
}
