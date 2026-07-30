//! Fuzzy filtering of the session list, reusing [`common::fuzzy_match`]
//! against each session's name, id, and project path.

use common::fuzzy_search::{SearchMatch, fuzzy_match};
use minimald_rpc::ListSessionsEntry;

/// The best fuzzy match of `filter` against a session's name, id, and
/// project path (last path segment). An empty filter matches everything
/// at the lowest rank so callers can treat "no filter" uniformly.
pub fn session_match(filter: &str, entry: &ListSessionsEntry) -> Option<SearchMatch> {
    if filter.is_empty() {
        return Some(SearchMatch::Fuzzy { score: 0 });
    }
    let id = entry.id.to_string();
    let project_segment = entry
        .project_path
        .as_ref()
        .and_then(|p| p.as_utf8_path().file_name())
        .unwrap_or("");
    [
        entry.name.as_deref().and_then(|n| fuzzy_match(filter, n)),
        fuzzy_match(filter, &id),
        fuzzy_match(filter, project_segment),
    ]
    .into_iter()
    .flatten()
    .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: Option<&str>, project: &str) -> ListSessionsEntry {
        ListSessionsEntry {
            id: sessions::SessionId::nil(),
            name: name.map(str::to_owned),
            project_path: Some(paths::HostAbsPath::try_new(project).unwrap()),
            status: sessions::SessionStatus::Active,
            attrs: None,
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        assert!(session_match("", &entry(Some("api"), "/src/api")).is_some());
        assert!(session_match("", &entry(None, "/src/api")).is_some());
    }

    #[test]
    fn matches_name_prefix() {
        // Project segment doesn't match, so the name prefix is the best rank.
        assert!(matches!(
            session_match("api", &entry(Some("api-staging"), "/work/other")),
            Some(SearchMatch::PrefixMatch { .. })
        ));
    }

    #[test]
    fn matches_project_path_segment() {
        assert!(session_match("api", &entry(None, "/home/u/src/api")).is_some());
    }

    #[test]
    fn rejects_non_matching_filter() {
        assert!(session_match("zzz", &entry(Some("api"), "/src/api")).is_none());
    }

    #[test]
    fn exact_name_beats_fuzzy_project_match() {
        let exact = session_match("api", &entry(Some("api"), "/work/other")).unwrap();
        let fuzzy = session_match("api", &entry(Some("bench"), "/work/a-p-i")).unwrap();
        assert!(exact > fuzzy);
    }
}
