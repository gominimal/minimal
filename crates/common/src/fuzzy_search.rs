//! Fuzzy string matching for package name search.

use std::cmp::Ordering;

/// Describes the quality of a search match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMatch {
    /// The needle matches the haystack exactly (case-insensitive).
    ExactMatch,
    /// The haystack starts with the needle.
    PrefixMatch { haystack_len: u32 },
    /// The haystack contains the needle as a substring.
    ContainsMatch { extra_len: u32 },
    /// The needle matches the haystack fuzzily (characters appear in order).
    Fuzzy { score: u32 },
}

impl Ord for SearchMatch {
    fn cmp(&self, other: &Self) -> Ordering {
        fn rank(m: &SearchMatch) -> u8 {
            match m {
                SearchMatch::ExactMatch => 3,
                SearchMatch::PrefixMatch { .. } => 2,
                SearchMatch::ContainsMatch { .. } => 1,
                SearchMatch::Fuzzy { .. } => 0,
            }
        }

        match rank(self).cmp(&rank(other)) {
            Ordering::Equal => match (self, other) {
                (
                    SearchMatch::PrefixMatch { haystack_len: a },
                    SearchMatch::PrefixMatch { haystack_len: b },
                ) => b.cmp(a), // shorter haystack = better
                (
                    SearchMatch::ContainsMatch { extra_len: a },
                    SearchMatch::ContainsMatch { extra_len: b },
                ) => b.cmp(a), // less extra = better
                (SearchMatch::Fuzzy { score: a }, SearchMatch::Fuzzy { score: b }) => a.cmp(b), // higher score = better
                _ => Ordering::Equal,
            },
            ord => ord,
        }
    }
}

impl PartialOrd for SearchMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Performs a fuzzy match of `needle` against `haystack`, returning a [`SearchMatch`]
/// describing the quality of the match. Returns `None` if there is no meaningful match.
pub fn fuzzy_match(needle: &str, haystack: &str) -> Option<SearchMatch> {
    let n = needle.trim().to_lowercase();
    let h = haystack.trim().to_lowercase();

    if n == h {
        return Some(SearchMatch::ExactMatch);
    }
    if h.contains(n.as_str()) {
        if h.starts_with(n.as_str()) {
            return Some(SearchMatch::PrefixMatch {
                haystack_len: h.len() as u32,
            });
        }
        return Some(SearchMatch::ContainsMatch {
            extra_len: (h.len() - n.len()) as u32,
        });
    }

    let mut h_rest = h.as_str();
    let mut score = 0u32;
    let mut consecutive_bonus = 0u32;
    let mut matched = 0u32;

    for ch in n.chars() {
        if let Some(idx) = h_rest.find(ch) {
            consecutive_bonus = if idx == 0 && matched > 0 {
                consecutive_bonus + 1
            } else {
                0
            };
            score += 10 + consecutive_bonus;
            h_rest = &h_rest[idx + ch.len_utf8()..];
            matched += 1;
        }
    }

    let n_len = n.chars().count() as u32;
    let h_len = h.chars().count() as u32;
    let char_score = score * 10 / (n_len * 11); // approx divide by 1.1
    let length_penalty_num = n_len * 100 / n_len.max(h_len);
    let final_score = char_score * length_penalty_num / 100;

    if final_score < 3 {
        return None;
    }
    Some(SearchMatch::Fuzzy { score: final_score })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert_eq!(
            fuzzy_match("libffi", "libffi"),
            Some(SearchMatch::ExactMatch)
        );
        assert_eq!(
            fuzzy_match("LibFFI", "libffi"),
            Some(SearchMatch::ExactMatch)
        );
    }

    #[test]
    fn prefix_match() {
        assert!(matches!(
            fuzzy_match("lib", "libffi"),
            Some(SearchMatch::PrefixMatch { .. })
        ));
    }

    #[test]
    fn contains_match() {
        assert!(matches!(
            fuzzy_match("lib", "zlib"),
            Some(SearchMatch::ContainsMatch { .. })
        ));
    }

    #[test]
    fn fuzzy() {
        assert!(
            matches!(
                fuzzy_match("lbffi", "libffi"),
                Some(SearchMatch::Fuzzy { .. })
            ),
            "got: {:?}",
            fuzzy_match("lbffi", "libffi")
        );
    }

    #[test]
    fn no_match() {
        assert_eq!(fuzzy_match("xyz", "libffi"), None);
    }

    #[test]
    fn ordering() {
        let exact = SearchMatch::ExactMatch;
        let prefix = SearchMatch::PrefixMatch { haystack_len: 6 };
        let contains = SearchMatch::ContainsMatch { extra_len: 1 };
        let fuzzy = SearchMatch::Fuzzy { score: 50 };

        assert!(exact > prefix);
        assert!(prefix > contains);
        assert!(contains > fuzzy);

        // Within PrefixMatch: shorter haystack is better
        let short_prefix = SearchMatch::PrefixMatch { haystack_len: 4 };
        let long_prefix = SearchMatch::PrefixMatch { haystack_len: 10 };
        assert!(short_prefix > long_prefix);

        // Within ContainsMatch: less extra is better
        let small_extra = SearchMatch::ContainsMatch { extra_len: 1 };
        let large_extra = SearchMatch::ContainsMatch { extra_len: 5 };
        assert!(small_extra > large_extra);

        // Within Fuzzy: higher score is better
        let high_score = SearchMatch::Fuzzy { score: 80 };
        let low_score = SearchMatch::Fuzzy { score: 20 };
        assert!(high_score > low_score);
    }
}
