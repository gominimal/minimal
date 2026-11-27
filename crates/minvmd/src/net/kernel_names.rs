//! Numbers for box-zone names, as the decision kernel wants them.
//!
//! The kernel compares names as numbers: a row carries the number of its
//! own name and the numbers of the box-zone names its `allow_dns_hosts`
//! lists, and two numbers are equal exactly when the names are. This is
//! the one place that gives a name its number.
//!
//! A number is never given to two names. A name keeps its number for as
//! long as any row holds it, as its own name or as a listed one, so a row
//! that lists `web.min.internal` before a box of that name exists matches
//! that box when it is registered or renamed. When the last hold is
//! released the name is forgotten, and a later hold gives it a new number.

use std::collections::HashMap;

use boxes::core::zone_answer::ZONE_APEX;

use crate::box_registry::canonical_box_name;
use crate::net::baseline::HOST_ALIAS_NAME;

/// The number no name has: a row without a name carries it, and no list
/// holds it.
pub(crate) const NO_NAME: u32 = 0;

/// The names held, each with its number and how many holds it has.
#[derive(Debug, Default)]
pub(crate) struct NameIds {
    held: HashMap<String, (u32, usize)>,
    /// The last number given out.
    last: u32,
}

/// The zone name of the box called `name`: `<name>.min.internal`, ASCII
/// lower-case.
pub(crate) fn zone_name(name: &str) -> String {
    format!("{}.{ZONE_APEX}", canonical_box_name(name))
}

/// Whether `allow_dns_hosts` names the host alias, `host.min.internal`, as
/// the box's half of a host exposure (NET-160).
pub(crate) fn names_host(allow_dns_hosts: &[String]) -> bool {
    allow_dns_hosts.iter().any(|host| {
        host.trim_end_matches('.')
            .eq_ignore_ascii_case(HOST_ALIAS_NAME)
    })
}

/// The box-zone names `allow_dns_hosts` lists, ASCII lower-case and with no
/// trailing dot: the names under the box zone that are neither its apex
/// nor the host alias's (NET-163). Each once, in the order first listed.
pub(crate) fn listed_zone_names(allow_dns_hosts: &[String]) -> Vec<String> {
    let suffix = format!(".{ZONE_APEX}");
    let mut names: Vec<String> = Vec::new();
    for host in allow_dns_hosts {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.len() > suffix.len()
            && host.ends_with(&suffix)
            && host != HOST_ALIAS_NAME
            && !names.contains(&host)
        {
            names.push(host);
        }
    }
    names
}

impl NameIds {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Takes one hold on `zone_name` and returns its number: the number it
    /// has while held, or a new one. `None`, and nothing changes, when
    /// every number has been given out.
    pub(crate) fn hold(&mut self, zone_name: &str) -> Option<u32> {
        if let Some((id, holds)) = self.held.get_mut(zone_name) {
            *holds += 1;
            return Some(*id);
        }
        let id = self.last.checked_add(1)?;
        self.last = id;
        self.held.insert(zone_name.to_string(), (id, 1));
        Some(id)
    }

    /// Gives back one hold on `zone_name`. The name is forgotten with its
    /// last hold. A name that is not held is left alone.
    pub(crate) fn release(&mut self, zone_name: &str) {
        let Some((_, holds)) = self.held.get_mut(zone_name) else {
            return;
        };
        if *holds > 1 {
            *holds -= 1;
        } else {
            self.held.remove(zone_name);
        }
    }

    /// Takes one hold on each of `zone_names` and returns their numbers in
    /// the same order. `None`, and no hold is kept, when the numbers run
    /// out part way.
    pub(crate) fn hold_all(&mut self, zone_names: &[String]) -> Option<Vec<u32>> {
        let mut ids = Vec::with_capacity(zone_names.len());
        for (taken, name) in zone_names.iter().enumerate() {
            match self.hold(name) {
                Some(id) => ids.push(id),
                None => {
                    for earlier in zone_names.iter().take(taken) {
                        self.release(earlier);
                    }
                    return None;
                }
            }
        }
        Some(ids)
    }

    /// Gives back one hold on each of `zone_names`.
    pub(crate) fn release_all(&mut self, zone_names: &[String]) {
        for name in zone_names {
            self.release(name);
        }
    }

    /// How many names are held.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn a_name_keeps_its_number_while_any_row_holds_it() {
        let mut ids = NameIds::new();
        let listed = ids.hold("web.min.internal").unwrap();
        // The box of that name is registered later and matches.
        let own = ids.hold(&zone_name("Web")).unwrap();
        assert_eq!(own, listed);
        assert_ne!(own, NO_NAME);
        ids.release("web.min.internal");
        assert_eq!(ids.hold("web.min.internal"), Some(listed));
    }

    #[test]
    fn two_names_never_share_a_number_and_a_forgotten_number_is_not_given_again() {
        let mut ids = NameIds::new();
        let web = ids.hold("web.min.internal").unwrap();
        let db = ids.hold("db.min.internal").unwrap();
        assert_ne!(web, db);
        ids.release("web.min.internal");
        assert_eq!(ids.len(), 1);
        let again = ids.hold("web.min.internal").unwrap();
        assert_ne!(again, web);
        assert_ne!(again, db);
    }

    #[test]
    fn releasing_a_name_that_is_not_held_changes_nothing() {
        let mut ids = NameIds::new();
        let web = ids.hold("web.min.internal").unwrap();
        ids.release("db.min.internal");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids.hold("web.min.internal"), Some(web));
    }

    #[test]
    fn the_listed_names_are_the_box_zone_names_and_no_others() {
        let listed = listed_zone_names(&strings(&[
            "Web.min.internal.",
            "github.com",
            "min.internal",
            "host.min.internal",
            "web.min.internal",
            "db.min.internal",
        ]));
        assert_eq!(listed, strings(&["web.min.internal", "db.min.internal"]));
    }

    #[test]
    fn the_host_is_named_by_its_alias_name_in_any_case_and_by_nothing_else() {
        assert!(names_host(&strings(&["github.com", "Host.Min.Internal."])));
        assert!(!names_host(&strings(&["web.min.internal", "min.internal"])));
        assert!(!names_host(&[]));
    }

    #[test]
    fn when_the_numbers_run_out_nothing_is_held() {
        let mut ids = NameIds {
            held: HashMap::new(),
            last: u32::MAX - 1,
        };
        assert!(
            ids.hold_all(&strings(&["a.min.internal", "b.min.internal"]))
                .is_none()
        );
        assert_eq!(ids.len(), 0);
        assert_eq!(ids.hold("a.min.internal"), None);
    }
}
