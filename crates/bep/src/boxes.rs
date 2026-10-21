//! The boxes this proxy serves: each box's declared egress and its address
//! stance (BEP-020, BEP-022).
//!
//! The box's creator registers the box over the control socket
//! ([`crate::control`]) when it creates the box, and forgets it when it
//! destroys the box. The proxy reads the registry at each request, so a
//! registration decides the next request. A box id that is not registered
//! has no declared egress, so the proxy refuses every request from it
//! `outside_declared_egress`, and attributes it to no live box.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use serde::{Deserialize, Serialize};

use crate::redeem::{Attribution, Authority};

/// How a box's traffic reaches the proxy: from an address of its own, or
/// from the address this host's `host_ip` boxes share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stance {
    /// The box sends from an address of its own.
    OwnIp,
    /// The box sends from the address this host's `host_ip` boxes share.
    HostIp,
}

/// One registered box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxEgress {
    /// The authorities the box's declared egress admits.
    pub egress: Vec<Authority<String>>,
    /// The box's address stance.
    pub stance: Stance,
}

/// The registered boxes, by box id. Shared between the control socket and
/// the redeemer.
#[derive(Debug, Default)]
pub struct Boxes {
    boxes: RwLock<HashMap<String, BoxEgress>>,
}

/// The box registry as the control socket and the redeemer share it.
pub type BoxRegistry = Arc<Boxes>;

impl Boxes {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `box_id` with its declared egress and its stance. A second
    /// registration of the same id replaces the first.
    pub fn register(&self, box_id: &str, egress: Vec<Authority<String>>, stance: Stance) {
        tracing::debug!(
            box_id,
            authorities = egress.len(),
            ?stance,
            "registered a box's declared egress"
        );
        self.boxes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(box_id.to_owned(), BoxEgress { egress, stance });
    }

    /// Forgets `box_id`. Returns whether it was registered.
    pub fn forget(&self, box_id: &str) -> bool {
        let removed = self
            .boxes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(box_id)
            .is_some();
        tracing::debug!(box_id, removed, "forgot a box");
        removed
    }

    /// The registration of `box_id`, if any.
    #[must_use]
    pub fn get(&self, box_id: &str) -> Option<BoxEgress> {
        self.boxes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(box_id)
            .cloned()
    }

    /// The authorities the declared egress of `box_id` admits. None for a
    /// box that is not registered (BEP-022).
    #[must_use]
    pub fn egress(&self, box_id: &str) -> Vec<Authority<String>> {
        self.get(box_id).map(|b| b.egress).unwrap_or_default()
    }

    /// The box a connection from `box_id` is attributed to (BEP-020).
    #[must_use]
    pub fn attribution(&self, box_id: &str) -> Attribution<String> {
        match self.get(box_id).map(|b| b.stance) {
            None => Attribution::NoLiveBox,
            Some(Stance::OwnIp) => Attribution::OwnIp(box_id.to_owned()),
            Some(Stance::HostIp) => Attribution::HostIpCohort,
        }
    }

    /// The ids of the registered `host_ip` boxes, in a stable order.
    #[must_use]
    pub fn cohort(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .boxes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, b)| b.stance == Stance::HostIp)
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use super::*;
    use crate::control::{self, Request};
    use crate::handle::ClientKeys;

    fn line(request: &Request) -> String {
        serde_json::to_string(request).unwrap()
    }

    fn authority(host: &str, port: u16) -> Authority<String> {
        Authority {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn registered_box_egress_is_read_per_request() {
        let keys = RwLock::new(ClientKeys::new());
        let boxes = Boxes::new();
        let reply = control::handle_line(
            &line(&Request::RegisterBox {
                box_id: "b1".into(),
                egress: vec!["api.github.com".into(), "GitHub.com:8443".into()],
                stance: Stance::OwnIp,
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(
            boxes.egress("b1"),
            vec![
                authority("api.github.com", 443),
                authority("github.com", 8443)
            ]
        );
        assert_eq!(boxes.attribution("b1"), Attribution::OwnIp("b1".into()));
        assert!(boxes.egress("b2").is_empty());

        // A new registration decides the next read.
        let reply = control::handle_line(
            &line(&Request::RegisterBox {
                box_id: "b1".into(),
                egress: vec!["codeload.github.com".into()],
                stance: Stance::HostIp,
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(
            boxes.egress("b1"),
            vec![authority("codeload.github.com", 443)]
        );
        assert_eq!(boxes.attribution("b1"), Attribution::HostIpCohort);
        assert_eq!(boxes.cohort(), vec!["b1".to_owned()]);

        // An authority that does not parse refuses the whole registration.
        let reply = control::handle_line(
            &line(&Request::RegisterBox {
                box_id: "b1".into(),
                egress: vec!["github.com:notaport".into()],
                stance: Stance::OwnIp,
            }),
            &keys,
            &boxes,
        );
        assert!(!reply.ok);
        assert_eq!(
            boxes.egress("b1"),
            vec![authority("codeload.github.com", 443)]
        );
    }

    #[test]
    fn forgotten_box_is_refused_no_live_box() {
        let keys = RwLock::new(ClientKeys::new());
        let boxes = Boxes::new();
        boxes.register("b1", vec![authority("github.com", 443)], Stance::OwnIp);
        let reply = control::handle_line(
            &line(&Request::ForgetBox {
                box_id: "b1".into(),
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(boxes.attribution("b1"), Attribution::NoLiveBox);
        assert!(boxes.egress("b1").is_empty());
        assert!(boxes.cohort().is_empty());
        // Forgetting a box that is not registered is not an error.
        let reply = control::handle_line(
            &line(&Request::ForgetBox {
                box_id: "b1".into(),
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
    }
}
