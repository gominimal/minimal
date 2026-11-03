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

    const BOX: &str = "0190f0e0a1b2c3d4e5f60718293a4b5c";
    const OTHER: &str = "0190f0e0a1b2c3d4e5f60718293a4b5d";

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
                box_id: BOX.into(),
                egress: vec!["api.github.com".into(), "GitHub.com:8443".into()],
                stance: Stance::OwnIp,
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(
            boxes.egress(BOX),
            vec![
                authority("api.github.com", 443),
                authority("github.com", 8443)
            ]
        );
        assert_eq!(boxes.attribution(BOX), Attribution::OwnIp(BOX.into()));
        assert!(boxes.egress(OTHER).is_empty());

        // A new registration decides the next read.
        let reply = control::handle_line(
            &line(&Request::RegisterBox {
                box_id: BOX.into(),
                egress: vec!["codeload.github.com".into()],
                stance: Stance::HostIp,
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(
            boxes.egress(BOX),
            vec![authority("codeload.github.com", 443)]
        );
        assert_eq!(boxes.attribution(BOX), Attribution::HostIpCohort);
        assert_eq!(boxes.cohort(), vec![BOX.to_owned()]);

        // An authority that does not parse refuses the whole registration.
        let reply = control::handle_line(
            &line(&Request::RegisterBox {
                box_id: BOX.into(),
                egress: vec!["github.com:notaport".into()],
                stance: Stance::OwnIp,
            }),
            &keys,
            &boxes,
        );
        assert!(!reply.ok);
        assert_eq!(
            boxes.egress(BOX),
            vec![authority("codeload.github.com", 443)]
        );

        // An uppercase or hyphenated id is stored in the listener's form.
        let reply = control::handle_line(
            &line(&Request::RegisterBox {
                box_id: "0190F0E0-A1B2-C3D4-E5F6-0718293A4B5D".into(),
                egress: vec!["github.com".into()],
                stance: Stance::OwnIp,
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(boxes.egress(OTHER), vec![authority("github.com", 443)]);

        // An id that is not 32 hex digits is refused, and registers nothing.
        for bad in [
            "",
            "b1",
            "0190f0e0a1b2c3d4e5f60718293a4b5",
            "0190f0e0a1b2c3d4e5f60718293a4b5g",
        ] {
            let reply = control::handle_line(
                &line(&Request::RegisterBox {
                    box_id: bad.into(),
                    egress: vec!["github.com".into()],
                    stance: Stance::OwnIp,
                }),
                &keys,
                &boxes,
            );
            assert!(!reply.ok, "{bad:?} was registered");
            assert!(boxes.get(bad).is_none());
        }
    }

    #[test]
    fn forgotten_box_is_refused_no_live_box() {
        let keys = RwLock::new(ClientKeys::new());
        let boxes = Boxes::new();
        boxes.register(BOX, vec![authority("github.com", 443)], Stance::OwnIp);
        // An id that is not 32 hex digits is refused, and forgets nothing.
        let reply = control::handle_line(
            &line(&Request::ForgetBox {
                box_id: "b1".into(),
            }),
            &keys,
            &boxes,
        );
        assert!(!reply.ok);
        assert_eq!(boxes.egress(BOX), vec![authority("github.com", 443)]);
        // The uppercase form of the id forgets the box.
        let reply = control::handle_line(
            &line(&Request::ForgetBox {
                box_id: BOX.to_ascii_uppercase(),
            }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(boxes.attribution(BOX), Attribution::NoLiveBox);
        assert!(boxes.egress(BOX).is_empty());
        assert!(boxes.cohort().is_empty());
        // Forgetting a box that is not registered is not an error.
        let reply = control::handle_line(
            &line(&Request::ForgetBox { box_id: BOX.into() }),
            &keys,
            &boxes,
        );
        assert!(reply.ok, "{reply:?}");
    }
}
