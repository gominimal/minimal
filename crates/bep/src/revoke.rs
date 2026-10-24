//! Revocations by box id (BEP-043, BEP-067, BEP-071).
//!
//! On an un-enrolled host, the one revocation event is the destroy of a live
//! box. The box's creator sends `record_revocation` over the control socket
//! ([`crate::control`]). The proxy then holds the box id in [`Revocations`],
//! and appends one `revocation` record to the audit log.
//!
//! A revocation covers a sealed value exactly when it names the value's box
//! id ([`covers`]). A box id is unique per creation and never returns
//! (BEP-070), so a box created later, under any name, is covered by no
//! revocation. The redeemer reads the revocations at its decision, before
//! it resolves any sign-in reference ([`crate::redeemer`]). So a revoked
//! value never makes the proxy read the keychain or renew a sign-in.
//!
//! The revocations live in this process. T33
//! (<https://github.com/gominimal/minimal/issues/2290>) restores them from
//! the retained audit segments at start.

use std::sync::PoisonError;

use crate::audit::{self, Decision, Kind, Mapping, Outcome};
pub use crate::redeemer::Revocations;

/// Whether the revocations `revoked` cover a sealed value that names
/// `box_id`: exactly when one of them names that box id (BEP-071).
#[must_use]
pub fn covers<S: AsRef<str>>(revoked: &[S], box_id: &str) -> bool {
    revoked.iter().any(|named| named.as_ref() == box_id)
}

/// The revocations in force for a sealed value that names `box_id`: the
/// ones that name `box_id`, and no other.
#[must_use]
pub fn in_force_for(revocations: &Revocations, box_id: &str) -> Vec<String> {
    revocations
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|named| named.as_str() == box_id)
        .cloned()
        .collect()
}

/// Puts a revocation of `box_id` in force. `true` when it is new, and
/// `false` when a revocation of `box_id` is already in force.
pub fn record(revocations: &Revocations, box_id: &str) -> bool {
    let mut held = revocations.write().unwrap_or_else(PoisonError::into_inner);
    if covers(&held, box_id) {
        return false;
    }
    held.push(box_id.to_owned());
    true
}

/// The audit record of the revocation of `box_id`: kind `revocation`, the
/// box as its subject, and no upstream, identifier or mapping.
#[must_use]
pub fn revocation_record(box_id: &str) -> Decision {
    Decision {
        kind: Kind::Revocation,
        box_id: box_id.to_owned(),
        authority: audit::NONE.to_owned(),
        identifier: None,
        mapping: Mapping::ModuleUnmapped,
        outcome: Outcome::Refuse,
        marker: None,
    }
}

/// The audit record of one member the client minted for `box_id`: kind
/// `mint`, and the member's identifier, `<store>:<id>`, the identifier the
/// proxy's decisions on that member carry.
#[must_use]
pub fn mint_record(box_id: &str, identifier: &str) -> Decision {
    Decision {
        kind: Kind::Mint,
        box_id: box_id.to_owned(),
        authority: audit::NONE.to_owned(),
        identifier: Some(identifier.to_owned()),
        mapping: Mapping::ModuleUnmapped,
        outcome: Outcome::Admit,
        marker: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};

    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;
    use zeroize::Zeroizing;

    use super::*;
    use crate::boxes::{BoxRegistry, Boxes, Stance};
    use crate::control::{Trail, handle_line_with};
    use crate::forward::{Redeemer, Verdict};
    use crate::handle::{self, Claims, ClientKeys, Inject};
    use crate::keys::memory::MemoryStore;
    use crate::keys::{HeldKey as _, KeyStore, Role};
    use crate::module::GITHUB;
    use crate::proxy::AuditWriter;
    use crate::redeem::{Authority, Check, RequestAuthority};
    use crate::redeemer::BoxRedeemer;
    use crate::seal::{self, Breadth, Context, Member, MemberKind, MemberList, Mode};
    use crate::signin::{Flow, Keychain, Material, Metadata, SignInError};

    const NOW: u64 = 1_800_000_000;
    const NODE: &str = "node-1";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";
    const BOX: &str = "0190a1b2c3d47e8f9a0b1c2d3e4f5a6b";

    fn hex_id() -> impl Strategy<Value = String> {
        // A small alphabet, so a drawn value id often equals a revoked one.
        (0u8..6).prop_map(|n| format!("{n:032x}"))
    }

    proptest! {
        // BEP-071: for every set of revocation records and every sealed
        // value, the value is covered iff some record names its box id. A
        // box created after the revocations, under a fresh id, is covered
        // by no record.
        #[test]
        fn prop_revocation_covers_exactly_its_box(
            revoked in prop::collection::vec(hex_id(), 0..6),
            named in hex_id(),
            fresh in any::<u128>(),
        ) {
            let revocations = Revocations::default();
            for id in &revoked {
                record(&revocations, id);
            }
            let named_in_set = revoked.contains(&named);
            let held = revocations.read().unwrap().clone();
            prop_assert_eq!(covers(&held, &named), named_in_set);
            let in_force = in_force_for(&revocations, &named);
            prop_assert!(in_force.iter().all(|id| id == &named));
            prop_assert_eq!(!in_force.is_empty(), named_in_set);

            // A later creation's id: its random fields put it outside the
            // small alphabet the revocations were drawn from.
            let fresh = format!("{:032x}", fresh | (1u128 << 127));
            prop_assert!(!covers(&held, &fresh));
            prop_assert!(in_force_for(&revocations, &fresh).is_empty());
        }
    }

    // BEP-071: a second revocation of the same box adds nothing.
    #[test]
    fn a_revocation_is_recorded_once() {
        let revocations = Revocations::default();
        assert!(record(&revocations, BOX));
        assert!(!record(&revocations, BOX));
        assert_eq!(revocations.read().unwrap().len(), 1);
    }

    /// A keychain that holds one sign-in and counts every read of it.
    struct CountingKeychain {
        reads: Arc<AtomicUsize>,
        token_expires_at: u64,
    }

    impl Keychain for CountingKeychain {
        fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Metadata {
                account: "octocat".into(),
                instance: INSTANCE.into(),
                flow: Flow::Device,
                token_expires_at: self.token_expires_at,
                refresh_expires_at: NOW + 7200,
            }))
        }

        fn material(&self) -> Result<Option<Material>, SignInError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Material {
                instance: INSTANCE.into(),
                access_token: "ghu_the_real_token".into(),
                refresh_token: "ghr_refresh".into(),
            }))
        }

        fn write(&self, _: &Metadata, _: &Material) -> Result<(), SignInError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn api() -> Authority<String> {
        Authority {
            host: "api.github.com".into(),
            port: 443,
        }
    }

    /// Redeems a value sealed for [`BOX`] once from [`BOX`], against a
    /// sign-in whose token expires at `token_expires_at`, after `revoke`
    /// ran on the control socket. Gives the verdict's marker, `None` for an
    /// admit, and the number of keychain reads.
    fn redeem_after(
        token_expires_at: u64,
        revoke: impl FnOnce(&Trail, &BoxRegistry),
    ) -> (Option<&'static str>, usize) {
        let store = MemoryStore::default();
        let key = store.generate(Role::Sealing).unwrap();
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let clients = Arc::new(RwLock::new(keys));
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        boxes.register(BOX, vec![api()], Stance::OwnIp);
        let revocations = Revocations::default();
        let reads = Arc::new(AtomicUsize::new(0));
        let keychain = CountingKeychain {
            reads: Arc::clone(&reads),
            token_expires_at,
        };
        let records = Arc::new(std::sync::Mutex::new(Vec::<Decision>::new()));
        let audit: Arc<dyn AuditWriter> = records.clone();
        let trail = Trail::new(audit, Arc::clone(&revocations));
        revoke(&trail, &boxes);

        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::clone(&clients),
            Arc::clone(&boxes),
            keychain,
        )
        .with_revocations(revocations)
        .with_clock(Arc::new(|| NOW));
        let jws = handle::sign(
            &client,
            &Claims {
                sub: BOX.into(),
                node_id: NODE.into(),
                store: GITHUB.id.into(),
                id: INSTANCE.into(),
                upstream: GITHUB.hosts.iter().map(|a| a.host.to_owned()).collect(),
                inject: None::<Inject>,
                iat: NOW - 10,
                exp: NOW + 3600,
                jti: "jti-1".into(),
            },
        );
        let sealed = seal::seal(
            &sealing,
            &Context {
                box_id: BOX.into(),
                host: NODE.into(),
                module: GITHUB.id.into(),
                host_set_version: GITHUB.host_set_version,
                mode: Mode::User,
                iat: NOW - 10,
                expiry: NOW + 600,
                kid: sealing.kid(),
            },
            &MemberList {
                members: vec![Member {
                    kind: MemberKind::SignIn,
                    breadth: Breadth::Full,
                    jws: Zeroizing::new(jws),
                    exp: None,
                }],
                default_owner: None,
            },
        )
        .unwrap();
        let verdict = redeemer.redeem(
            BOX,
            &api(),
            &RequestAuthority {
                host: Some(api()),
                target: None,
            },
            &sealed,
        );
        let marker = match verdict {
            Verdict::Admit { .. } => None,
            Verdict::Refuse(marker) => Some(marker),
        };
        (marker, reads.load(Ordering::SeqCst))
    }

    fn line(op: &str, box_id: &str) -> String {
        format!(r#"{{"op":"{op}","box_id":"{box_id}"}}"#)
    }

    // BEP-071: a value a revocation covers is refused before any sign-in
    // reference is resolved, so the proxy never reads the keychain for it,
    // and never renews its sign-in. A token past its expiry is the one a
    // renewal would start from.
    #[test]
    fn revoked_value_never_triggers_renewal() {
        let clients = RwLock::new(ClientKeys::new());
        for token_expires_at in [NOW + 3600, NOW - 1] {
            // Not revoked: the decision reaches the keychain.
            let (_, reads) = redeem_after(token_expires_at, |_, _| {});
            assert!(reads > 0, "an unrevoked value reads the sign-in");

            // Revoked over the control socket: refused `revoked`, and the
            // keychain is never read.
            let (marker, reads) = redeem_after(token_expires_at, |trail, boxes| {
                let reply =
                    handle_line_with(&line("record_revocation", BOX), &clients, boxes, trail);
                assert!(reply.ok, "{reply:?}");
            });
            assert_eq!(marker, Some(Check::Revoked.marker()));
            assert_eq!(reads, 0, "a revoked value never reads the sign-in");

            // Revoked and forgotten, as a destroy does: still refused, and
            // still no keychain read.
            let (marker, reads) = redeem_after(token_expires_at, |trail, boxes| {
                for op in ["record_revocation", "forget_box"] {
                    let reply = handle_line_with(&line(op, BOX), &clients, boxes, trail);
                    assert!(reply.ok, "{reply:?}");
                }
            });
            assert!(marker.is_some(), "a destroyed box's value is refused");
            assert_eq!(reads, 0);
        }
    }
}
