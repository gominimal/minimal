//! Revocations by box id (BEP-043, BEP-071).
//!
//! A revocation names one box id, and nothing more. It covers a sealed value
//! exactly when it names the value's box id. A box id is minted fresh for
//! each creation and never returns (BEP-070), so a box created later, under
//! any name, is covered by no earlier revocation.
//!
//! The control socket records a revocation when a live box is destroyed
//! ([`crate::control`], `revoke_box`). The redeemer reads the set at each
//! request and gives it to [`crate::redeem::decide`], which refuses a
//! covered value before the redeemer resolves any reference or renews any
//! sign-in ([`crate::redeemer`], step 4).

use std::sync::PoisonError;

use crate::redeemer::Revocations;

/// True when a revocation in `revoked` covers a value that names `box_id`:
/// some revocation names exactly that id (BEP-071).
#[must_use]
pub fn covers<B: PartialEq>(revoked: &[B], box_id: &B) -> bool {
    revoked.iter().any(|named| named == box_id)
}

/// The revocations in `revoked` that cover a value naming `box_id`. Each
/// one names `box_id`, so the list is empty or holds that id alone.
#[must_use]
pub fn in_force_for<'a, B: PartialEq>(revoked: &'a [B], box_id: &B) -> Vec<&'a B> {
    revoked.iter().filter(|named| *named == box_id).collect()
}

/// Puts a revocation of `box_id` in force. Returns `false` when one is in
/// force already, so the caller records each revocation once.
pub fn record(revocations: &Revocations, box_id: &str) -> bool {
    let mut revoked = revocations.write().unwrap_or_else(PoisonError::into_inner);
    if covers(&revoked, &box_id.to_owned()) {
        return false;
    }
    revoked.push(box_id.to_owned());
    true
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};

    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit::{Kind, Outcome};
    use crate::boxes::{BoxRegistry, Boxes};
    use crate::control::Records;
    use crate::forward::{Redeemer, Verdict};
    use crate::handle::{self, Claims, ClientKeys, Inject};
    use crate::keys::memory::MemoryStore;
    use crate::keys::{HeldKey, KeyStore, Role};
    use crate::module::GITHUB;
    use crate::proxy::AuditWriter;
    use crate::redeem::{Authority, Check, RequestAuthority};
    use crate::redeemer::BoxRedeemer;
    use crate::seal::{self, Breadth, Context, Member, MemberKind, MemberList, Mode};
    use crate::signin::{
        Flow, Keychain, Material, MemoryKeychain, Metadata, RefreshError, Refreshed, SignInError,
        TokenEndpoint,
    };

    /// A box id in the proxy's form: 32 lowercase hex digits.
    fn hex(id: [u8; 16]) -> String {
        crate::listener::box_id_text(&id)
    }

    /// The same id as a hyphenated UUID, the form `min` and `minvmd` print.
    fn hyphenated(id: [u8; 16]) -> String {
        let text = hex(id);
        format!(
            "{}-{}-{}-{}-{}",
            &text[..8],
            &text[8..12],
            &text[12..16],
            &text[16..20],
            &text[20..]
        )
    }

    fn revoke_line(box_id: &str) -> String {
        format!(r#"{{"op":"revoke_box","box_id":"{box_id}"}}"#)
    }

    proptest! {
        // BEP-071: for every set of revocations recorded over the control
        // socket, in either id form, a value is covered exactly when some
        // revocation names its box id. A box minted after the revocations,
        // with an id none of them names, is covered by none.
        #[test]
        fn prop_revocation_covers_exactly_its_box(
            pool in prop::collection::vec(any::<[u8; 16]>(), 1..6),
            picks in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 0..8),
            value in any::<prop::sample::Index>(),
            later in any::<[u8; 16]>(),
        ) {
            let records = Records::default();
            let mut named = Vec::new();
            for (pick, dashed) in &picks {
                let id = *pick.get(&pool);
                let text = if *dashed { hyphenated(id) } else { hex(id) };
                let reply = records.handle(&revoke_line(&text));
                prop_assert!(reply.ok, "{reply:?}");
                named.push(hex(id));
            }
            let revoked = records.revocations.read().unwrap().clone();
            // Each box is recorded once, however often it is revoked.
            let mut unique = named.clone();
            unique.sort();
            unique.dedup();
            prop_assert_eq!(revoked.len(), unique.len());

            let value_box = hex(*value.get(&pool));
            let expected = named.contains(&value_box);
            prop_assert_eq!(covers(&revoked, &value_box), expected);
            let in_force = in_force_for(&revoked, &value_box);
            prop_assert_eq!(in_force.len(), usize::from(expected));
            prop_assert!(in_force.iter().all(|id| **id == value_box));

            // A later creation gets a fresh id, so no earlier revocation
            // covers it, whatever name the box takes.
            let later = hex(later);
            prop_assume!(!pool.iter().any(|id| hex(*id) == later));
            prop_assert!(!covers(&revoked, &later));
            prop_assert!(in_force_for(&revoked, &later).is_empty());
        }
    }

    const NOW: u64 = 1_800_000_000;
    const NODE: &str = "node-1";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

    /// A keychain that counts its reads of the token.
    #[derive(Default)]
    struct CountingKeychain {
        inner: MemoryKeychain,
        material_reads: AtomicUsize,
    }

    impl Keychain for CountingKeychain {
        fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
            self.inner.metadata()
        }

        fn material(&self) -> Result<Option<Material>, SignInError> {
            self.material_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.material()
        }

        fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
            self.inner.write(metadata, material)
        }
    }

    /// A token endpoint that counts its renewals and renews each one.
    #[derive(Default)]
    struct CountingEndpoint {
        calls: AtomicUsize,
    }

    impl TokenEndpoint for CountingEndpoint {
        fn refresh(&self, _flow: Flow, _refresh_token: &str) -> Result<Refreshed, RefreshError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Refreshed {
                access_token: "ghu_renewed".into(),
                refresh_token: "ghr_renewed".into(),
                expires_in: 28_800,
                refresh_token_expires_in: 15_000_000,
            })
        }
    }

    // BEP-071: a value that a revocation covers is refused before the
    // redeemer resolves its reference or renews its sign-in. The sign-in's
    // token is expired, so any resolution would renew it.
    #[test]
    fn revoked_value_never_triggers_renewal() {
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let keychain = CountingKeychain::default();
        keychain
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: Flow::Device,
                    // Expired: the next resolution renews it.
                    token_expires_at: NOW - 60,
                    refresh_expires_at: NOW + 86_400,
                },
                &Material {
                    instance: INSTANCE.into(),
                    access_token: "ghu_expired".into(),
                    refresh_token: "ghr_refresh".into(),
                },
            )
            .unwrap();
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        let records = Records {
            boxes: Arc::clone(&boxes),
            ..Records::default()
        };
        let endpoint = Arc::new(CountingEndpoint::default());
        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::new(RwLock::new(keys)),
            Arc::clone(&boxes),
            keychain,
        )
        .with_revocations(Arc::clone(&records.revocations))
        .with_token_endpoint(endpoint.clone())
        .with_clock(Arc::new(|| NOW));

        let web = hex([0x01; 16]);
        let api = Authority {
            host: "api.github.com".to_owned(),
            port: 443,
        };
        let register = format!(
            r#"{{"op":"register_box","box_id":"{web}","egress":["api.github.com"],"stance":"own_ip"}}"#
        );
        assert!(records.handle(&register).ok);
        let jws = handle::sign(
            &client,
            &Claims {
                sub: web.clone(),
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
                box_id: web.clone(),
                host: NODE.into(),
                module: GITHUB.id.into(),
                host_set_version: GITHUB.host_set_version,
                mode: Mode::User,
                iat: NOW - 10,
                expiry: NOW + 3600,
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
        let request = RequestAuthority {
            host: Some(api.clone()),
            target: None,
        };

        // The destroy's revocation, sent while the box is still registered,
        // so only the revocation can refuse the value.
        assert!(records.handle(&revoke_line(&hyphenated([0x01; 16]))).ok);
        let verdict = redeemer.redeem(&web, &api, &request, &sealed);
        assert!(
            matches!(verdict, Verdict::Refuse(marker) if marker == Check::Revoked.marker()),
            "{verdict:?}"
        );
        assert_eq!(endpoint.calls.load(Ordering::SeqCst), 0, "no renewal");

        // The same value from a box that no revocation names is resolved,
        // and its expired token is renewed: the request above was refused
        // by the revocation alone.
        records.revocations.write().unwrap().clear();
        let verdict = redeemer.redeem(&web, &api, &request, &sealed);
        assert!(matches!(verdict, Verdict::Admit { .. }), "{verdict:?}");
        assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1, "one renewal");
    }

    // BEP-067, BEP-043: a revocation over the control socket appends one
    // `revocation` record to the log, and a second revocation of the same
    // box appends none.
    #[test]
    fn revocation_appends_one_record() {
        let written = Arc::new(std::sync::Mutex::new(Vec::<crate::audit::Decision>::new()));
        let records = Records {
            audit: Some(written.clone() as Arc<dyn AuditWriter>),
            ..Records::default()
        };
        let web = hex([0x02; 16]);
        assert!(records.handle(&revoke_line(&web)).ok);
        assert!(records.handle(&revoke_line(&hyphenated([0x02; 16]))).ok);
        let written = written.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].kind, Kind::Revocation);
        assert_eq!(written[0].box_id, web);
        assert_eq!(written[0].outcome, Outcome::Refuse);
        assert!(!records.handle(&revoke_line("web")).ok);
    }

    /// An audit writer whose every append fails, counting the attempts.
    #[derive(Default)]
    struct FailingWriter {
        attempts: AtomicUsize,
    }

    impl AuditWriter for FailingWriter {
        fn write(&self, _: &crate::audit::Decision) {}

        fn try_write(&self, _: &crate::audit::Decision) -> std::io::Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("the disk is full"))
        }
    }

    // BEP-071, BEP-067: an append that fails reaches `revoke_box`, which
    // logs the lost record. The revocation stays in force, so the reply
    // stays `ok`, and a second revocation of the box tries no append.
    #[test]
    fn revocation_stays_in_force_when_its_append_fails() {
        let writer = Arc::new(FailingWriter::default());
        let records = Records {
            audit: Some(writer.clone() as Arc<dyn AuditWriter>),
            ..Records::default()
        };
        let web = hex([0x03; 16]);
        assert!(records.handle(&revoke_line(&web)).ok);
        assert_eq!(writer.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(*records.revocations.read().unwrap(), vec![web.clone()]);
        assert!(records.handle(&revoke_line(&web)).ok);
        assert_eq!(writer.attempts.load(Ordering::SeqCst), 1);
    }
}
