//! The revocations in force, by box id (BEP-043, BEP-071).
//!
//! On a host that is not enrolled, the one revocation event is the destroy
//! of a live box. The box's creator sends `record_revocation` over the
//! control socket ([`crate::control`]). The proxy then puts the box id in
//! this book and appends a `revocation` record to the audit log.
//!
//! A revocation covers a sealed value exactly when it names the value's
//! box id. A box id names one creation and never returns (BEP-070), so a
//! box created later under the same name has a new id, and no revocation
//! covers it.
//!
//! The redeemer reads the book's ids at each request
//! ([`crate::redeemer::BoxRedeemer::with_revocations`]). The pure decision
//! ([`crate::redeem::decide`]) refuses a covered value before the redeemer
//! resolves any sign-in reference or reads the keychain. So a revoked value
//! never makes the proxy renew a sign-in.
//!
//! Interim: the book starts empty at each start of the proxy. T33
//! (<https://github.com/gominimal/minimal/issues/2290>) restores it from
//! every retained audit segment, the BEP-068 restore-on-start
//! sub-requirement. Until then a destroyed box's values are refused after a
//! restart through the withdrawal of its attachment (NET-133).

use std::sync::{Arc, PoisonError};

use crate::redeemer::Revocations;

/// The box ids that the revocations in force name, shared with the
/// redeemer.
#[derive(Debug, Clone, Default)]
pub struct RevocationBook {
    ids: Revocations,
}

impl RevocationBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The ids this book holds, as the redeemer reads them
    /// ([`crate::redeemer::BoxRedeemer::with_revocations`]). A revocation
    /// recorded here later is in force there at the next request.
    #[must_use]
    pub fn shared(&self) -> Revocations {
        Arc::clone(&self.ids)
    }

    /// Records a revocation naming `box_id`. `true` when the book did not
    /// hold it already.
    pub fn record(&self, box_id: &str) -> bool {
        let mut ids = self.ids.write().unwrap_or_else(PoisonError::into_inner);
        if ids.iter().any(|id| id == box_id) {
            return false;
        }
        ids.push(box_id.to_owned());
        true
    }

    /// Whether a revocation in force covers a value that names `box_id`.
    #[must_use]
    pub fn covers(&self, box_id: &str) -> bool {
        covers(
            &self.ids.read().unwrap_or_else(PoisonError::into_inner),
            box_id,
        )
    }
}

/// Whether one of the revocations `revoked` covers a value that names
/// `box_id`: some revocation names that id exactly (BEP-071).
#[must_use]
pub fn covers(revoked: &[String], box_id: &str) -> bool {
    revoked.iter().any(|id| id == box_id)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, RwLock};

    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit::{Decision, Kind, Outcome};
    use crate::boxes::{BoxRegistry, Boxes, Stance};
    use crate::control::{Ledger, handle_line_with};
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
        Flow as SignInFlow, Keychain, Material, MemoryKeychain, Metadata, SignInError,
    };

    const NOW: u64 = 1_800_000_000;
    const NODE: &str = "node-1";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

    /// Box ids as the control socket stores them.
    const IDS: [&str; 4] = [
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5",
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f6",
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f7",
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f8",
    ];

    fn ledger() -> (Ledger, Arc<Mutex<Vec<Decision>>>, RevocationBook) {
        let records = Arc::new(Mutex::new(Vec::new()));
        let book = RevocationBook::new();
        let audit: Arc<dyn AuditWriter> = records.clone();
        (Ledger::new(audit, book.clone()), records, book)
    }

    fn submit(ledger: &Ledger, line: &str) -> bool {
        let registry = RwLock::new(ClientKeys::new());
        let boxes = Boxes::new();
        handle_line_with(line, &registry, &boxes, ledger).ok
    }

    fn revocation_line(box_id: &str) -> String {
        format!(r#"{{"op":"record_revocation","box_id":"{box_id}"}}"#)
    }

    proptest! {
        // BEP-071: for every set of revocation records and every value, the
        // value is covered iff some record names its box id. A box created
        // after the revocations, with a fresh id, is covered by none.
        #[test]
        fn prop_revocation_covers_exactly_its_box(
            revoked in prop::collection::vec(0usize..IDS.len(), 0..=6),
            named in 0usize..IDS.len(),
            fresh in prop::array::uniform16(any::<u8>()),
        ) {
            let (ledger, records, book) = ledger();
            for &i in &revoked {
                prop_assert!(submit(&ledger, &revocation_line(IDS[i])));
            }
            let want = revoked.contains(&named);
            prop_assert_eq!(book.covers(IDS[named]), want);
            prop_assert_eq!(
                covers(&book.shared().read().unwrap(), IDS[named]),
                want
            );
            // One record per id, however often the destroy was sent.
            let mut distinct = revoked.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let records = records.lock().unwrap();
            prop_assert_eq!(records.len(), distinct.len());
            for record in records.iter() {
                prop_assert_eq!(record.kind, Kind::Revocation);
                prop_assert!(distinct.iter().any(|&i| IDS[i] == record.box_id));
            }
            // A new creation gets a new id, which no record names.
            let fresh: String = fresh.iter().map(|b| format!("{b:02x}")).collect();
            if !IDS.contains(&fresh.as_str()) {
                prop_assert!(!book.covers(&fresh));
            }
        }
    }

    /// A keychain that counts every call, over a memory keychain.
    #[derive(Default)]
    struct Counting {
        inner: MemoryKeychain,
        calls: Arc<AtomicUsize>,
    }

    impl Keychain for Counting {
        fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.metadata()
        }

        fn material(&self) -> Result<Option<Material>, SignInError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.material()
        }

        fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.write(metadata, material)
        }
    }

    fn api() -> Authority<String> {
        Authority {
            host: "api.github.com".into(),
            port: 443,
        }
    }

    // BEP-071, BEP-043: a value whose box a revocation covers is refused
    // before the redeemer reads the keychain, so it never resolves the
    // reference or renews the sign-in. The token here renews at the proxy,
    // which is the state a renewal would start from.
    #[test]
    fn revoked_value_never_triggers_renewal() {
        let box_id = IDS[0];
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let keychain = Counting::default();
        keychain
            .inner
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: SignInFlow::Device,
                    // Expired, with live refresh material: a renewal's start.
                    token_expires_at: NOW - 60,
                    refresh_expires_at: NOW + 7200,
                },
                &Material {
                    instance: INSTANCE.into(),
                    access_token: "ghu_the_real_token".into(),
                    refresh_token: "ghr_refresh".into(),
                },
            )
            .unwrap();
        let calls = Arc::clone(&keychain.calls);
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        boxes.register(box_id, vec![api()], Stance::OwnIp);
        let (ledger, records, book) = ledger();
        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::new(RwLock::new(keys)),
            Arc::clone(&boxes),
            keychain,
        )
        .with_revocations(book.shared())
        .with_clock(Arc::new(|| NOW));

        let jws = handle::sign(
            &client,
            &Claims {
                sub: box_id.into(),
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
                box_id: box_id.into(),
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
        let request = RequestAuthority {
            host: Some(api()),
            target: None,
        };
        let redeem = || redeemer.redeem(box_id, &api(), &request, &sealed);

        // Before the revocation the value reaches the keychain.
        let before = redeem();
        assert!(
            matches!(before, Verdict::Refuse(m) if m != Check::Revoked.marker()),
            "{before:?}"
        );
        assert!(calls.load(Ordering::SeqCst) > 0);

        calls.store(0, Ordering::SeqCst);
        assert!(submit(&ledger, &revocation_line(box_id)));
        let after = redeem();
        assert!(
            matches!(after, Verdict::Refuse(m) if m == Check::Revoked.marker()),
            "{after:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a revoked value never reads the keychain"
        );

        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, Kind::Revocation);
        assert_eq!(records[0].box_id, box_id);
        assert_eq!(records[0].outcome, Outcome::Refuse);
    }
}
