//! Revocations by box id (BEP-043, BEP-071).
//!
//! A revocation names one box id, and it covers a sealed value exactly when
//! the value names that box id (BEP-071). A box id is minted once for each
//! creation and never returns (BEP-070). So a box created after a
//! revocation, under any name, is covered by no revocation.
//!
//! The creator of a box records a revocation over the control socket when
//! it destroys a live box ([`crate::control`]). The control socket puts the
//! box id in the [`RevocationBook`] and appends the `revocation` record to
//! the audit log. The redeemer reads the same set at each request
//! ([`crate::redeemer::BoxRedeemer::with_revocations`]). The decision
//! refuses a covered value before the redeemer resolves any reference or
//! renews any sign-in ([`crate::redeem::decide`], step 6).
//!
//! Interim: the book lives in memory, so a revocation is not in force after
//! the proxy restarts. T33
//! (<https://github.com/gominimal/minimal/issues/2290>) restores the book
//! from every retained audit segment at start. A destroyed box's values
//! stay refused across the restart all the same, because the box's
//! attachment is withdrawn at its destroy (NET-133).

use std::sync::{Arc, PoisonError};

use crate::audit::{Decision, Kind, Mapping, NONE, Outcome};
use crate::redeemer::Revocations;

/// The marker of a `revocation` record: a live box was destroyed.
pub const BOX_DESTROYED: &str = "box_destroyed";

/// The revocations in force on this proxy, by box id.
///
/// Every clone shares one set. The ids are in the form the listener names a
/// box by: 32 lowercase hex digits.
#[derive(Debug, Clone, Default)]
pub struct RevocationBook {
    in_force: Revocations,
}

impl RevocationBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The set the redeemer reads, shared with this book.
    #[must_use]
    pub fn in_force(&self) -> Revocations {
        Arc::clone(&self.in_force)
    }

    /// Records a revocation naming `box_id`. Returns `true` when no
    /// revocation named it before.
    pub fn revoke(&self, box_id: &str) -> bool {
        let mut ids = self
            .in_force
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if covers(&ids, box_id) {
            return false;
        }
        ids.push(box_id.to_owned());
        true
    }

    /// Whether a revocation in force covers a value that names `box_id`.
    #[must_use]
    pub fn covers(&self, box_id: &str) -> bool {
        covers(
            &self.in_force.read().unwrap_or_else(PoisonError::into_inner),
            box_id,
        )
    }

    /// How many revocations are in force.
    #[must_use]
    pub fn len(&self) -> usize {
        self.in_force
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no revocation is in force.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Whether the revocations that name `revoked` cover a value that names
/// `box_id`: exactly when one of them names that id (BEP-071).
#[must_use]
pub fn covers(revoked: &[String], box_id: &str) -> bool {
    revoked.iter().any(|id| id == box_id)
}

/// The `revocation` record for the destroyed box `box_id`. It names no
/// upstream and no member, and it carries the [`BOX_DESTROYED`] marker.
#[must_use]
pub fn revocation_record(box_id: &str) -> Decision {
    Decision {
        kind: Kind::Revocation,
        box_id: box_id.to_owned(),
        authority: NONE.to_owned(),
        identifier: None,
        mapping: Mapping::ModuleUnmapped,
        outcome: Outcome::Refuse,
        marker: Some(BOX_DESTROYED.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, RwLock};

    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;
    use zeroize::Zeroizing;

    use super::*;
    use crate::boxes::{BoxRegistry, Boxes, Stance};
    use crate::control::{Recorder, Reply, Request, handle_request};
    use crate::forward::{Redeemer, Verdict};
    use crate::handle::{self, Claims, ClientKeys, Inject};
    use crate::keys::memory::{MemoryKey, MemoryStore};
    use crate::keys::{HeldKey, KeyStore, Role};
    use crate::module::GITHUB;
    use crate::proxy::AuditWriter;
    use crate::redeem::{Authority, Check, RequestAuthority};
    use crate::redeemer::BoxRedeemer;
    use crate::seal::{self, Breadth, Context, Member, MemberKind, MemberList, Mode};
    use crate::signin::{
        Flow, Keychain, Material, MemoryKeychain, Metadata, SignInError, Standing,
    };

    const NOW: u64 = 1_800_000_000;
    const NODE: &str = "node-1";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

    /// A 32-hex-digit box id from a number.
    fn id(n: u128) -> String {
        format!("{n:032x}")
    }

    /// Sends `request` through the control socket's line handler with
    /// `recorder`.
    fn submit(recorder: &Recorder, request: &Request) -> Reply {
        let line = serde_json::to_string(request).unwrap();
        handle_request(
            &line,
            &RwLock::new(ClientKeys::new()),
            &Boxes::new(),
            recorder,
        )
    }

    proptest! {
        /// BEP-071: for every set of revocation records and every sealed
        /// value, the value is covered exactly when some record names its
        /// box id. A box created after the revocations, with a fresh id, is
        /// covered by none.
        #[test]
        fn prop_revocation_covers_exactly_its_box(
            revoked in prop::collection::vec(0u128..8, 0..6),
            named in 0u128..8,
            fresh in any::<u128>(),
        ) {
            let audit = Arc::new(Mutex::new(Vec::<Decision>::new()));
            let book = RevocationBook::new();
            let recorder = Recorder::new(audit.clone(), book.clone());
            for n in &revoked {
                let reply = submit(&recorder, &Request::RevokeBox { box_id: id(*n) });
                prop_assert!(reply.ok, "{reply:?}");
            }
            prop_assert_eq!(book.covers(&id(named)), revoked.contains(&named));
            // The ids the revocations name are below 8, so a fresh id at 8
            // or above is a box no revocation names.
            let fresh = fresh.max(8);
            prop_assert!(!book.covers(&id(fresh)));
            // One revocation per id, and one record per revocation.
            let mut distinct = revoked.clone();
            distinct.sort_unstable();
            distinct.dedup();
            prop_assert_eq!(book.len(), distinct.len());
            let records = audit.lock().unwrap();
            prop_assert_eq!(records.len(), distinct.len());
            for record in records.iter() {
                prop_assert_eq!(record.kind, Kind::Revocation);
                prop_assert_eq!(record.marker.as_deref(), Some(BOX_DESTROYED));
            }
        }
    }

    /// A keychain that counts every call, over a memory keychain.
    #[derive(Default)]
    struct Counting {
        inner: MemoryKeychain,
        calls: AtomicUsize,
    }

    impl Keychain for Arc<Counting> {
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

    /// A value sealed for `box_id` on [`NODE`], with a sign-in member signed
    /// under `client`.
    fn sealed_for(sealing: &seal::ProxyPublicKey, client: &SigningKey, box_id: &str) -> String {
        let jws = handle::sign(
            client,
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
        seal::seal(
            sealing,
            &Context {
                box_id: box_id.into(),
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
        .unwrap()
    }

    /// BEP-071: a request with a value a revocation covers is refused
    /// before the redeemer reads the sign-in item, so a sign-in whose token
    /// renews at the proxy is never renewed for it.
    #[test]
    fn revoked_value_never_triggers_renewal() {
        let store = MemoryStore::default();
        let key: MemoryKey = store.generate(Role::Sealing).unwrap();
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let clients = Arc::new(RwLock::new(keys));

        // The token has expired and the refresh material has not: the next
        // request that uses the sign-in is the one that renews it.
        let keychain = Arc::new(Counting::default());
        let metadata = Metadata {
            account: "octocat".into(),
            instance: INSTANCE.into(),
            flow: Flow::Device,
            token_expires_at: NOW - 60,
            refresh_expires_at: NOW + 86_400,
        };
        assert_eq!(metadata.standing(NOW), Standing::RenewsAtProxy);
        keychain
            .inner
            .write(
                &metadata,
                &Material {
                    instance: INSTANCE.into(),
                    access_token: "ghu_expired_token".into(),
                    refresh_token: "ghr_refresh".into(),
                },
            )
            .unwrap();

        let web = id(0x0192_f0c1_7a2b_7c3d_8e4f_a0b1_c2d3_e4f5);
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        let api = Authority {
            host: "api.github.com".to_owned(),
            port: 443,
        };
        boxes.register(&web, vec![api.clone()], Stance::OwnIp);
        let book = RevocationBook::new();
        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::clone(&clients),
            Arc::clone(&boxes),
            Arc::clone(&keychain),
        )
        .with_revocations(book.in_force())
        .with_clock(Arc::new(|| NOW));
        let sealed = sealed_for(&sealing, &client, &web);
        let request = RequestAuthority {
            host: Some(api.clone()),
            target: None,
        };

        // Before the revocation the value passes the decision, and the
        // redeemer reads the sign-in item to resolve the reference.
        let before = redeemer.redeem(&web, &api, &request, &sealed);
        assert!(matches!(before, Verdict::Refuse(m) if m != Check::Revoked.marker()));
        assert!(keychain.calls.load(Ordering::SeqCst) > 0);

        // The box's destroy records its revocation over the control socket.
        let audit: Arc<Mutex<Vec<Decision>>> = Arc::default();
        let writer: Arc<dyn AuditWriter> = audit.clone();
        let reply = submit(
            &Recorder::new(writer, book.clone()),
            &Request::RevokeBox {
                box_id: web.clone(),
            },
        );
        assert!(reply.ok, "{reply:?}");
        assert_eq!(audit.lock().unwrap()[0], revocation_record(&web));

        keychain.calls.store(0, Ordering::SeqCst);
        for _ in 0..3 {
            let after = redeemer.redeem(&web, &api, &request, &sealed);
            assert!(matches!(after, Verdict::Refuse(m) if m == Check::Revoked.marker()));
        }
        assert_eq!(
            keychain.calls.load(Ordering::SeqCst),
            0,
            "a revoked value read the sign-in item"
        );
    }
}
