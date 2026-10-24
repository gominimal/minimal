//! The revocations in force, by box id, and the `mint` and `revocation`
//! records the control socket appends (BEP-043, BEP-067, BEP-071).
//!
//! A revocation names one box id. It covers a sealed value exactly when the
//! value's box id is the id it names (BEP-071). A box id never returns
//! (BEP-070), so a box created after the revocation, under any name, is
//! covered by no revocation.
//!
//! [`Revoker`] holds the set that the redeemer reads at each request
//! ([`crate::redeemer::BoxRedeemer::with_revocations`]). The redeemer gives
//! the set to [`crate::redeem::decide`], which refuses a covered value
//! before the redeemer resolves any sign-in reference. So a revoked value
//! never makes the proxy read the keychain or renew a sign-in.
//!
//! [`Revoker::revoke`] puts the revocation in force first, and then
//! appends its record to the audit log. A record that fails to write does
//! not take the revocation out of force.
//!
//! The proxy is the log's only writer. The client's mints and a destroyed
//! box's revocation reach the log through the control socket
//! ([`crate::control`]), so they share one chain with the proxy's
//! decisions.
//!
//! Interim: the set lives in memory, so a restart of `bep serve` starts with
//! no revocation in force. T33
//! (<https://github.com/gominimal/minimal/issues/2290>) restores the set
//! from every retained audit segment at start.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use crate::audit::{AuditLog, Decision, Kind, Mapping, NONE, Outcome};
pub use crate::redeemer::Revocations;

/// Where the control socket appends its records. Unlike
/// [`crate::proxy::AuditWriter`], an append reports its failure, so the
/// control socket can tell the client that the record was not written.
pub trait Append: Send + Sync {
    /// Appends one record.
    ///
    /// # Errors
    ///
    /// The I/O error of the append.
    fn append(&self, decision: &Decision) -> io::Result<()>;
}

impl Append for Mutex<AuditLog> {
    fn append(&self, decision: &Decision) -> io::Result<()> {
        self.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .append(decision)
            .map(drop)
    }
}

impl Append for Mutex<Vec<Decision>> {
    fn append(&self, decision: &Decision) -> io::Result<()> {
        self.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(decision.clone());
        Ok(())
    }
}

/// Whether a revocation in `revoked` covers a value sealed for `box_id`:
/// exactly when one of them names `box_id` (BEP-071).
#[must_use]
pub fn covers(revoked: &[String], box_id: &str) -> bool {
    revoked.iter().any(|named| named == box_id)
}

/// The `revocation` record of the destroyed box `box_id`. It names no
/// upstream and no member, and its decision is `refuse`.
#[must_use]
pub fn revocation_record(box_id: &str) -> Decision {
    Decision {
        kind: Kind::Revocation,
        box_id: box_id.to_owned(),
        authority: NONE.to_owned(),
        identifier: None,
        mapping: Mapping::ModuleUnmapped,
        outcome: Outcome::Refuse,
        marker: None,
    }
}

/// The `mint` record of one member that the client minted for `box_id`.
/// `identifier` is the member's audit identifier, `<store>:<id>`. It names
/// no upstream, and its decision is `admit`.
#[must_use]
pub fn mint_record(box_id: &str, identifier: &str) -> Decision {
    Decision {
        kind: Kind::Mint,
        box_id: box_id.to_owned(),
        authority: NONE.to_owned(),
        identifier: Some(identifier.to_owned()),
        mapping: Mapping::ModuleUnmapped,
        outcome: Outcome::Admit,
        marker: None,
    }
}

/// The revocations in force, and the log their records go to.
#[derive(Clone, Default)]
pub struct Revoker {
    revoked: Revocations,
    log: Option<Arc<dyn Append>>,
}

impl std::fmt::Debug for Revoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revoker")
            .field("revoked", &self.revoked)
            .field("log", &self.log.is_some())
            .finish()
    }
}

impl Revoker {
    /// A revoker over the shared set `revoked`, with no log. A record with
    /// no log to go to is kept nowhere. `bep serve` always gives a log
    /// ([`Self::with_log`]).
    #[must_use]
    pub fn new(revoked: Revocations) -> Self {
        Self { revoked, log: None }
    }

    /// This revoker, appending its records to `log`.
    #[must_use]
    pub fn with_log(mut self, log: Arc<dyn Append>) -> Self {
        self.log = Some(log);
        self
    }

    /// The shared set, for the redeemer.
    #[must_use]
    pub fn revocations(&self) -> Revocations {
        Arc::clone(&self.revoked)
    }

    /// Whether a revocation in force covers a value sealed for `box_id`.
    #[must_use]
    pub fn covers(&self, box_id: &str) -> bool {
        covers(
            &self.revoked.read().unwrap_or_else(PoisonError::into_inner),
            box_id,
        )
    }

    /// Revokes every sealed value that names `box_id`, and appends one
    /// `revocation` record. A box revoked already gets no second record.
    /// The revocation is in force before the append, so it holds also when
    /// the append fails.
    ///
    /// # Errors
    ///
    /// The I/O error of the append.
    pub fn revoke(&self, box_id: &str) -> io::Result<()> {
        {
            let mut revoked = self.revoked.write().unwrap_or_else(PoisonError::into_inner);
            if covers(&revoked, box_id) {
                return Ok(());
            }
            revoked.push(box_id.to_owned());
        }
        tracing::info!(box_id, "recorded a revocation of the box's sealed values");
        self.append(&revocation_record(box_id))
    }

    /// Appends the `mint` record of one member minted for `box_id`.
    ///
    /// # Errors
    ///
    /// The I/O error of the append.
    pub fn record_mint(&self, box_id: &str, identifier: &str) -> io::Result<()> {
        self.append(&mint_record(box_id, identifier))
    }

    fn append(&self, decision: &Decision) -> io::Result<()> {
        let Some(log) = &self.log else {
            return Ok(());
        };
        log.append(decision).inspect_err(|error| {
            tracing::error!(
                box_id = %decision.box_id,
                kind = ?decision.kind,
                %error,
                "the audit record was not written"
            );
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;
    use zeroize::Zeroizing;

    use super::*;
    use crate::boxes::{BoxRegistry, Boxes, Stance};
    use crate::control::{self, Registry};
    use crate::forward::{Redeemer, Verdict};
    use crate::handle::{self, Claims, ClientKeys, Inject};
    use crate::keys::memory::MemoryStore;
    use crate::keys::{HeldKey, KeyStore, Role};
    use crate::module::GITHUB;
    use crate::redeem::{Authority, Check, RequestAuthority};
    use crate::redeemer::BoxRedeemer;
    use crate::seal::{self, Breadth, Context, Member, MemberKind, MemberList, Mode};
    use crate::signin::{Flow, Keychain, Material, MemoryKeychain, Metadata, SignInError};

    const IDS: [&str; 4] = [
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f0",
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f1",
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f2",
        "0192f0c17a2b7c3d8e4fa0b1c2d3e4f3",
    ];
    /// A box id that no revocation in the property names: a box created
    /// after every revocation.
    const LATER: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4ff";

    fn control_line(op: &str, box_id: &str) -> String {
        format!(r#"{{"op":"{op}","box_id":"{box_id}"}}"#)
    }

    proptest! {
        // BEP-071: for every set of revocation records and every sealed
        // value, the value is covered exactly when some record names its
        // box id. A box created after the revocations, under any name, is
        // covered by none. The revocations arrive the way `minvmd` sends
        // them, over the control socket, some in hyphenated UUID form.
        #[test]
        fn prop_revocation_covers_exactly_its_box(
            revoked in prop::collection::vec((0usize..IDS.len(), any::<bool>()), 0..=6),
            value in 0usize..IDS.len(),
        ) {
            let log = Arc::new(Mutex::new(Vec::<Decision>::new()));
            let revoker = Revoker::new(Revocations::default()).with_log(log.clone());
            let clients = RwLock::new(ClientKeys::new());
            let boxes = Boxes::new();
            for (named, hyphens) in &revoked {
                let id = IDS[*named];
                let text = if *hyphens {
                    format!("{}-{}-{}-{}-{}", &id[..8], &id[8..12], &id[12..16], &id[16..20], &id[20..])
                } else {
                    id.to_owned()
                };
                let reply = control::handle_with(
                    &control_line("revoke_box", &text),
                    &clients,
                    &boxes,
                    &revoker,
                );
                prop_assert!(reply.ok, "{reply:?}");
            }
            let named = revoked.iter().any(|(n, _)| *n == value);
            prop_assert_eq!(revoker.covers(IDS[value]), named);
            prop_assert!(!revoker.covers(LATER));
            // One record for each box revoked, whatever the repeats.
            let records = log.lock().unwrap().clone();
            let mut distinct: Vec<usize> = revoked.iter().map(|(n, _)| *n).collect();
            distinct.sort_unstable();
            distinct.dedup();
            prop_assert_eq!(records.len(), distinct.len());
            for record in &records {
                prop_assert_eq!(record.kind, Kind::Revocation);
                prop_assert!(IDS.contains(&record.box_id.as_str()));
            }
        }
    }

    const NOW: u64 = 1_800_000_000;
    const NODE: &str = "node-1";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

    /// A keychain that counts its reads and writes. A renewal starts with a
    /// read of the item, so a request that reads nothing renews nothing.
    #[derive(Default)]
    struct Counting {
        inner: MemoryKeychain,
        touched: std::sync::atomic::AtomicUsize,
    }

    impl Counting {
        fn touched(&self) -> usize {
            self.touched.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn touch(&self) {
            self.touched
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Keychain for Counting {
        fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
            self.touch();
            self.inner.metadata()
        }

        fn material(&self) -> Result<Option<Material>, SignInError> {
            self.touch();
            self.inner.material()
        }

        fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
            self.touch();
            self.inner.write(metadata, material)
        }
    }

    impl Keychain for Arc<Counting> {
        fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
            self.as_ref().metadata()
        }

        fn material(&self) -> Result<Option<Material>, SignInError> {
            self.as_ref().material()
        }

        fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
            self.as_ref().write(metadata, material)
        }
    }

    // BEP-071: a request that carries a revoked value is refused before
    // the proxy resolves any reference or renews any sign-in. The sign-in
    // here is past its token's expiry, so a redemption that reached the
    // sign-in item would start a renewal. The revoked value never reads it.
    #[test]
    fn revoked_value_never_triggers_renewal() {
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let keychain = Arc::new(Counting::default());
        keychain
            .inner
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: Flow::Device,
                    // The token expired, the refresh is live: it renews.
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
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        let box_id = IDS[0];
        let egress: Vec<Authority<String>> = GITHUB
            .hosts
            .iter()
            .map(|a| Authority {
                host: a.host.to_owned(),
                port: a.port,
            })
            .collect();
        boxes.register(box_id, egress, Stance::OwnIp);
        let log = Arc::new(Mutex::new(Vec::<Decision>::new()));
        let revoker = Revoker::new(Revocations::default()).with_log(log.clone());
        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Registry::new(RwLock::new(keys)),
            Arc::clone(&boxes),
            Arc::clone(&keychain),
        )
        .with_revocations(revoker.revocations())
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
        let api = Authority {
            host: "api.github.com".to_owned(),
            port: 443,
        };
        let request = RequestAuthority {
            host: Some(api.clone()),
            target: None,
        };

        // Before the revocation the value reaches the sign-in item.
        let before = redeemer.redeem(box_id, &api, &request, &sealed);
        assert!(matches!(before, Verdict::Refuse(_)), "{before:?}");
        assert!(
            keychain.touched() > 0,
            "an unrevoked value reads the sign-in"
        );

        // The destroy: the revocation, then the forget.
        let clients = RwLock::new(ClientKeys::new());
        let line = control_line("revoke_box", box_id);
        assert!(control::handle_with(&line, &clients, &boxes, &revoker).ok);
        let touched = keychain.touched();
        for _ in 0..3 {
            let verdict = redeemer.redeem(box_id, &api, &request, &sealed);
            assert!(
                matches!(verdict, Verdict::Refuse(m) if m == Check::Revoked.marker()),
                "{verdict:?}"
            );
        }
        let line = control_line("forget_box", box_id);
        assert!(control::handle_with(&line, &clients, &boxes, &revoker).ok);
        let verdict = redeemer.redeem(box_id, &api, &request, &sealed);
        assert!(matches!(verdict, Verdict::Refuse(_)), "{verdict:?}");
        assert_eq!(
            keychain.touched(),
            touched,
            "a revoked value never reads the sign-in item"
        );
        let records = log.lock().unwrap().clone();
        assert_eq!(records, vec![revocation_record(box_id)]);
    }
}
