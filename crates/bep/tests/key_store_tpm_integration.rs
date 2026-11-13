//! The TPM key store against a real TPM (BEP-088).
//!
//! * `a_tpm_key_is_fixed_exempt_from_lockout_and_needs_its_authorization`
//!   generates the proxy's three keys in the TPM that `BEP_TPM_TCTI` names,
//!   as `swtpm` in CI (`swtpm:host=localhost,port=2321`). It checks that the
//!   TPM reports `fixedTPM`, `fixedParent` and `noDA` on each key, so the TPM
//!   refuses to duplicate it. It signs and agrees through the TPM, and checks
//!   each result in software. It loads each key again in a new store from
//!   its key file and its authorization file alone. Last, it checks that the
//!   TPM refuses the root key with another authorization value, with the
//!   response code a noDA object gets, and that the root key works again
//!   with its own authorization file.
//!
//! The test needs `tpm2-tools` and a TPM. It is ignored by default, and
//! returns early when `BEP_TPM_TCTI` is not set, as the `_root_integration`
//! proofs do on a host that cannot run them. Run it with
//! `BEP_TPM_TCTI=<tcti> cargo nextest run -p bep --run-ignored ignored-only
//! a_tpm_key_is_fixed_exempt_from_lockout_and_needs_its_authorization`.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use bep::ca::CaKey as _;
use bep::keys::{HeldKey as _, KeyError, KeyStore as _, Role, Slot};
use bep::tpm::{self, TpmStore, attr};
use p256::ecdsa::signature::Verifier as _;

#[test]
#[ignore = "needs a TPM: set BEP_TPM_TCTI"]
fn a_tpm_key_is_fixed_exempt_from_lockout_and_needs_its_authorization() {
    let Ok(tcti) = std::env::var("BEP_TPM_TCTI") else {
        eprintln!("BEP_TPM_TCTI is not set, so this host has no TPM for the test. Skipped.");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("tpm");
    let store = TpmStore::new(store_dir.clone(), tcti.clone());

    let mut publics = Vec::new();
    for role in Role::ALL {
        assert!(store.find(role).expect("find").is_none(), "{role}");
        let key = store.generate(role).expect("generate in the TPM");
        assert!(!key.exportable());

        // The public area the TPM wrote carries every custody attribute.
        let bytes = fs::read(store.key_path(role, Slot::Held)).expect("key file");
        let (public, _) = tpm::parse_public(&bytes).expect("public area");
        for bit in [
            attr::FIXED_TPM,
            attr::FIXED_PARENT,
            attr::NO_DA,
            attr::USER_WITH_AUTH,
        ] {
            assert_ne!(public.attributes & bit, 0, "{role}: bit {bit:#x}");
        }
        assert_eq!(public.key, key.public());

        // The authorization value is at least 128 bits, and only its user
        // reads it.
        let auth_path = store.auth_path(role, Slot::Held);
        assert!(fs::read(&auth_path).expect("auth file").len() * 8 >= 128);
        let mode = fs::metadata(&auth_path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o077, 0, "{role}: auth file mode {mode:o}");

        use_key(role, &key);
        publics.push((role, key.public()));
    }

    // A new store loads each key from its key file and authorization file
    // alone.
    let names: Vec<String> = fs::read_dir(&store_dir)
        .expect("read dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| !name.starts_with(".work-"))
        .collect();
    assert_eq!(names.len(), 2 * Role::ALL.len(), "{names:?}");
    assert!(
        names
            .iter()
            .all(|n| n.ends_with(".key") || n.ends_with(".auth")),
        "{names:?}"
    );
    let again = TpmStore::new(store_dir.clone(), tcti.clone());
    for (role, public) in &publics {
        let key = again.find(*role).expect("load").expect("held");
        assert_eq!(key.public(), *public);
        key.probe().expect("probe");
        use_key(*role, &key);
    }

    // A wrong authorization value is refused, and does not lock the TPM out.
    // The TPM answers TPM_RC_BAD_AUTH in session 1 (`0x000009a2`) only for
    // an object with noDA. An object without it gets TPM_RC_AUTH_FAIL.
    let root_auth_path = store.auth_path(Role::Root, Slot::Held);
    let root_auth = fs::read(&root_auth_path).expect("root auth file");
    fs::write(&root_auth_path, [0u8; 32]).expect("write");
    for _ in 0..5 {
        let key = again.find(Role::Root).expect("load").expect("held");
        match key.sign(b"wrong authorization") {
            Err(KeyError::Refused { role, detail }) => {
                assert_eq!(role, Role::Root);
                assert!(detail.ends_with("0x000009a2"), "{detail}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // The root key still works with its own authorization. Without noDA on
    // the root key, the failures above count toward lockout.
    fs::write(&root_auth_path, &root_auth).expect("restore root auth file");
    let root = again.find(Role::Root).expect("load").expect("held");
    root.probe().expect("no lockout after wrong authorizations");
    use_key(Role::Root, &root);
}

fn use_key(role: Role, key: &bep::tpm::TpmKey) {
    match role {
        Role::Sealing => {
            let peer = loop {
                let mut bytes = [0u8; 32];
                getrandom::fill(&mut bytes).expect("random source");
                if let Ok(secret) = p256::SecretKey::from_slice(&bytes) {
                    break secret;
                }
            };
            let peer_public =
                bep::seal::ProxyPublicKey::from_sec1_bytes(&peer.public_key().to_sec1_bytes())
                    .expect("a P-256 point");
            let shared = key.agree(&peer_public).expect("ECDH in the TPM");
            let ours = p256::PublicKey::from_sec1_bytes(&key.public().to_sec1_bytes())
                .expect("a P-256 point");
            let expected = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), ours.as_affine());
            assert_eq!(shared.as_slice(), expected.raw_secret_bytes().as_slice());
        }
        Role::Root | Role::Signing => {
            let msg = b"a certificate to sign";
            let der = key.sign(msg).expect("ECDSA in the TPM");
            let signature = p256::ecdsa::Signature::from_der(&der).expect("DER");
            let verifying =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public().to_sec1_bytes())
                    .expect("a P-256 point");
            verifying
                .verify(msg, &signature)
                .expect("a valid signature");
        }
    }
}
