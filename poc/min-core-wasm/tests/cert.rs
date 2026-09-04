//! Decision-level tests against the gominimal/arch certificate vectors at the
//! manifest's fixed clock: every `invalid/` case must be refused with exactly
//! its `expected_error`, and the valid ones accepted. Runs the same
//! functions the fake daemon (`auth_openssh_certificate`) and the client
//! (`check_server_key`) run.

use std::collections::HashSet;
use std::path::PathBuf;

use min_core::credential::{Anchors, verify_host_cert, verify_user_cert};
use russh::keys::Certificate;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(vectors().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn anchors(pub_file: &str) -> Anchors {
    Anchors::from_openssh_lines([read(pub_file).as_str()]).unwrap()
}

fn cert(rel: &str) -> Certificate {
    Certificate::from_openssh(read(rel).trim()).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[derive(serde::Deserialize)]
struct Manifest {
    clock: u64,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    file: String,
    serial: u64,
    expected_error: String,
}

#[derive(serde::Deserialize)]
struct Revoked {
    revoked_serials: Vec<u64>,
    not_revoked_probe: Vec<u64>,
}

#[test]
fn every_invalid_vector_is_refused_with_its_expected_error() {
    let manifest: Manifest = serde_json::from_str(&read("ssh-certs/invalid/manifest.json")).unwrap();
    let revoked: Revoked = serde_json::from_str(&read("krl/expected-revoked.json")).unwrap();
    let revoked_set: HashSet<u64> = revoked.revoked_serials.iter().copied().collect();
    let user_ca = anchors("keys/ca-user.pub");
    for case in &manifest.cases {
        let c = cert(&format!("ssh-certs/invalid/{}", case.file));
        assert_eq!(c.serial(), case.serial, "{}", case.file);
        let result = verify_user_cert(&c, &user_ca, "dev", manifest.clock, |s| revoked_set.contains(&s));
        let code = result.expect_err(&format!("{} must be refused", case.file)).code();
        assert_eq!(code, case.expected_error, "{}", case.file);
    }
    for serial in revoked.not_revoked_probe {
        assert!(!revoked_set.contains(&serial));
    }
}

#[test]
fn valid_user_vector_is_accepted_for_its_principals_only() {
    let manifest: Manifest = serde_json::from_str(&read("ssh-certs/invalid/manifest.json")).unwrap();
    let user_ca = anchors("keys/ca-user.pub");
    let c = cert("ssh-certs/user-interactive-valid.cert");
    verify_user_cert(&c, &user_ca, "dev", manifest.clock, |_| false).expect("valid for dev");
    verify_user_cert(&c, &user_ca, "u:gh:583231", manifest.clock, |_| false).expect("valid for the subject");
    let err = verify_user_cert(&c, &user_ca, "root", manifest.clock, |_| false).unwrap_err();
    assert_eq!(err.code(), "principal_mismatch");
    // The same certificate against the wrong CA set.
    let err = verify_user_cert(&c, &anchors("keys/rogue-ca.pub"), "dev", manifest.clock, |_| false).unwrap_err();
    assert_eq!(err.code(), "unknown_ca");
    // And outside its window.
    let err = verify_user_cert(&c, &user_ca, "dev", c.valid_before(), |_| false).unwrap_err();
    assert_eq!(err.code(), "cert_expired");
}

#[test]
fn valid_host_vector_is_accepted_for_its_names() {
    let manifest: Manifest = serde_json::from_str(&read("ssh-certs/invalid/manifest.json")).unwrap();
    let host_ca = anchors("keys/ca-host.pub");
    let c = cert("ssh-certs/host-valid.cert");
    verify_host_cert(&c, &host_ca, "10.0.0.5", manifest.clock).expect("by ip");
    verify_host_cert(&c, &host_ca, "sbx-01jx.sbx.acme.gatehouse.io", manifest.clock).expect("by name");
    assert_eq!(
        verify_host_cert(&c, &host_ca, "other.acme.gatehouse.io", manifest.clock).unwrap_err().code(),
        "principal_mismatch"
    );
    // A user cert is not a host cert, whoever signed it.
    let u = cert("ssh-certs/user-interactive-valid.cert");
    assert_eq!(
        verify_host_cert(&u, &anchors("keys/ca-user.pub"), "dev", manifest.clock).unwrap_err().code(),
        "wrong_cert_type"
    );
}

#[test]
fn per_node_wildcard_principals_match_boxes_under_the_node() {
    // Minted by the stub CA: the §5.3 per-node wildcard shape.
    let ca = min_core::stub::StubCa::generate();
    let key = min_core::testing::generate_ed25519_key();
    let now = min_core::rt::unix_now();
    let c = ca.mint_host_cert(
        &key.public_key(),
        &["*.node1.box.stub.minimal.dev".to_string(), "10.90.0.1".to_string()],
        now,
    );
    let anchors = ca.host_anchors();
    verify_host_cert(&c, &anchors, "box-a.node1.box.stub.minimal.dev", now).expect("wildcard");
    verify_host_cert(&c, &anchors, "10.90.0.1", now).expect("exact");
    assert_eq!(
        verify_host_cert(&c, &anchors, "box-a.node2.box.stub.minimal.dev", now).unwrap_err().code(),
        "principal_mismatch"
    );
    assert_eq!(
        verify_host_cert(&c, &anchors, "node1.box.stub.minimal.dev", now).unwrap_err().code(),
        "principal_mismatch",
        "the wildcard covers names under the node, not the node itself"
    );
}
