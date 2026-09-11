//! Handshake-level: certificate auth and host-certificate verification over
//! the in-process WireGuard tunnel, with certificates minted at test time by
//! the stub CA (the frozen arch vectors expired on 2026-06-15, and russh's
//! server pre-validates the window against the wall clock).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey as WgPublic, StaticSecret};
use min_core::credential::{Anchors, Credential, HostPolicy, KeySigner};
use min_core::stub::{Case, Stub};
use min_core::testing::{FakeMinimald, generate_ed25519_key};
use min_core::wg::{DatagramPipe, WgConfig, WgStack};
use min_core::{Attach, ConnectOptions, Error, Event, Grid};
use russh::keys::Certificate;
use russh::server;

const TAB_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 2);
const DAEMON_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 1);

struct Bench {
    stub: Arc<Stub>,
    tab: WgStack,
}

/// A daemon node in certificate mode (host cert presented, cert auth only)
/// and a tab node, cross-connected in memory. `present_host_cert: false`
/// leaves the daemon on its bare host key.
fn bench(present_host_cert: bool) -> Bench {
    let stub = Arc::new(Stub::new(&DAEMON_IP.to_string()));
    let host_key = generate_ed25519_key();
    let host_cert = present_host_cert.then(|| {
        stub.ca
            .mint_host_cert(&host_key.public_key(), &[DAEMON_IP.to_string()], min_core::rt::unix_now())
    });
    let tab_secret = StaticSecret::from([0x71u8; 32]);
    let daemon_secret = StaticSecret::from([0x72u8; 32]);
    let (tab_pipe, daemon_pipe) = DatagramPipe::pair(256);
    let (tab, tab_driver) = WgStack::new(
        WgConfig {
            private_key: tab_secret.to_bytes(),
            peer_public_key: WgPublic::from(&daemon_secret).to_bytes(),
            local_ip: TAB_IP,
            prefix_len: 24,
            peer_ip: DAEMON_IP,
            persistent_keepalive_secs: Some(25),
            initiate: true,
        },
        tab_pipe,
    );
    let (daemon, daemon_driver) = WgStack::new(
        WgConfig {
            private_key: daemon_secret.to_bytes(),
            peer_public_key: WgPublic::from(&tab_secret).to_bytes(),
            local_ip: DAEMON_IP,
            prefix_len: 24,
            peer_ip: TAB_IP,
            persistent_keepalive_secs: None,
            initiate: false,
        },
        daemon_pipe,
    );
    tokio::spawn(tab_driver);
    tokio::spawn(daemon_driver);
    // A pool of listening sockets on port 22 (smoltcp accepts one connection
    // per listening socket), so a new attempt never finds the port without a
    // listener while the previous session is being torn down.
    for _ in 0..8 {
        let daemon = daemon.clone();
        let auth = stub.daemon_auth.clone();
        let host_key = host_key.clone();
        let host_cert = host_cert.clone();
        tokio::spawn(async move {
            loop {
                let accepted = daemon.listen(22);
                let config = Arc::new(server::Config {
                    keys: vec![host_key.clone()],
                    certificates: host_cert.clone().into_iter().collect(),
                    ..Default::default()
                });
                if let Ok(running) = server::run_stream(config, accepted, FakeMinimald::with_auth(auth.clone())).await {
                    let _ = running.await;
                }
                if daemon.is_dead() {
                    break;
                }
            }
        });
    }
    Bench { stub, tab }
}

fn credential(stub: &Stub, case: Case) -> (Credential<KeySigner>, u64) {
    let key = generate_ed25519_key();
    let minted = stub
        .ca
        .mint_user_cert(&key.public_key(), &stub.username, &stub.subject, case, min_core::rt::unix_now())
        .expect("mint");
    let certificate = Certificate::from_openssh(&minted.certificate).expect("parse minted cert");
    (
        Credential {
            username: stub.username.clone(),
            certificate,
            signer: KeySigner(key),
        },
        minted.serial,
    )
}

fn policy(stub: &Stub) -> HostPolicy {
    HostPolicy {
        anchors: stub.ca.host_anchors(),
        expected_principal: DAEMON_IP.to_string(),
    }
}

async fn attempt(b: &Bench, cred: Option<Credential<KeySigner>>, policy: Option<HostPolicy>) -> Result<Attach, Error> {
    tokio::time::timeout(
        Duration::from_secs(10),
        Attach::connect_with(
            b.tab.connect(22),
            ConnectOptions {
                session_id: "sess-cert",
                term: "xterm-256color",
                grid: Grid { cols: 80, rows: 24 },
                credential: cred,
                host_policy: policy,
            },
        ),
    )
    .await
    .expect("no timeout")
}

#[tokio::test]
async fn valid_certificate_attaches_and_the_host_certificate_is_verified() {
    let b = bench(true);
    let (cred, serial) = credential(&b.stub, Case::Valid);
    let attached = attempt(&b, Some(cred), Some(policy(&b.stub))).await.expect("attach");
    let (writer, mut reader) = attached.split();
    match tokio::time::timeout(Duration::from_secs(5), reader.next()).await {
        Ok(Some(Event::Data(bytes))) => assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), "attached sess-cert 80x24\r\n"),
        other => panic!("{other:?}"),
    }
    writer.write(b"hi\n").await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), reader.next()).await {
        Ok(Some(Event::Data(bytes))) => assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), "echo hi\n"),
        other => panic!("{other:?}"),
    }
    let decisions = b.stub.daemon_auth.decisions();
    let last = decisions.last().expect("a decision was recorded");
    assert_eq!(last.result, "accepted");
    assert_eq!(last.serial, serial);
    assert_eq!(last.user, "dev");
    assert!(last.key_id.contains(r#""sub":"u:stub:1""#), "{}", last.key_id);
}

#[tokio::test]
async fn auth_none_is_refused_in_certificate_mode() {
    let b = bench(true);
    let err = attempt(&b, None, Some(policy(&b.stub))).await.err().expect("must fail");
    assert!(matches!(err, Error::AuthRejected), "{err}");
}

#[tokio::test]
async fn each_refusal_case_is_refused() {
    let b = bench(true);
    // (case, decision code the daemon records, or None when russh refuses the
    // certificate before the daemon's hook runs)
    let cases = [
        (Case::RogueCa, Some("unknown_ca")),
        (Case::HostType, Some("wrong_cert_type")),
        (Case::UnknownCritical, Some("unknown_critical_option")),
        (Case::Revoked, Some("cert_revoked")),
        (Case::Expired, None),
        (Case::NotYetValid, None),
        (Case::Tampered, None),
        (Case::OtherKey, None),
    ];
    for (case, expected) in cases {
        let before = b.stub.daemon_auth.decisions().len();
        let (cred, serial) = credential(&b.stub, case);
        let err = attempt(&b, Some(cred), Some(policy(&b.stub)))
            .await
            .err()
            .unwrap_or_else(|| panic!("{case:?} must be refused"));
        assert!(matches!(err, Error::AuthRejected), "{case:?}: {err}");
        let decisions = b.stub.daemon_auth.decisions();
        match expected {
            Some(code) => {
                let d = decisions.iter().rev().find(|d| d.serial == serial).unwrap_or_else(|| panic!("{case:?}: no decision recorded"));
                assert_eq!(d.result, code, "{case:?}");
            }
            None => assert_eq!(decisions.len(), before, "{case:?}: refused before the daemon's decision"),
        }
    }
    // And a good one still works afterwards.
    let (cred, _) = credential(&b.stub, Case::Valid);
    attempt(&b, Some(cred), Some(policy(&b.stub))).await.expect("valid after refusals");
}

#[tokio::test]
async fn host_policy_refuses_a_wrong_principal_a_rogue_ca_and_a_bare_key() {
    let b = bench(true);
    let (cred, _) = credential(&b.stub, Case::Valid);
    let err = attempt(
        &b,
        Some(cred),
        Some(HostPolicy {
            anchors: b.stub.ca.host_anchors(),
            expected_principal: "10.90.0.9".into(),
        }),
    )
    .await
    .err().expect("wrong principal");
    match err {
        Error::HostRejected(reason) => assert!(reason.contains("principal_mismatch"), "{reason}"),
        other => panic!("{other}"),
    }
    let (cred, _) = credential(&b.stub, Case::Valid);
    let err = attempt(
        &b,
        Some(cred),
        Some(HostPolicy {
            anchors: Anchors::from_openssh_lines([b.stub.ca.rogue_ca_public().as_str()]).unwrap(),
            expected_principal: DAEMON_IP.to_string(),
        }),
    )
    .await
    .err().expect("rogue host CA");
    match err {
        Error::HostRejected(reason) => assert!(reason.contains("unknown_ca"), "{reason}"),
        other => panic!("{other}"),
    }

    // A daemon that presents only its bare key is refused by any policy.
    let bare = bench(false);
    let (cred, _) = credential(&bare.stub, Case::Valid);
    let err = attempt(&bare, Some(cred), Some(policy(&bare.stub))).await.err().expect("bare key");
    match err {
        Error::HostRejected(reason) => assert!(reason.contains("bare key"), "{reason}"),
        other => panic!("{other}"),
    }
}
