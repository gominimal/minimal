//! Proof that the sandbox layer builds an own-IP tap where a plan asks for one:
//! a [`sandbox::NetPlan`] with tap parameters, `new_container` from it, a real
//! spawn, and [`sandbox::Spawned::from_child`] handing the descriptor out — how
//! a native (DM2) own-IP PTask gets its tap, rootless. No switch is attached.
//!
//! `#[ignore]`, and early-returns unless `MINIMALD_NETNS_TEST` is set; the
//! native lane's `minimald-root-integration` job discovers it by suffix. Locally:
//! `MINIMALD_NETNS_TEST=1 cargo test -p minimald --test own_ip_tap_root_integration -- --include-ignored`
#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::path::Path;

use minimald::net::{DEFAULT_MTU, SwitchSubnet};
use sandbox::config::{Config, SandboxMapped};
use sandbox::{NetPlan, Network, PlanFuture, Resolver, Spawned, TapSpec};

/// `/bin/true` and the libraries `ldd` says it loads, at their own paths, plus
/// the `usr/lib` the sandbox layer's `lib64` symlink expects.
fn minimal_rootfs(dir: &Path) {
    std::fs::create_dir_all(dir.join("usr").join("lib")).unwrap();
    let ldd = std::process::Command::new("ldd")
        .arg("/bin/true")
        .output()
        .expect("running ldd");
    let libs = String::from_utf8_lossy(&ldd.stdout);
    let files = libs
        .split_whitespace()
        .filter(|w| w.starts_with('/'))
        .chain(std::iter::once("/bin/true"));
    for file in files {
        let dest = dir.join(file.trim_start_matches('/'));
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(file, &dest).unwrap_or_else(|e| panic!("copying {file}: {e}"));
    }
}

/// The plan a native own-IP PTask is built from: the switch subnet's first
/// PTask address, its netmask and gateway, and the relay's MTU.
fn own_ip_plan() -> NetPlan {
    let subnet = SwitchSubnet::default();
    NetPlan::isolated_with_tap(TapSpec {
        address: Ipv4Addr::from(subnet.first_ptask()),
        netmask: subnet.netmask(),
        gateway: subnet.gateway(),
        mtu: DEFAULT_MTU,
    })
}

#[tokio::test]
#[ignore = "creates a tap in a user+network namespace; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
async fn the_sandbox_layer_builds_the_tap_a_plan_asks_for() {
    if std::env::var_os("MINIMALD_NETNS_TEST").is_none() {
        eprintln!("skipping own-IP tap proof: MINIMALD_NETNS_TEST not set");
        return;
    }
    assert!(
        Path::new("/dev/net/tun").exists(),
        "prerequisite missing: /dev/net/tun is absent, so no tap can be made here"
    );

    let tmp = tempfile::TempDir::new().unwrap();
    let source = tmp.path().join("rootfs-src");
    minimal_rootfs(&source);

    let config = Config::new("own-ip-tap")
        .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
        .with_dns(false)
        .with_plan(own_ip_plan());
    let mut sandbox = config.build(tmp.path().join("sandbox"), ()).await.unwrap();

    let plan = sandbox.built_in_plan();
    let container = sandbox.new_container(&plan).unwrap();
    let mut child = sandbox
        .command(&container, "/bin/true", [""; 0], [("", ""); 0])
        .unwrap()
        .spawn()
        .expect("spawning the own-IP sandbox; a RustSlirp failure surfaces here");

    let mut spawned = Spawned::from_child(&mut child);
    let status = child.wait().expect("waiting for /bin/true");
    assert!(status.success(), "the probe did not run: {status:?}");
    assert!(
        spawned.take_tap_fd().is_some(),
        "RustSlirp handed out no tap descriptor for a plan that asked for one"
    );
    assert!(
        spawned.take_tap_fd().is_none(),
        "the descriptor must be handed out once (017-010)"
    );
}

/// A network with an empty namespace and a name server that nothing serves.
#[derive(Debug)]
struct Empty;

impl Network for Empty {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(NetPlan::isolated().with_resolver(
            Resolver::Nameservers(vec![Ipv4Addr::LOCALHOST]),
        ))))
    }
}

/// NET-155: a fetch placed in a held namespace leaves from that namespace and
/// not from this process's. A listener on this process's loopback serves the
/// file to an unplaced download. The placed download of the same URL cannot
/// reach it, and the listener sees no connection. The namespace's process
/// goes when the hold ends.
#[tokio::test]
#[ignore = "creates a user+network namespace; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
async fn a_placed_fetch_leaves_from_the_held_namespace() {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    if std::env::var_os("MINIMALD_NETNS_TEST").is_none() {
        eprintln!("skipping the held namespace proof: MINIMALD_NETNS_TEST not set");
        return;
    }
    let body = b"the source archive";
    let sha = "1f8ba2cd2f1fae8c6d3f4b2fc2e31a97f2bfb3bb70e6cfa3f6a4a6d3c1f6f7f0";
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&served);
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            assert!(stream.read(&mut buf).unwrap() > 0);
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        }
    });

    let tmp = tempfile::TempDir::new().unwrap();
    let storage = common::RemoteStorage::new(tmp.path().join("downloads"), false)
        .await
        .unwrap();
    let op = ot::OpTracker::new_root();
    let url = format!("http://{addr}/pkg-1.0.tar.gz");

    let held = sandbox::hold_network(&tmp.path().join("held"), Arc::new(Empty))
        .await
        .expect("a held namespace");
    let pid = held.pid();
    assert!(Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(held.nameservers(), &[Ipv4Addr::LOCALHOST]);
    let namespace =
        common::NetNamespace::of_process(pid, held.nameservers(), Arc::new(|_| true)).unwrap();

    let placed = storage
        .download_web_placed(&url, sha, &common::Placement::Namespace(namespace), &op)
        .await
        .expect_err("this process's loopback is not in the namespace");
    assert!(
        placed
            .to_string()
            .starts_with(&format!("could not connect to {addr}: ")),
        "{placed:#}"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        0,
        "nothing reached the listener"
    );

    drop(held);
    for _ in 0..50 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    // The control: the same URL from this process's namespace reaches the
    // listener, so the placed download's failure was its placement.
    drop(
        storage
            .download_web_with_verification_and_caching(&url, sha, None, &op)
            .await,
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the listener was reachable"
    );
}
