//! Proof that the sandbox layer builds an own-IP tap where a plan asks for one:
//! a [`sandbox2::NetPlan`] with tap parameters, `new_container` from it, a real
//! spawn, and [`sandbox2::Spawned::from_child`] handing the descriptor out — how
//! a native (DM2) own-IP PTask gets its tap, rootless. No switch is attached.
//!
//! `#[ignore]`, and early-returns unless `MINIMALD_NETNS_TEST` is set; the
//! native lane's `minimald-root-integration` job discovers it by suffix. Locally:
//! `MINIMALD_NETNS_TEST=1 cargo test -p minimald --test own_ip_tap_root_integration -- --include-ignored`
#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::path::Path;

use minimald::net::{DEFAULT_MTU, SwitchSubnet};
use sandbox2::config::{Config, SandboxMapped};
use sandbox2::{NetPlan, Spawned, TapSpec};

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
