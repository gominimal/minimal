//! Spike proofs for unifying the own-IP tap mechanism on hakoniwa's `RustSlirp`.
//!
//! Today an own-IP PTask gets its tap in one of two ways, and which one depends
//! on whether `minimald` is root:
//!
//! * **DM2, native Linux, unprivileged** — `RustSlirp` creates the tap *inside*
//!   the sandbox's user+network namespace and hands the fd back via
//!   `hakoniwa::Child::rustslirp_tapfd`. No host `CAP_NET_ADMIN`.
//! * **DM1/3/4, in a libkrun VM, root** — [`minimald::net::switch::open_tap`] plus
//!   `ip`/`nsenter` ([`minimald::net::switch::tap_netns_commands`]) create the tap
//!   in the guest's root netns and move it in. Needs `CAP_NET_ADMIN`.
//!
//! Two mechanisms means two rollback owners, and it is the root cause of most of
//! the machinery proposed in `docs/specs/12-spec-sandbox-network-provider`.
//! `docs/specs/03-spec-networking/networking-with-diagrams.md` says the two
//! deployments should differ only in *relay transport* — diagram 7 labels both
//! host panels `PTasks (each: userns + netns + tap)`, and diagram 6 maps the
//! isolation requirement to building block B1, "Linux user namespaces
//! (unprivileged netns + tap)", at no per-invocation root. `RustSlirp` is B1; the
//! in-VM `open_tap` path is not.
//!
//! So: can the in-VM path use `RustSlirp` too? It is a superset-of-privilege
//! question — `RustSlirp` `setns`es into the target's user *and* network
//! namespaces (`souk4711/hakoniwa`, `hakoniwa/src/unshare/newnet/rustslirp.rs`),
//! and the rootless path assumes an unprivileged userns, which `sandbox2` gets
//! from its `uidmap(1000)`. Root should be able to do everything that path does,
//! but the combination has never been exercised. These two proofs exercise it:
//!
//! * `rustslirp_tap_comes_up_unprivileged` — the DM2 baseline. This mechanism is
//!   in production on the native path today and has no automated coverage: the
//!   own-IP proofs in `netns_root_integration.rs` drive the *other* mechanism
//!   (`sudo ip tuntap add` + `open_tap` + `tap_netns_commands`), and
//!   `scripts/session-e2e.sh` has no own-IP case at all. Without this there is no
//!   baseline to compare the root result against.
//! * `rustslirp_tap_comes_up_as_root` — the same proof with the hakoniwa parent
//!   running as root, which is what `minimald` is inside the guest. A pass says
//!   the in-VM path can drop `open_tap`/`move_tap_into_netns` and use the
//!   rootless mechanism; a failure says unification needs a change in hakoniwa
//!   itself (a git-pinned third-party dependency) and should be abandoned.
//!
//! Both build the container exactly as [`sandbox2::Sandbox::new_container`] does
//! for an own-IP PTask — same uid/gid map, same namespaces, same `RustSlirp`
//! settings — so a drift in that construction shows up here rather than only in
//! a live session.
//!
//! Both are `#[ignore]` and additionally early-return unless `MINIMALD_NETNS_TEST`
//! is set. Auto-discovered by the native lane's `minimald-root-integration` job
//! via the `_root_integration` binary-name suffix
//! (`-E 'binary(/_root_integration$/)'`) — ubuntu-latest with sudo and
//! unprivileged userns. Neither KVM nor gvproxy is needed: neither proof attaches
//! to a switch, because tap *creation* is the step that differs.
//!
//! To run locally you need a host with `/dev/net/tun`, unprivileged userns, and
//! passwordless sudo:
//! `MINIMALD_NETNS_TEST=1 cargo test -p minimald --test rustslirp_root_integration -- --include-ignored`
#![cfg(target_os = "linux")]

use std::io::Read as _;
use std::net::Ipv4Addr;
use std::process::Command;

use minimald::net::{DEFAULT_MTU, SwitchSubnet};

/// Set on the sudo re-exec so the root proof knows it is the inner run and does
/// the work instead of re-execing again.
const AS_ROOT_MARKER: &str = "MINIMALD_RUSTSLIRP_AS_ROOT";

/// A `PATH` for the in-sandbox probe. The sandbox bind-mounts the host rootfs, so
/// `ip` is present, but hakoniwa does not guarantee an inherited `PATH`; these are
/// the same trusted directories `minimald::net::switch` resolves `ip`/`nsenter`
/// against.
const PROBE_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";

/// Whether the gate env var is set; when absent both proofs early-return so a
/// default `cargo test` run never attempts namespace or tap operations.
fn gated() -> bool {
    if std::env::var_os("MINIMALD_NETNS_TEST").is_some() {
        return true;
    }
    eprintln!("skipping RustSlirp proof: MINIMALD_NETNS_TEST not set");
    false
}

/// The tap parameters an own-IP PTask gets, computed the way the session host
/// computes them today (`crates/minimald/src/session_host.rs`): the PTask address
/// from the switch subnet's allocatable range, the netmask from its prefix, the
/// gateway from the subnet, and the relay's frame-buffer MTU.
fn tap_params() -> (Ipv4Addr, Ipv4Addr, Ipv4Addr, u16) {
    let subnet = SwitchSubnet::default();
    let prefix = subnet.prefix();
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (
        Ipv4Addr::from(subnet.first_ptask()),
        Ipv4Addr::from(mask),
        subnet.gateway(),
        DEFAULT_MTU,
    )
}

/// Fails loudly, and specifically, when the host cannot create a tap at all.
///
/// Without this a missing prerequisite surfaces as "RustSlirp handed out no tap
/// fd" with empty output, which reads as a *negative result for the spike* and
/// would wrongly retire the mechanism. Neither prerequisite is optional and
/// neither is RustSlirp-specific: `open_tap` needs `/dev/net/tun` just as much.
/// A failure here means a broken or newly-restricted runner, and the native
/// lane's own "Confirm netns capability" step exists for the same reason —
/// better a loud failure than a mis-skip into a false green.
fn preflight() {
    assert!(
        std::path::Path::new("/dev/net/tun").exists(),
        "prerequisite missing: /dev/net/tun is absent, so NEITHER tap mechanism can \
         work here. This is a host limitation, not a result for RustSlirp."
    );
    let userns = Command::new("unshare")
        .args(["--user", "--net", "true"])
        .status();
    assert!(
        matches!(&userns, Ok(s) if s.success()),
        "prerequisite missing: cannot create a user+network namespace ({userns:?}), so \
         the sandbox cannot be built at all. On Ubuntu this is usually AppArmor — the \
         native lane sets kernel.apparmor_restrict_unprivileged_userns=0. Not a result \
         for RustSlirp."
    );
}

/// What the sandbox reported about its own network, plus whether hakoniwa handed
/// the tap fd back out.
struct OwnIpProbe {
    /// `Some` when `RustSlirp` created the tap and passed its fd to the parent —
    /// the fd the switch relay would consume. `None` means the setup did not run.
    tapfd: Option<i32>,
    /// `ip addr` / `ip route` as seen from *inside* the sandbox's netns.
    stdout: String,
    stderr: String,
    /// How the probe process ended. Reported on failure: a sandbox that died
    /// before running `ip` produces the same empty output as one whose tap was
    /// never made, and the two need telling apart.
    status: String,
}

/// Builds an own-IP-shaped sandbox the way [`sandbox2::Sandbox::new_container`]
/// does, runs a probe inside it, and reports what came back.
///
/// The probe runs `ip` *inside* the sandbox rather than `nsenter`-ing in from
/// outside: the namespace belongs to the sandbox, so asking it directly is both
/// simpler and a stronger statement — it is the view the PTask's own processes
/// get.
fn run_own_ip_sandbox() -> OwnIpProbe {
    let (address, netmask, gateway, mtu) = tap_params();

    let mut container = hakoniwa::Container::new();
    container
        .rootfs("/")
        .expect("bind-mounting the host rootfs")
        // Mirrors `sandbox2`: the sandbox user is uid/gid 1000, and that mapping
        // is what makes the userns `RustSlirp` joins an unprivileged one.
        .uidmap(1000)
        .gidmap(1000)
        .devfsmount("/dev")
        .tmpfsmount("/tmp")
        .unshare(hakoniwa::Namespace::Cgroup)
        .runctl(hakoniwa::Runctl::IgnoreCgroupSetupFailed)
        // `network()` does not imply the netns unshare, so this must come first —
        // the same ordering constraint `new_container` documents.
        .unshare(hakoniwa::Namespace::Network);

    container.network(
        hakoniwa::RustSlirp::default()
            // L2: the gvproxy relay is HyperKit-framed Ethernet, not L3.
            .mode(hakoniwa::RustSlirpMode::TAP)
            .address(address)
            .netmask(netmask)
            // Next-hop default route; gvproxy is a real gateway and does not
            // proxy-ARP, so an on-link route would not do.
            .gateway(hakoniwa::RustSlirpGateway::IfaceWithAddr(gateway))
            .mtu(mtu)
            .clone(),
    );

    let mut command = container.command("/bin/sh");
    command
        .args([
            "-c",
            &format!("export PATH={PROBE_PATH}; ip -4 addr show; echo ---; ip route show"),
        ])
        .stdout(hakoniwa::Stdio::MakePipe)
        .stderr(hakoniwa::Stdio::MakePipe);

    let mut child = command.spawn().expect(
        "spawning the own-IP sandbox: a RustSlirp setup failure surfaces here as \
         SetupNetworkFailed, which is the negative result this proof is looking for",
    );
    // Read before `wait`: the probe's output is a few hundred bytes, well under
    // the pipe buffer, but taking the pipes first keeps this correct if the
    // probe ever grows.
    let tapfd = child.rustslirp_tapfd;
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let status = match child.wait() {
        Ok(s) => format!("{s:?}"),
        Err(e) => format!("wait failed: {e}"),
    };

    OwnIpProbe {
        tapfd,
        stdout,
        stderr,
        status,
    }
}

/// Asserts the sandbox came up with a configured tap: hakoniwa handed the fd out,
/// and the PTask's own address and default route are present inside its netns.
fn assert_tap_is_up(probe: &OwnIpProbe, who: &str) {
    let (address, _, gateway, _) = tap_params();

    // `preflight` has already ruled out the host-level causes, so an empty
    // result here really is RustSlirp's answer.
    assert!(
        probe.tapfd.is_some(),
        "{who}: RustSlirp handed out no tap fd, so no switch relay could be built\n\
         exit={}\nstdout={}\nstderr={}",
        probe.status,
        probe.stdout,
        probe.stderr,
    );
    assert!(
        probe.stdout.contains(&address.to_string()),
        "{who}: the PTask address {address} is not configured inside the sandbox netns\n\
         exit={}\nstdout={}\nstderr={}",
        probe.status,
        probe.stdout,
        probe.stderr,
    );
    assert!(
        probe.stdout.contains(&gateway.to_string()),
        "{who}: no default route via the switch gateway {gateway} inside the sandbox netns\n\
         exit={}\nstdout={}\nstderr={}",
        probe.status,
        probe.stdout,
        probe.stderr,
    );
}

/// The DM2 baseline: unprivileged, `RustSlirp` builds and configures the tap
/// inside the sandbox's own namespaces.
///
/// This is the mechanism the native own-IP path ships today. It had no automated
/// coverage before this proof.
#[test]
#[ignore = "creates a tap in a user+network namespace; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
fn rustslirp_tap_comes_up_unprivileged() {
    if !gated() {
        return;
    }
    preflight();
    let probe = run_own_ip_sandbox();
    assert_tap_is_up(&probe, "unprivileged");
}

/// The spike's blocking question: the same proof with the hakoniwa parent running
/// as **root**, which is what `minimald` is inside a libkrun guest.
///
/// The test binary runs unprivileged (the native lane's root job notes that "the
/// tap/netns commands sudo themselves"), so the proof re-execs itself under
/// `sudo` and asserts on the inner run. `sudo -E env VAR=…` rather than `sudo
/// VAR=… `: sudo's `env_reset` drops assignments made on its own command line
/// unless the sudoers policy grants `SETENV`, but it will happily exec `env`.
#[test]
#[ignore = "creates a tap as root; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
fn rustslirp_tap_comes_up_as_root() {
    if !gated() {
        return;
    }

    // The inner, sudo'd run: do the work and let the exit status carry the result
    // back out to the outer run.
    if std::env::var_os(AS_ROOT_MARKER).is_some() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "the re-exec was supposed to be root but is not; sudo did not elevate"
        );
        preflight();
        let probe = run_own_ip_sandbox();
        assert_tap_is_up(&probe, "root");
        return;
    }

    let exe = std::env::current_exe().expect("locating this test binary for the sudo re-exec");
    let out = Command::new("sudo")
        .arg("-E")
        .arg("env")
        .arg(format!("{AS_ROOT_MARKER}=1"))
        .arg("MINIMALD_NETNS_TEST=1")
        .arg(&exe)
        // libtest takes the filter as a positional argument, so it goes last.
        .args([
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
            "rustslirp_tap_comes_up_as_root",
        ])
        .output()
        .expect("re-execing this test binary under sudo (is passwordless sudo available?)");

    assert!(
        out.status.success(),
        "RustSlirp did not bring a tap up with a root parent — the in-VM own-IP path \
         cannot use the rootless mechanism without a change in hakoniwa itself.\n\
         status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
