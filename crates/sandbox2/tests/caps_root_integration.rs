//! Capability proofs for the sandbox layer (NET-083): every box runs without
//! `CAP_NET_RAW`, and without any other capability.
//!
//! * `boxes_lack_cap_net_raw` — inside an *open* box (a plan with no
//!   socket-family filter, so the only thing that can refuse a raw socket is
//!   the missing capability) and inside a *none* box (whose family filter
//!   refuses it earlier still), a process reports its uid, gid, capability
//!   sets and `no_new_privs` bit from `/proc/self/status` and attempts a raw
//!   socket. The report must show the unprivileged box uid, `no_new_privs` set,
//!   every capability set empty, and the bounding set — the one set an exec
//!   does not clear — holding none of the capabilities no box may hold,
//!   `CAP_NET_RAW` first.
//!
//! These proofs launch a real box, which needs the unprivileged user namespace
//! every sandbox starts by unsharing. A host that would deny it (stock Ubuntu
//! 24.04 restricts it for unconfined processes) cannot run them at all, so they
//! say why and pass rather than fail; the CI lane that relaxes that sysctl runs
//! them for real. The probe is compiled statically with `gcc`, and a host whose
//! gate passes but that has no `gcc` fails the proof rather than skipping it
//! into a false green.
//!
//! To run locally you need a host that allows unprivileged user namespaces and
//! a C compiler:
//! `cargo nextest run -p sandbox2 boxes_lack_cap_net_raw`
#![cfg(target_os = "linux")]

use sandbox2::NetPlan;
use sandbox2::config::{BOX_FORBIDDEN_CAPABILITIES, BOX_GID, BOX_UID, Config, SandboxMapped};

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// C source for a tiny static probe that reports a box's identity and
/// capability sets from its status file, then the errno of a raw socket attempt
/// — the one capability-dependent operation NET-083 is about — and of a stream
/// socket, which needs no capability and therefore still works. One `key:
/// value` line per fact, parsed by the caller.
const CAP_PROBE_C: &str = r#"
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) { perror("fopen /proc/self/status"); return 1; }
    char line[256];
    while (fgets(line, sizeof line, status)) {
        if (strncmp(line, "Uid:", 4) == 0 || strncmp(line, "Gid:", 4) == 0 ||
            strncmp(line, "Cap", 3) == 0 || strncmp(line, "NoNewPrivs:", 11) == 0) {
            fputs(line, stdout);
        }
    }
    fclose(status);

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    printf("raw_socket_errno: %d\n", raw >= 0 ? 0 : errno);
    if (raw >= 0) close(raw);

    int stream = socket(AF_INET, SOCK_STREAM, 0);
    printf("stream_socket_errno: %d\n", stream >= 0 ? 0 : errno);
    if (stream >= 0) close(stream);
    return 0;
}
"#;

/// Compile the capability probe statically and return its path.
///
/// Panics when no C compiler is on `PATH` instead of skipping: this proof is
/// only reached on a host whose user-namespace gate passed, so a missing
/// compiler is a host that promised to run it and cannot — a skip here would be
/// a vacuous green on a security proof.
fn compile_cap_probe(base: &Path) -> PathBuf {
    let src = base.join("cap_probe.c");
    let bin = base.join("cap_probe");
    std::fs::write(&src, CAP_PROBE_C).expect("writing capability probe source");
    let status = Command::new("gcc")
        .args(["-static", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .expect(
            "spawning gcc to compile the capability probe — a gcc that is not \
             on PATH means this proof's host gate passed but the host cannot \
             keep that promise: install a C compiler (build-essential on \
             Ubuntu) rather than letting a security proof pass without \
             asserting anything",
        );
    assert!(
        status.success(),
        "gcc failed to compile the capability probe: {status:?}"
    );
    bin
}

/// Create a minimal rootfs directory containing the static probe at
/// `/usr/bin/probe`. The sandbox layer symlinks `/bin -> /usr/bin` when `/bin`
/// is absent, so `/usr/bin` must exist. `usr/lib` is also present so the layer
/// can create its `usr/lib` symlink.
fn probe_rootfs(dir: &Path, probe: &Path) {
    let usr_bin = dir.join("usr").join("bin");
    std::fs::create_dir_all(&usr_bin).expect("create rootfs usr/bin dir");
    std::fs::copy(probe, usr_bin.join("probe")).expect("copy probe into rootfs");
    std::fs::create_dir_all(dir.join("usr").join("lib")).expect("create rootfs usr/lib dir");
    // An empty /etc satisfies hakoniwa's rootfs setup without forcing a host
    // /etc bind that could trip over locked mount flags in restricted CI
    // runners.
    std::fs::create_dir_all(dir.join("etc")).expect("create rootfs etc dir");
}

/// Where this proof builds its boxes: the target directory's tmp.
///
/// hakoniwa remounts every bind in a box read-only, and in a user namespace
/// that request may only repeat flags the underlying mount already has — a
/// bind whose source carries a locked `nodev` (a /tmp on a `nosuid,nodev`
/// tmpfs) is refused a remount that does not ask for `nodev` back, so a box
/// built on such a /tmp dies in its mount setup. The target directory sits on
/// the checkout's filesystem, which carries no such lock here or on the CI
/// runners, and the rootfs source has to share a filesystem with the sandbox
/// anyway (the layer assembles the rootfs as a hardlink farm over it).
fn base_dir() -> PathBuf {
    // The target directory this build uses; cargo points test targets at its
    // own tmp through CARGO_TARGET_DIR, and a checkout that lets cargo default
    // has one at its root, ignored by git like everything under target/.
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(|dir| PathBuf::from(dir).join("tmp"))
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp"));
    std::fs::create_dir_all(&target).expect("creating the target tmp dir");
    target
}

/// Launch a box for `plan`, run the probe inside it, and return its report.
///
/// Both boxes come from the production launch path — the same
/// `Sandbox::new_container` every consumer uses — so what the report shows is
/// what any box a session or a task runs in holds, not a hand-built container.
async fn box_report(plan: NetPlan) -> BTreeMap<String, String> {
    let base_dir = base_dir();
    let no_base_dir = format!("base temp dir under {}", base_dir.display());
    let base = tempfile::tempdir_in(&base_dir).expect(&no_base_dir);
    let probe = compile_cap_probe(base.path());
    let source = base.path().join("rootfs-src");
    probe_rootfs(&source, &probe);

    let config = Config::new("cap-probe")
        .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
        .with_dns(false)
        .with_plan(plan);
    let no_sandbox_dir = format!("sandbox temp dir under {}", base_dir.display());
    let sandbox_base = tempfile::tempdir_in(&base_dir).expect(&no_sandbox_dir);
    let mut sandbox = config
        .build(sandbox_base.path().join("sandbox"), ())
        .await
        .expect("building the box");
    let plan = sandbox.built_in_plan();
    let container = sandbox
        .new_container(&plan)
        .expect("building the box's container");

    let mut command = sandbox
        .command(
            &container,
            "/usr/bin/probe",
            [""; 0],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect("building the probe command");
    command.stdout(hakoniwa::Stdio::MakePipe);
    let mut child = command.spawn().expect("spawning the probe in the box");

    let stdout = child.stdout.take().expect("the probe's stdout pipe");
    let report = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            let mut buf = Vec::new();
            std::io::BufReader::new(stdout)
                .read_to_end(&mut buf)
                .expect("reading the probe's report");
            buf
        }),
    )
    .await
    .expect("the probe in the box did not report in time")
    .expect("spawn_blocking join");
    let status = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || child.wait()),
    )
    .await
    .expect("waiting for the probe in the box timed out")
    .expect("spawn_blocking join")
    .expect("waiting for the probe in the box");
    assert!(
        status.success(),
        "the probe in the box failed: {status:?}\nreport: {}",
        String::from_utf8_lossy(&report)
    );

    parse_report(&String::from_utf8_lossy(&report))
}

/// NET-083. Every box runs without `CAP_NET_RAW`, and without any other
/// capability: it execs as the unprivileged box uid inside its user namespace
/// with `no_new_privs` set, so the kernel clears every capability set at exec
/// and no file capability can restore one, and the capabilities no box may
/// hold are dropped from the bounding set — the one set an exec does not clear
/// — so they cannot come back.
///
/// Both halves matter. An open box has no socket-family filter, so a raw socket
/// there is refused by the missing capability alone, while a stream socket
/// still works — the refusal is about the capability, not a broken network
/// stack. A none box carries the family filter on top of the same credentials,
/// so the raw socket is refused by the seal before the capability check is
/// reached, and what its report adds is that the credentials and the filter
/// hold together in the one launch closure that applies both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boxes_lack_cap_net_raw() {
    if let Some(reason) = sandbox2::user_namespaces_restriction() {
        eprintln!(
            "skipping boxes_lack_cap_net_raw: this host denies the \
             unprivileged user namespace every sandbox starts by unsharing: \
             {reason}"
        );
        return;
    }

    let open = box_report(NetPlan::host()).await;
    assert_box_credentials(&open, "an open box");
    assert_eq!(
        reported_errno(&open, "raw_socket_errno", "an open box"),
        libc::EPERM,
        "an open box must not be able to open a raw socket: it holds no \
         CAP_NET_RAW"
    );
    assert_eq!(
        reported_errno(&open, "stream_socket_errno", "an open box"),
        0,
        "a stream socket needs no capability, so an open box refusing raw \
         but not stream is the refusal about the capability, not a broken \
         network stack"
    );

    let none = box_report(NetPlan::none()).await;
    assert_box_credentials(&none, "a none box");
    assert_eq!(
        reported_errno(&none, "raw_socket_errno", "a none box"),
        libc::EAFNOSUPPORT,
        "a none box's family filter must still refuse the socket family \
         itself, seal and credentials together in the same launch"
    );
}

/// What every box's report must show: the unprivileged box uid and gid, the
/// `no_new_privs` bit set, every capability set empty, and the bounding set
/// holding none of the capabilities no box may hold.
fn assert_box_credentials(report: &BTreeMap<String, String>, what: &str) {
    // The box uid and gid in every id field the status file reports (real,
    // effective, saved, fs): a box is never root inside its own user
    // namespace, which is what makes exec clear the capability sets at all.
    for (key, expected) in [("Uid", BOX_UID), ("Gid", BOX_GID)] {
        let value = reported(report, key, what);
        let fields: Vec<&str> = value.split_ascii_whitespace().collect();
        assert_eq!(
            fields.len(),
            4,
            "{what}: {key} must carry the real, effective, saved and fs ids: {value}"
        );
        for field in &fields {
            let not_a_number = format!("{what}: {key} field {field} is not a number");
            let id: u32 = field.parse().expect(&not_a_number);
            assert_eq!(
                id, expected,
                "{what}: the box must exec as the box uid/gid {expected} in every {key} field: {value}"
            );
        }
    }

    assert_eq!(
        reported(report, "NoNewPrivs", what),
        "1",
        "{what}: the box's no_new_privs bit must be set, so no file \
         capability or setuid bit can restore a privilege"
    );

    // The sets exec clears: empty by construction, whatever the daemon's own
    // credential state was.
    for set in ["CapPrm", "CapEff", "CapInh", "CapAmb"] {
        let mask = capability_mask(report, set, what);
        assert_eq!(
            mask, 0,
            "{what}: {set} must be empty — the box execs as the unprivileged \
             box uid with no_new_privs set, so exec clears it"
        );
    }

    // The bounding set, the one set exec does not clear: it must hold none of
    // the capabilities no box may hold. A capability left in it is one a file
    // capability in the box could hand back.
    let mask = capability_mask(report, "CapBnd", what);
    for cap in BOX_FORBIDDEN_CAPABILITIES {
        assert_eq!(
            mask & (1 << cap.number),
            0,
            "{what}: CapBnd must not hold {} (bit {}): the bounding set \
             survives exec, so a capability left in it is one a file \
             capability in the box could restore",
            cap.name,
            cap.number
        );
    }
}

/// The probe's report: one entry per `key: value` line it printed.
fn parse_report(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// The probe's report line for `key`, or a panic naming what never arrived: a
/// report that does not show up is the failure to show, not a mystery, so the
/// panic carries the report that did arrive, whatever shape it is in.
fn reported<'a>(report: &'a BTreeMap<String, String>, key: &str, what: &str) -> &'a str {
    let never_arrived = format!("{what}: the probe did not report {key}: {report:?}");
    report.get(key).expect(&never_arrived)
}

/// The errno the probe reported for `key`, e.g. `raw_socket_errno`.
fn reported_errno(report: &BTreeMap<String, String>, key: &str, what: &str) -> i32 {
    let not_a_number = format!("{what}: {key} is not a number");
    reported(report, key, what).parse().expect(&not_a_number)
}

/// One capability-set mask from the probe's report, e.g. `CapBnd:
/// 000001ffffffffff`.
fn capability_mask(report: &BTreeMap<String, String>, set: &str, what: &str) -> u64 {
    let value = reported(report, set, what);
    let no_mask = format!("{what}: {set} must carry one hex mask: {value}");
    let mask = value.split_ascii_whitespace().next().expect(&no_mask);
    let not_a_mask = format!("{what}: {set} is not a hex mask: {mask}");
    u64::from_str_radix(mask, 16).expect(&not_a_mask)
}
