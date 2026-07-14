//! `det-init` — the minimal-detonation guest **pid-1** (`/init`).
//!
//! The kernel runs the initramfs `/init` (this binary) as pid-1 inside the
//! detonation microVM. Rather than fork or patch `minimald`, `det-init`
//! *embeds* `minimald`'s public guest-boot library ([`minimald::guest`]) for the
//! parts that are pure pid-1 plumbing — mount `/dev`, enter the ext4 rootfs,
//! bring up root-netns egress, take the VM down — and adds the detonation-
//! specific behaviour on top:
//!
//!   1. mount the BPF pseudo-filesystems the observer needs (`securityfs` + `bpffs`),
//!   2. stage the deny-channel tripwire *before* the LSM attaches,
//!   3. load the per-scan binding nonce from a root-0400 file (for the ROOT
//!      observer only) and prove `nobody` cannot read it,
//!   4. start the root BPF-LSM observer (`detonation-monitor`) and block until it
//!      signals readiness — so we never miss the sample's first syscalls,
//!   5. route the sample's DNS through the observer's collector (networked model),
//!   6. prove `nobody` cannot write the event feed (the uid boundary),
//!   7. fire the tripwire, then run the untrusted sample as `nobody` (`droppriv`),
//!      fork-and-reap so the observer can drain cleanly,
//!   8. drain the observer (SIGTERM, bounded, SIGKILL backstop),
//!   9. return — `main` then takes the VM down.
//!
//! Unlike `detonate.sh`/`init-launcher.sh` this does the boot mounts through the
//! **same code** `minimald` uses (not a `mount` binary the rootfs may lack), and
//! unlike the minvmd-session model it runs the sample **directly** — a detonation
//! is a one-shot, so there is no SSH server, no session, and no dependency on the
//! arbitrary-exec surface #709 removed. The observer streams the JSONL feed to
//! the host over its own vsock port (file fallback); the host consumes that and
//! runs `minimal-detonation verdict`.
//!
//! Isolation is the disposable microVM + `droppriv`'s uid drop — deliberately
//! NOT an in-guest namespace sandbox, which would suppress the very behaviour we
//! detonate to observe. See gominimal/minimal-detonation#194.

use std::ffi::CString;
use std::process::{Command, Stdio};
use std::time::Duration;

use minimald::guest;

// ── Runtime path + parameter contract ───────────────────────────────────────
// These are the interface between the bake (which stages the observer, droppriv,
// tripwire, and honeytokens into the rootfs) and the host (`det-host-agent`,
// which stages the per-scan sample command + binding nonce into the guest image
// before boot). Kept as named constants so a change here is an obvious diff.

/// The generic ext4 rootfs block device minvmd attaches (always `/dev/vda`).
const ROOTFS_DEVICE: &str = "/dev/vda";
/// The per-VM writable data volume (#672); mounted best-effort as the build-env.
const STATE_VOLUME_DEVICE: &str = "/dev/vdb";

/// The root BPF-LSM observer, baked into the rootfs.
const MONITOR: &str = "/opt/detonation/detonation-monitor";
/// The privilege-drop-then-exec helper, baked into the rootfs.
const DROPPRIV: &str = "/opt/detonation/droppriv";

/// Where the observer writes the JSONL feed (also streamed over vsock).
const EVENTS: &str = "/run/det-events.jsonl";
/// The observer touches this once its LSM programs are attached and it is ready.
const READY: &str = "/run/mon.ready";
/// vsock port the observer streams the feed to the host on (file is the fallback).
const MONITOR_VSOCK_PORT: u16 = 1024;

/// The deny-channel tripwire path the LSM `file_open` hook denies with `-EPERM`.
const TRIPWIRE: &str = "/det-tripwire-DENY";

/// Root-0400 file holding the per-scan binding nonce (host-staged). Override with
/// `DET_BINDING_NONCE_FILE`; a plain `DET_BINDING_NONCE` env var also works for
/// local dev (but rides `/proc/<pid>/cmdline`, so it is not the secure channel).
const NONCE_FILE_DEFAULT: &str = "/det/binding-nonce";
/// File holding the exact sample command to detonate (host-staged, verbatim — no
/// base64 needed since a file has no host→ssh→shell quoting to survive). Override
/// with `DET_SAMPLE_FILE`; `DET_SAMPLE_CMD` env also works for local dev.
const SAMPLE_FILE_DEFAULT: &str = "/det/sample.cmd";

/// The sample's `$HOME`: the seeded honeytoken tree (decoy creds baked into the
/// rootfs). A credential thief that reads `$HOME/.aws/credentials` takes the bait.
const HONEYTOKEN_HOME: &str = "/home/det";
/// The unprivileged uid the sample runs as (matches `droppriv` + the observer).
const SAMPLE_UID: u32 = 65534;

/// Bounded wait for the observer to become ready: `READY_ATTEMPTS × POLL`.
const READY_ATTEMPTS: u32 = 100; // 100 × 100ms = 10s
/// Bounded wait for the observer to drain after SIGTERM before SIGKILL.
const DRAIN_ATTEMPTS: u32 = 50; // 50 × 100ms = 5s
const POLL: Duration = Duration::from_millis(100);

/// A top-level error, mirroring `minimald::main`'s shape.
#[derive(Debug)]
enum MainError {
    IO(std::io::Error, &'static str),
    Other(String),
}

fn main() -> Result<(), MainError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("det-init-worker")
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async_main());

    // As the microVM's pid-1 we must not return: exiting init panics the guest
    // kernel and wedges the VM (minimald #730). Take the VM down instead — on a
    // clean detonation and a failed one alike, since either way there is no init
    // left to run. Guarded by `is_detonation_init` so a host-side test run never
    // reboots the developer's machine (mirrors `minimald::is_minimal_microvm`).
    if is_detonation_init() {
        match &result {
            Ok(()) => tracing::info!("detonation complete; taking the microVM down"),
            Err(e) => tracing::error!(error = ?e, "detonation failed; taking the microVM down"),
        }
        let error = guest::shut_down_vm();
        tracing::error!(%error, "shutting the VM down failed; parking pid-1 (exiting it would panic the guest kernel)");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    result
}

async fn async_main() -> Result<(), MainError> {
    init_tracing();

    // ── Boot: reuse minimald's guest-boot library ──────────────────────────
    guest::mount_dev();
    if let Err(e) = guest::enter_rootfs(ROOTFS_DEVICE) {
        // No rootfs disk: nothing to detonate. Emit the simple READY beacon so a
        // watching minvmd host doesn't hang on its READY timeout, then fail.
        tracing::error!(error = %e, device = ROOTFS_DEVICE, "entering rootfs failed");
        let _ = guest::emit_simple_ready_marker().await;
        return Err(MainError::IO(e, "entering rootfs"));
    }
    // The per-VM writable data volume (#672) is the build-env scratch space.
    // Best-effort: a single-sample detonation can run without it (rootfs + /tmp
    // tmpfs suffice); a real ecosystem install that needs GiB of scratch wants
    // it. Not fatal on this prototype path.
    if let Err(e) = guest::mount_state_volume(STATE_VOLUME_DEVICE, guest::STATE_VOLUME_MOUNTPOINT) {
        tracing::warn!(error = %e, device = STATE_VOLUME_DEVICE, "data volume unavailable; build-env limited to rootfs + /tmp");
    }

    // ── BPF pseudo-filesystems (detonation-specific; minimald does not mount
    // these — a vanilla build VM should not carry bpffs). Best-effort: a kernel
    // without them just degrades coverage (the host caps the verdict at REVIEW).
    mount_fs("none", "/sys/kernel/security", "securityfs");
    mount_fs("bpf", "/sys/fs/bpf", "bpf");
    raise_memlock_rlimit();

    // ── Stage the deny-channel tripwire BEFORE the LSM attaches ────────────
    // Once the observer's `file_open` hook is live, even creating this sentinel
    // is denied (chicken-and-egg). World-readable so the later unprivileged probe
    // passes the DAC check and actually reaches the LSM hook. If staging fails
    // (read-only rootfs), the probe later gets ENOENT, no denial is recorded, and
    // the host honestly caps the verdict at REVIEW — never a false "confirmed".
    stage_tripwire();

    // ── Load the per-scan binding nonce (PR2/PR3), for the ROOT observer only ──
    let nonce = load_binding_nonce();

    // ── Capture the real DNS upstream before we repoint the resolver ───────
    // `bring_up_root_egress` will point the resolver at the gvproxy DNS gateway;
    // read whatever the resolver currently is so the collector can forward to it,
    // then (once the collector is up) we repoint at 127.0.0.1 so every query name
    // transits the observer. No-NIC model: this is loopback/empty and a no-op.
    let dns_upstream_pre = read_nameserver();

    // ── Root-netns egress via the host gvproxy shuttle (networked model) ───
    // Held for the detonation's lifetime (dropping tears the relay down).
    // Best-effort: no host gvproxy → the sample simply has no network (the prior
    // no-NIC behaviour), which is still a valid detonation.
    let _egress = match guest::bring_up_root_egress().await {
        Ok(relay) => Some(relay),
        Err(e) => {
            tracing::warn!(error = %e, "root egress unavailable; detonating without network");
            None
        }
    };
    // `bring_up_root_egress` set the resolver to the gvproxy DNS; re-read it so the
    // collector forwards to the *real* upstream (falling back to the pre-egress one).
    let dns_upstream = read_nameserver().or(dns_upstream_pre);

    // ── Start the root observer, block on readiness ────────────────────────
    let _ = std::fs::remove_file(READY);
    let _ = std::fs::remove_file(EVENTS);
    let mut mon = Command::new(MONITOR);
    mon.arg("--output")
        .arg(EVENTS)
        .arg("--ready-file")
        .arg(READY)
        .arg("--vsock-port")
        .arg(MONITOR_VSOCK_PORT.to_string());
    if let Some(n) = &nonce {
        // The nonce is set on the OBSERVER's environment only; it is never set on
        // the sample's, so uid 65534 never sees it (the F3/F4 guarantee).
        mon.env("DET_BINDING_NONCE", n);
    }
    if let Some(up) = &dns_upstream {
        mon.env("DET_DNS_UPSTREAM", up);
    }
    let mut monitor = mon
        .spawn()
        .map_err(|e| MainError::IO(e, "spawning the observer"))?;
    let mon_pid = monitor.id();
    tracing::info!(pid = mon_pid, output = EVENTS, "started root observer");

    for attempt in 0..READY_ATTEMPTS {
        if std::path::Path::new(READY).exists() {
            break;
        }
        if let Some(status) = monitor
            .try_wait()
            .map_err(|e| MainError::IO(e, "polling the observer"))?
        {
            return Err(MainError::Other(format!(
                "observer pid={mon_pid} exited before becoming ready ({status})"
            )));
        }
        if attempt + 1 == READY_ATTEMPTS {
            let _ = monitor.kill();
            return Err(MainError::Other(
                "observer did not become ready within 10s".to_string(),
            ));
        }
        tokio::time::sleep(POLL).await;
    }
    tracing::info!("observer ready");

    // ── Prove nobody cannot read the nonce (the nonce channel must not leak) ──
    // The file channel exists precisely so the `nobody` sample can NEVER read the
    // nonce — a sample that learns it could forge a feed that passes
    // `--expect-nonce`. Fail closed if the leak-check ever succeeds.
    if nonce.is_some() {
        let nonce_file = nonce_file_path();
        if nobody_can(&format!("cat {nonce_file}")) {
            return Err(MainError::Other(format!(
                "SECURITY: binding nonce {nonce_file} is readable by uid {SAMPLE_UID} — nonce channel leaks"
            )));
        }
        tracing::info!("nonce leak-check passed (nobody cannot read the nonce file)");
    }

    // ── Route the sample's DNS through the collector (networked model only) ──
    // The collector (127.0.0.1:53) is now listening and forwards to the upstream,
    // so repointing the resolver keeps resolution working while making every
    // query name observable. Skip in the no-NIC model (upstream loopback/empty).
    match dns_upstream.as_deref() {
        None | Some("") | Some("127.0.0.1") | Some("::1") => {}
        Some(up) => match install_local_resolver() {
            Ok(()) => tracing::info!(upstream = up, "routed sample DNS through the collector"),
            Err(e) => tracing::warn!(error = %e, "could not repoint resolver; DNS names may go unobserved"),
        },
    }

    // ── uid-boundary self-check (PR3): nobody must not be able to write the feed ──
    // The whole "a nobody sample can't forge the feed" guarantee rests on the feed
    // being unwritable by uid 65534. Non-destructive (`test -w`); fail closed.
    if nobody_can(&format!("test -w {EVENTS}")) {
        return Err(MainError::Other(format!(
            "SECURITY: feed {EVENTS} is writable by uid {SAMPLE_UID} — uid boundary broken"
        )));
    }
    tracing::info!("uid-boundary self-check passed (nobody cannot write the feed)");

    // ── Fire the tripwire (monitor is ready), then run the sample ──────────
    // The open is EXPECTED to fail with EPERM (the LSM denies it); that recorded
    // denial is what lets a clean run earn a confident PASS. Run in the same
    // unprivileged scope the sample gets.
    let _ = run_as_nobody(&format!("cat {TRIPWIRE} >/dev/null 2>&1; true"));
    tracing::info!("fired deny-channel tripwire (expected EPERM on the tripwire path)");

    let sample_cmd = load_sample_command()?;
    tracing::info!("dropping privileges and launching the sample as a child");
    // Fork-and-reap (not exec): keep pid-1 alive so we can drain the observer
    // after the sample exits, before `main` takes the VM down. The sample never
    // receives the nonce env (it was only ever set on the observer's Command).
    // The sample's stdout is the console (debug) — the event feed is the file +
    // vsock, a separate channel, so there is nothing to corrupt.
    let mut sample = Command::new(DROPPRIV);
    sample
        .arg("/bin/sh")
        .arg("-c")
        .arg(&sample_cmd)
        .env("HOME", HONEYTOKEN_HOME)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut sample = sample
        .spawn()
        .map_err(|e| MainError::IO(e, "spawning the sample under droppriv"))?;
    let sample_pid = sample.id();
    tracing::info!(pid = sample_pid, "sample running as nobody");
    let sample_rc = sample
        .wait()
        .map_err(|e| MainError::IO(e, "reaping the sample"))?;
    tracing::info!(rc = ?sample_rc.code(), "sample exited");

    // ── Drain the observer: SIGTERM asks it to flush the ringbuf, bounded ──
    drain_monitor(&mut monitor, mon_pid).await;

    tracing::info!("detonation complete");
    Ok(())
}

/// Whether this process is the detonation microVM's init: the kernel runs the
/// initramfs `/init` (this binary) as pid-1. Both halves are load-bearing — it
/// gates `reboot(2)` via [`guest::shut_down_vm`], and `argv[0]` alone is
/// caller-controlled while pid-1 alone could be a container init. Mirrors
/// `minimald::is_minimal_microvm`.
fn is_detonation_init() -> bool {
    std::process::id() == 1
        && std::env::args_os().next().is_some_and(|a0| {
            std::path::Path::new(&a0).file_name() == Some(std::ffi::OsStr::new("init"))
        })
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        // Log to stderr; keep stdout free of daemon noise.
        .with(fmt::layer().with_ansi(false).with_writer(std::io::stderr))
        .with(filter)
        .init();
}

/// `mount(2)` a pseudo-filesystem, tolerating `EBUSY` (already mounted). Failures
/// are logged, not fatal — a missing bpffs just degrades coverage.
fn mount_fs(source: &str, target: &str, fstype: &str) {
    let _ = std::fs::create_dir_all(target);
    let (Ok(c_source), Ok(c_target), Ok(c_fstype)) = (
        CString::new(source),
        CString::new(target),
        CString::new(fstype),
    ) else {
        tracing::warn!(target, "invalid mount argument");
        return;
    };
    // SAFETY: `mount(2)` with valid, call-lifetime C strings for
    // source/target/fstype, no flags, and a null data pointer.
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBUSY) {
            tracing::warn!(target, fstype, error = %err, "mount failed (coverage may degrade)");
        }
    } else {
        tracing::info!(target, fstype, "mounted pseudo filesystem");
    }
}

/// Raise the locked-memory rlimit to unlimited for the BPF maps/ringbuf.
fn raise_memlock_rlimit() {
    let unlimited = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `setrlimit(2)` with a valid, fully-initialized rlimit pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not raise memlock rlimit");
    }
}

/// Create the deny-channel tripwire sentinel (world-readable) if it is not already
/// baked into the rootfs. Best-effort: on a read-only rootfs this is a no-op and
/// the verdict honestly caps at REVIEW.
fn stage_tripwire() {
    use std::os::unix::fs::PermissionsExt;
    if std::path::Path::new(TRIPWIRE).exists() {
        tracing::info!(path = TRIPWIRE, "deny-channel tripwire present");
        return;
    }
    match std::fs::File::create(TRIPWIRE) {
        Ok(f) => {
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o644));
            tracing::info!(path = TRIPWIRE, "staged deny-channel tripwire");
        }
        Err(e) => tracing::warn!(path = TRIPWIRE, error = %e, "could not stage tripwire (verdict will cap at REVIEW)"),
    }
}

fn nonce_file_path() -> String {
    std::env::var("DET_BINDING_NONCE_FILE").unwrap_or_else(|_| NONCE_FILE_DEFAULT.to_string())
}

/// Load the per-scan binding nonce, in precedence order: the `DET_BINDING_NONCE`
/// env (local-dev convenience) then the root-0400 file (the secure channel).
/// `None` means no nonce this run — the nonce gate is simply inactive.
fn load_binding_nonce() -> Option<String> {
    if let Ok(n) = std::env::var("DET_BINDING_NONCE") {
        if !n.is_empty() {
            tracing::info!("binding nonce supplied via environment for the root observer");
            return Some(n);
        }
    }
    let path = nonce_file_path();
    match std::fs::read_to_string(&path) {
        Ok(n) if !n.trim().is_empty() => {
            tracing::info!(from = %path, "loaded per-scan binding nonce for the root observer");
            Some(n.trim().to_string())
        }
        _ => {
            tracing::info!(tried = %path, "no binding nonce — nonce gate inactive this run");
            None
        }
    }
}

/// Load the exact sample command to detonate: `DET_SAMPLE_CMD` env (local dev)
/// then the host-staged file (verbatim).
fn load_sample_command() -> Result<String, MainError> {
    if let Ok(cmd) = std::env::var("DET_SAMPLE_CMD") {
        if !cmd.trim().is_empty() {
            return Ok(cmd);
        }
    }
    let path =
        std::env::var("DET_SAMPLE_FILE").unwrap_or_else(|_| SAMPLE_FILE_DEFAULT.to_string());
    let cmd = std::fs::read_to_string(&path).map_err(|e| MainError::IO(e, "reading the sample command file"))?;
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err(MainError::Other(format!(
            "sample command file {path} is empty; nothing to detonate"
        )));
    }
    Ok(cmd.to_string())
}

/// The first `nameserver` in `/etc/resolv.conf`, if any.
fn read_nameserver() -> Option<String> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("nameserver") {
            if let Some(ns) = it.next() {
                return Some(ns.to_string());
            }
        }
    }
    None
}

/// Repoint `/etc/resolv.conf` at the loopback collector (127.0.0.1). The rootfs is
/// read-only, so write to the `/run` tmpfs and bind-mount it over the target (the
/// same trick `minimald::guest::install_resolv_conf` uses for the gvproxy DNS).
fn install_local_resolver() -> std::io::Result<()> {
    std::fs::write("/run/det-resolv.conf", "nameserver 127.0.0.1\n")?;
    let src = c"/run/det-resolv.conf";
    let dst = c"/etc/resolv.conf";
    // SAFETY: bind-mount with valid C paths, MS_BIND, and no fs-type/data.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Run `sh -c <cmd>` as unprivileged `nobody` via `droppriv`, returning the exit
/// status. Falls back to a bare shell only if `droppriv` is absent (which would
/// itself be a rootfs-staging bug worth the loud path).
fn run_as_nobody(cmd: &str) -> std::io::Result<std::process::ExitStatus> {
    if std::path::Path::new(DROPPRIV).is_file() {
        Command::new(DROPPRIV)
            .arg("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .status()
    } else {
        tracing::warn!(path = DROPPRIV, "droppriv missing; running check without a uid drop");
        Command::new("/bin/sh").arg("-c").arg(cmd).status()
    }
}

/// Whether `nobody` can run `cmd` successfully (exit 0). Used by the security
/// self-checks: a `true` from `cat <nonce>` or `test -w <feed>` means the boundary
/// leaked and the run must not be trusted.
fn nobody_can(cmd: &str) -> bool {
    run_as_nobody(cmd)
        .map(|s| s.success())
        .unwrap_or(false)
}

/// SIGTERM the observer and wait (bounded) for it to drain the ringbuf + flush its
/// sink, then SIGKILL as a backstop so a wedged observer can never hang teardown.
async fn drain_monitor(monitor: &mut std::process::Child, mon_pid: u32) {
    // Already gone?
    if let Ok(Some(status)) = monitor.try_wait() {
        tracing::warn!(pid = mon_pid, ?status, "observer already exited before drain");
        return;
    }
    tracing::info!(pid = mon_pid, "signalling observer to drain and exit");
    // SAFETY: `kill(2)` with a signal number; no pointers. A stale pid at worst
    // signals nothing (ESRCH) — pid-1 reaps its own children so there is no
    // pid-reuse window here.
    unsafe {
        libc::kill(mon_pid as libc::pid_t, libc::SIGTERM);
    }
    for attempt in 0..DRAIN_ATTEMPTS {
        match monitor.try_wait() {
            Ok(Some(_)) => {
                tracing::info!("observer drained and exited");
                return;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "waiting on observer during drain");
                return;
            }
        }
        if attempt + 1 == DRAIN_ATTEMPTS {
            tracing::warn!(pid = mon_pid, "observer did not exit within 5s of SIGTERM; SIGKILL");
            let _ = monitor.kill();
            let _ = monitor.wait();
            return;
        }
        tokio::time::sleep(POLL).await;
    }
}
