//! `minvmd run` subcommand (R4.2).
//!
//! The foreground supervisor: resolves kernel + rootfs, manages lifecycle state
//! transitions (Stopped → Starting → Running → Stopped), spawns and supervises
//! the hidden `minvmd __krun-vmm` child, and waits for the guest `READY` marker
//! before reporting boot success.
//!
//! `--detach` mode: re-execs the supervisor as a background process (new
//! session via `setsid`) and returns only once the VM is serving (host UDS
//! connectable, alive lock held, lifecycle Running) or the configurable
//! timeout expires (R4.2).
//!
//! Without libkrun this subcommand bails immediately with a "no libkrun" error
//! so the stock Linux CI (which has no libkrun) stays green.

#[cfg(minvmd_libkrun)]
use std::time::Duration;

use anyhow::{Result, bail};
// `.context()` is only called from the libkrun-gated supervisor functions; on
// the stub build the trait is unused, so scope the import to match.
#[cfg(minvmd_libkrun)]
use anyhow::Context as _;

/// Default timeout in seconds for `run --detach` to wait for the host UDS.
pub const DEFAULT_DETACH_TIMEOUT_SECS: u64 = 8;

/// Run the `run` subcommand.
///
/// - `detach`: if true, spawn the supervisor in the background and poll until
///   the VM is serving (up to `timeout_secs`).
/// - `timeout_secs`: only meaningful under `--detach`; `None` when the flag was
///   omitted. Rejected without `--detach` rather than silently ignored;
///   defaults to [`DEFAULT_DETACH_TIMEOUT_SECS`] when detaching.
/// - `root`: this process's root span ([`crate::telemetry::root_span`]),
///   entered. A `--detach` caller holds it until it returns; the supervisor
///   ends it once the VM is ready, so it exports while the VM runs
///   (`telemetry::SupervisorStart`).
pub fn run(
    detach: bool,
    timeout_secs: Option<u64>,
    root: tracing::span::EnteredSpan,
) -> Result<()> {
    // `--timeout` only bounds the detach poll loop; foreground runs supervise
    // the VMM child for its whole life and never consult it. Accepting it in
    // foreground mode would silently ignore it, so reject the combination.
    if !detach && timeout_secs.is_some() {
        bail!("`--timeout` only applies with `--detach`");
    }
    let timeout_secs = timeout_secs.unwrap_or(DEFAULT_DETACH_TIMEOUT_SECS);

    // One line per VM start, naming the VM, its state directory (NET-052), and
    // the boot images + switch it resolved (NET-049/NET-051). Only the process
    // that will actually supervise the VM logs it: a `--detach` caller re-execs
    // `minvmd run` (without `--detach`) for the real start, so the line is
    // written once, by the process that owns the boot.
    //
    // When resolution fails the supervisor below fails on the same missing
    // images, so no VM boots — do not emit the resolved-images line with empty
    // paths (it would name nothing while claiming a start). The start record
    // still exists, at WARN, carrying the reason instead.
    if !detach {
        let switch = crate::image::resolve_gvproxy_path();
        let switch_str = if switch.exists() {
            switch.display().to_string()
        } else {
            "not found".to_string()
        };
        match crate::image::resolve_boot_images() {
            Ok((kernel, rootfs, initramfs)) => tracing::info!(
                vm = %crate::state::vm_name(),
                state_dir = %crate::state::provider_dir().display(),
                kernel = %kernel.display(),
                rootfs = %rootfs.display(),
                initramfs = %initramfs.display(),
                switch = %switch_str,
                "starting VM"
            ),
            Err(e) => tracing::warn!(
                vm = %crate::state::vm_name(),
                state_dir = %crate::state::provider_dir().display(),
                switch = %switch_str,
                error = %e,
                "starting VM with unresolved boot images"
            ),
        }
    }

    #[cfg(minvmd_libkrun)]
    return run_supervisor(detach, timeout_secs, root);

    #[cfg(not(minvmd_libkrun))]
    {
        let _ = (detach, timeout_secs);
        drop(root);
        bail!("`minvmd run` requires libkrun (macOS, or Linux with libkrun installed)");
    }
}

/// Reap a stale gvproxy left by a killed supervisor before the node proxy
/// port is drawn, and hand the resolved pair to the spawn block.
///
/// A SIGKILLed or aborted supervisor leaves its gvproxy alive — the pidfd
/// stop paths are clean-stop-only and gvproxy holds no alive lock — and the
/// leftover keeps the hostname proxy's default port bound. Reaping only
/// after the draw (at the gvproxy spawn, as before) is too late: the draw
/// sees the default port refused and hands the proxy an ephemeral one.
///
/// Runs only when a gvproxy binary is installed; the reaper's match is
/// exact argv tokens — argv[0] is the gvproxy binary and `-listen` names
/// this VM's switch socket. The supervisor's alive lock (held by the time
/// this is called) rules out a live same-instance supervisor, so a match
/// owned by a live minvmd fails the start rather than spawning a duplicate
/// switch. The caller is the synchronous supervisor thread, not a tokio
/// worker, so the reap's bounded wait may block it.
///
/// The socket dir and stale-socket cleanup stay at the spawn block, next
/// to the bind they guard; the resolved pair is returned so the spawn
/// block does not resolve twice.
#[cfg(minvmd_libkrun)]
fn reap_stale_gvproxy_before_port_draw() -> Result<(std::path::PathBuf, Option<std::path::PathBuf>)>
{
    let binary = crate::image::resolve_gvproxy_path();
    if !binary.exists() {
        return Ok((binary, None));
    }
    let switch_sock = crate::net::resolve_switch_sock().context("resolving switch socket")?;
    crate::net::reap_stale_gvproxy(&binary, &switch_sock).context("reaping a stale gvproxy")?;
    Ok((binary, Some(switch_sock)))
}

#[cfg(minvmd_libkrun)]
fn run_supervisor(detach: bool, timeout_secs: u64, root: tracing::span::EnteredSpan) -> Result<()> {
    // Adopt any pre-split `providers/local-<N>` dir into the kind-tagged scheme
    // before resolving our own `local-minvmd0` dir, so an upgraded host reuses
    // its existing VM state (data volume, boot log) instead of orphaning it.
    paths::migrate_legacy_provider_dirs(&crate::state::state_base_dir());

    // R2.4: fail fast with an actionable error if the hypervisor backend is
    // unavailable (Linux: /dev/kvm). No-op on macOS. Runs in the foreground
    // caller so the user sees the error directly, even under --detach.
    crate::cmd::ensure_hypervisor_accessible()?;
    // Likewise the sun_path limit: libkrun aborts on an over-long UDS path
    // deep in the VMM child; catch it here with a clear error instead. The
    // egress gate's socket (NET-081) is bridged by the same mechanism the
    // switch socket is, so it carries the same limit.
    crate::sock::check_uds_path_len(&crate::sock::resolve_uds_path()?)?;
    crate::sock::check_uds_path_len(&crate::net::resolve_switch_sock()?)?;
    crate::sock::check_uds_path_len(&crate::net::resolve_gate_sock()?)?;

    if detach {
        // The caller's root covers its whole wait: the hand-off ends when this
        // returns, with the VM serving or the wait failed.
        let result = run_detach(timeout_secs);
        drop(root);
        return result;
    }
    // A supervisor stopped by SIGTERM/SIGINT returns here once its teardown
    // (the `Stopped` write, the guards' drops) has run; `main` then ends the
    // process by that signal after flushing its telemetry and its log
    // ([`crate::control::die_by_received_stop_signal`]), so its exit status
    // still says what stopped it.
    run_foreground(root)
}

/// Outcome of one poll of the `--detach` readiness loop, decided from the
/// three observable signals in [`run_detach`]. Split out from the loop so the
/// decision is unit-testable on hosts without libkrun, where the loop itself
/// is not compiled.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
enum DetachPoll {
    /// The readiness predicate holds: the VM is serving. Return success.
    Ready,
    /// Neither ready nor failed yet: sleep and poll again until the deadline.
    Keep,
    /// The supervisor child exited with no daemon up: a real startup failure.
    Failed(std::process::ExitStatus),
    /// The supervisor child exited but a leaked `__krun-vmm` still holds the
    /// alive lock. The pid is the orphaned VMM process.
    LeakedVmm(u32),
}

/// Classify one readiness poll. `ready` is the readiness predicate (UDS
/// connectable, alive lock held, lifecycle `Running`); `child_status` is the
/// supervisor child's exit status once it has exited; `daemon_alive` is whether
/// some minvmd holds the alive lock; `vmm_pid` is the VMM pid the supervisor
/// recorded in state before it exited (if any); `vmm_owned_by_live_supervisor`
/// is whether that VMM's parent is still a live supervisor (i.e. the VMM
/// belongs to a competing supervisor, not to the exited child).
///
/// A child that exits while a daemon still holds the alive lock lost the
/// autospawn race: `try_acquire_alive_lock` handed the lock to a peer that is
/// still coming up and will reach `Running` shortly. That is success in the
/// making, not a startup failure — keep waiting to the deadline. Only a child
/// exit with no live daemon is a genuine failure.
///
/// When the child exited and the lock is still held, the holder could also be
/// an orphaned `__krun-vmm` that inherited the lock from a dead supervisor. If
/// the recorded VMM pid is still alive and is *not* owned by a live supervisor,
/// the VMM is leaked — fail fast rather than waiting for the full spawn
/// timeout. A live VMM owned by a live supervisor is a competing supervisor's
/// VMM, not a leak.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn classify_detach_poll(
    ready: bool,
    child_status: Option<std::process::ExitStatus>,
    daemon_alive: bool,
    vmm_pid: Option<u32>,
    vmm_owned_by_live_supervisor: bool,
) -> DetachPoll {
    if ready {
        return DetachPoll::Ready;
    }
    match child_status {
        Some(status) if !daemon_alive => DetachPoll::Failed(status),
        Some(_status) if daemon_alive => {
            // The supervisor exited but the alive lock is still held. If the
            // supervisor recorded a VMM pid and that pid is still running, the
            // VMM is orphaned — fail fast instead of waiting for the timeout.
            // A VMM whose parent is still a live supervisor belongs to a
            // competing supervisor that won the autospawn race, so it is not
            // a leak.
            if let Some(pid) = vmm_pid {
                // SAFETY: kill(pid, 0) probes for process existence without
                // delivering a signal.
                if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
                    && !vmm_owned_by_live_supervisor
                {
                    return DetachPoll::LeakedVmm(pid);
                }
            }
            DetachPoll::Keep
        }
        _ => DetachPoll::Keep,
    }
}

/// Whether `pid`'s parent is a live process other than init (pid 1).
///
/// A `__krun-vmm` child is reparented to init the moment its supervisor dies,
/// so a live parent other than init means the VMM is still owned by a live
/// supervisor — a competing supervisor's VMM, not a leak.
///
/// On macOS `/proc/<pid>/stat` does not exist; we read the parent pid via
/// `proc_pidinfo(PROC_PIDTBSDINFO)` / `proc_bsdinfo` instead. When the parent
/// pid cannot be determined, we conservatively treat the VMM as owned (return
/// `true`) so the poll loop keeps waiting rather than misclassifying a healthy
/// booting VMM as leaked.
#[cfg(minvmd_libkrun)]
fn vmm_owned_by_live_supervisor(pid: u32) -> bool {
    let ppid = parent_pid(pid);
    let Some(ppid) = ppid else {
        // Cannot determine ownership: treat as owned so we keep waiting.
        return true;
    };
    // SAFETY: kill(pid, 0) probes for process existence without delivering a
    // signal.
    ppid != 1 && unsafe { libc::kill(ppid as libc::pid_t, 0) } == 0
}

/// Read the parent pid of `pid`. Returns `None` when the lookup fails.
#[cfg(all(minvmd_libkrun, target_os = "macos"))]
fn parent_pid(pid: u32) -> Option<u32> {
    // SAFETY: the proc_bsdinfo buffer is stack-allocated and correctly sized;
    // proc_pidinfo reads process info for the given pid into it.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if ret <= 0 {
        return None;
    }
    Some(info.pbi_ppid)
}

/// Read the parent pid of `pid` from `/proc/<pid>/stat`.
#[cfg(all(minvmd_libkrun, not(target_os = "macos")))]
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is the parenthesised process name and can itself contain spaces
    // and ')' — split on the last ')' so the fields after it are stable. The
    // first field after comm is `state`; the second is `ppid`.
    let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest).unwrap_or("");
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next();
    fields.next().and_then(|s| s.parse::<u32>().ok())
}

/// Spawn `minvmd run` as a detached background supervisor, then poll until
/// the VM is serving (up to `timeout_secs`).
#[cfg(minvmd_libkrun)]
fn run_detach(timeout_secs: u64) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("run");
    // Forward the state-dir override and VM name so the re-exec'd supervisor
    // resolves the same per-VM state dir this process did.
    crate::state::forward_identity(&mut cmd);
    // And the trace: the supervisor's spans are children of this `run`.
    crate::telemetry::forward_trace(&mut cmd);
    // Mark the child as detached so it routes tracing to the daily-rotated
    // log file (`<state>/logs/minvmd.log`) instead of stdout.
    cmd.env(crate::DETACHED_ENV, "1");
    // The supervisor's stderr goes to a log file, not /dev/null: it carries
    // the boot-failure diagnosis (the guest's mount-failure reason, image
    // disposition, repair guidance), and the failure messages below point at
    // it. Truncated per attempt so it holds exactly this boot's story.
    let state_dir = crate::state::StateDir::new(crate::state::StateDir::default_path())
        .context("opening state dir")?;
    let log_path = state_dir.dir().join("run.log");
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("creating supervisor log at {}", log_path.display()))?;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(log));

    // SAFETY: setsid() is async-signal-safe. In the child, it creates a new
    // session so the supervisor is detached from the caller's controlling
    // terminal and not affected by SIGHUP when the shell exits.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning background run supervisor: {}", exe.display()))?;

    // Ready = UDS connectable AND a minvmd holds the alive lock AND lifecycle
    // is Running. The socket alone is not proof: ssh.sock is shared with
    // native minimald (a live peer backend would satisfy a bare connect while
    // our child's mutual-exclusion bail goes to /dev/null), and libkrun binds
    // it at VMM start — long before the guest serves — dialling the guest
    // vsock lazily per connection, so an early connect succeeds and then
    // drops at ssh time. Running is written only after the guest's READY
    // marker, which follows its vsock bind. A child exit with no live daemon
    // surfaces as an error rather than a silent timeout; a child that lost the
    // autospawn race to a live peer keeps waiting for that peer to serve.
    let uds_path = crate::sock::resolve_uds_path().context("resolving host UDS path")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let child_status = child.try_wait().context("polling supervisor child")?;
        let daemon_alive = state_dir.daemon_alive().context("probing alive lock")?;
        let state = state_dir.read_state().context("reading state")?;
        let ready = daemon_alive
            && std::os::unix::net::UnixStream::connect(&uds_path).is_ok()
            && state.lifecycle == crate::lifecycle::Lifecycle::Running;
        let vmm_owned = state.vmm_pid.is_some_and(vmm_owned_by_live_supervisor);
        match classify_detach_poll(ready, child_status, daemon_alive, state.vmm_pid, vmm_owned) {
            DetachPoll::Ready => return Ok(()),
            DetachPoll::Failed(status) => {
                // A start that failed on the hostname proxy's port says so
                // inline — port, holder and why (T93) — so the CLI's
                // autospawn error carries it, not just a log path.
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                if let Some(line) = proxy_failure_line(&log) {
                    bail!("{line} (supervisor log: {})", log_path.display());
                }
                bail!(
                    "the detached supervisor exited during startup ({status}); \
                     see {} for its error output",
                    log_path.display()
                )
            }
            DetachPoll::LeakedVmm(pid) => bail!(
                "the supervisor exited but a leaked __krun-vmm (pid {pid}) still holds the \
                 alive lock; run `min stop` (or `kill -9 {pid}`), then retry"
            ),
            DetachPoll::Keep => {}
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out after {timeout_secs}s waiting for minvmd to become ready on {} \
                 (supervisor log: {})",
                uds_path.display(),
                log_path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The supervisor's box registry: it feeds the proxy attachments, compiles
/// under the operator's deny-all opt-out, persists to `registry_file`, and
/// sends a live box's revocation to the Box Egress Proxy control socket under
/// the home directory (BEP-043). Only this start path sets that socket.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn supervisor_registry(
    proxy_attachments: crate::bep_attach::Attachments,
    egress_deny_all_opt_out: bool,
    registry_file: std::path::PathBuf,
) -> crate::box_registry::BoxRegistry {
    crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET)
        .feeding_proxy_attachments(proxy_attachments)
        .with_egress_deny_all_opt_out(egress_deny_all_opt_out)
        .with_proxy_control(crate::box_registry::home_proxy_control())
        .persisting_to(registry_file)
}

/// Foreground supervisor: boot the VM, manage lifecycle state, supervise until
/// the VMM child exits.
///
/// `root` (the process's root span, entered) and the `supervisor.start` span
/// under it end once the VM is ready; the rest of the VM's life runs under a
/// `supervisor.serve` root linked to them (`telemetry::SupervisorStart`).
#[cfg(minvmd_libkrun)]
fn run_foreground(root: tracing::span::EnteredSpan) -> Result<()> {
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use minimald_rpc::ProxyDownCause;

    use crate::cmd::MARKER_SOCK_ENV;
    use crate::image::resolve_boot_images;
    use crate::lifecycle::{Action, Lifecycle, next_state};
    use crate::net::answerer::DEFAULT_ANSWERER_PORT;
    use crate::state::{StartingGuard, State, StateDir};

    // One span per supervisor phase, like minimald's per-connection `conn`
    // span: every record the supervisor emits carries `vm`, so a detached
    // supervisor's lines in the shared log (`<state>/logs/minvmd.log`, common
    // to every VM on the host) stay attributable once a second VM runs —
    // grep instead of manual fields on each line. This one, `supervisor.start`,
    // is the parent of the switch start and of `vm.boot` (and so of the guest's
    // `guest.ready`), and ends with the process root at READY below.
    let start_phase = crate::telemetry::SupervisorStart::enter(root);

    // Fail-fast: resolve paths before touching lifecycle state.
    // (UDS path lengths were already checked in `run_supervisor`.)
    let (_kernel, _rootfs, _initramfs) =
        resolve_boot_images().context("resolving boot image paths")?;

    let state_dir = StateDir::new(StateDir::default_path()).context("opening state dir")?;

    // ── Phase 1: Stopped → Starting (under lock) ───────────────────────────
    // The alive lock outlives the block: held for the whole supervisor life
    // and inherited by the VMM child, so observers can tell a live daemon/VM
    // from stale state.
    let alive_lock;
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;

        alive_lock = match state_dir
            .try_acquire_alive_lock()
            .context("acquiring alive lock")?
        {
            Some(l) => l,
            None => match state.lifecycle {
                Lifecycle::Running => {
                    bail!("minvmd is already running (vmm_pid={:?})", state.vmm_pid)
                }
                Lifecycle::Starting => bail!("minvmd is already starting"),
                Lifecycle::Stopping => {
                    bail!("minvmd is stopping; wait for it to finish before restarting")
                }
                _ => bail!("another minvmd (a `boot` VM?) holds the alive lock"),
            },
        };

        // Both backends bind the same ssh.sock; don't steal a live native
        // daemon's socket.
        if state_dir
            .minimald_alive()
            .context("probing native minimald lock")?
        {
            bail!("a native minimald is serving this instance's socket; stop it first");
        }

        // The state machine only permits Start from Stopped: provision a
        // clean install, and reclaim (via Fail) active state left behind by a
        // dead daemon — we hold the alive lock, so nothing live wrote it.
        let base = match state.lifecycle {
            Lifecycle::NotProvisioned => {
                next_state(Lifecycle::NotProvisioned, Action::Provision)
                    .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?
            }
            stale if stale.is_active() => {
                tracing::warn!(?stale, "reclaiming state left by a dead daemon");
                next_state(stale, Action::Fail)
                    .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?
            }
            other => other,
        };
        let starting = next_state(base, Action::Start)
            .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?;
        state_dir
            .write_state(&State {
                lifecycle: starting,
                ..State::stopped()
            })
            .context("writing Starting state")?;
    }

    // StartingGuard: resets lifecycle to Stopped on drop if we bail before
    // committing (R4.6). Holds no lock so concurrent readers observe the
    // transient Starting state without contention.
    let guard = StartingGuard::new(state_dir.dir().to_path_buf());

    // ── Boot sequence ────────────────────────────────────────────────────────
    let nonce: u32 = {
        let mut buf = [0u8; 4];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .context("reading /dev/urandom for marker socket nonce")?;
        u32::from_le_bytes(buf)
    };
    let marker_sock_path = PathBuf::from(format!(
        "/tmp/minvmd-marker-{}-{nonce:08x}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker_sock_path);

    let listener =
        UnixListener::bind(&marker_sock_path).context("binding READY-marker unix socket")?;
    listener
        .set_nonblocking(false)
        .context("setting listener to blocking")?;

    // The host-side table of published namespaces (NET-138): the rows the
    // egress gate (NET-081) decides every frame leaving the VM by, filled in
    // this process on the host — never from anything the guest says. Held for
    // the supervisor's lifetime as the registration surface (the client-driven
    // path is a later task); published here with the one row the host itself
    // can name: the guest node's own namespace, the daemon's root-netns tap,
    // whose reach is the allow-all interim until the node-plane baseline set is
    // enumerated (NET-130). Its address is this host's derivation from the
    // registry's subnet, and the switch is configured with that same subnet
    // below — one value handed to both, so the row's lease and the switch's
    // address plan cannot drift apart. The daemon therefore keeps the egress
    // it had before the gate existed, its own package fetches above all.
    //
    // An own-address box's row is not one this process names on its own:
    // the activating client registers the box over the control socket below
    // (T66, #1711), and the registry hands out its switch address, so the
    // row stands before the box's first frame. A frame from an address no
    // row holds is dropped, unconditionally (NET-085), and the egress
    // default is in force (`UNREGISTERED_SOURCE_PHASE`, egress_gate): a row
    // with no egress section reaches nothing outside itself, unless the
    // operator set `MINVMD_EGRESS_DENY_ALL_OPT_OUT` when this process
    // started (NET-077), and a publish at an address no row holds is
    // refused.
    //
    // The proxy's attachment table (NET-133): one attachment per box, held
    // by this process for the VM's life. The registry is its one writer —
    // every box row it publishes is an attachment issued ahead of the row,
    // so the proxy holds the box before its first connection could arrive,
    // and every retirement takes the attachment with it — and the stand-in
    // acceptor below is handed the same table, so a delivered connection is
    // attributed only to a live box it holds an attachment for. Issued and
    // withdrawn for every boot, whatever binds at the proxy's socket: the
    // table and its one line per attachment are the host's own state, ready
    // for the acceptor that reads them.
    let proxy_attachments = crate::bep_attach::Attachments::new();
    // The operator's deny-all opt-out (NET-077), read once here as the VMM
    // child reads it for the boot line: the registry compiles a client box
    // with no `egress` section by it, so the host gate keeps the default the
    // guest daemon was handed.
    let egress_deny_all_opt_out = crate::vm::egress_deny_all_opt_out_from_env();
    tracing::info!(
        egress_deny_all_opt_out,
        "host-side egress default opt-out for undeclared boxes"
    );
    // The client boxes' registrations persist in this VM's state dir
    // (NET-138): a supervisor restarted under a session's live box reloads
    // its row detached, for the box to attach again or its creator to
    // resume inside the grace — never from anything the guest reports.
    let boxes = supervisor_registry(
        proxy_attachments.clone(),
        egress_deny_all_opt_out,
        state_dir.dir().join(crate::box_registry::REGISTRY_FILE),
    );
    // The node's own proxy port is resolved once before the VM boots — the
    // operator's override (`MINVMD_NODE_PROXY_PORT` in this supervisor's env)
    // or the default-first probe, so a VM sharing a host with a native daemon
    // still lands on the default proxy port when it is free — and the one
    // resolved port is written twice: handed to the guest through the VMM
    // child's env onto the kernel command line, and declared as the node
    // row's own publish. The daemon's setup publishes it at its address
    // (NET-025); the port it publishes is the port the guest binds. The
    // assignment owns the port's host-wide reservation for this VM's life
    // (T93): two supervisors booting at the same moment contend for it in
    // the kernel, and the kernel releases it when this supervisor stops,
    // exits or crashes — never a pid file, never a stale entry to clean.
    let ports_dir = node_ports_dir().context("opening the node-port reservation directory")?;
    // A stale gvproxy from a killed supervisor still holds the hostname
    // proxy's default port bound, so the reaper runs before the port draw:
    // drawing first would hand the proxy an ephemeral port for no reason.
    // The reaper's own guard still fails the start when the matching
    // gvproxy belongs to a live minvmd.
    let (gvproxy_binary, switch_sock) = reap_stale_gvproxy_before_port_draw()?;
    let mut node_port =
        assign_node_proxy_port(&ports_dir).context("assigning the node's proxy port")?;
    boxes
        .try_register_node_namespace(node_port.port)
        .context("publishing the node namespace's row")?;
    // SIGTERM or SIGINT sent to the supervisor (a service manager's stop,
    // or kill(1)) cancels and audits every pending ask (NET-045), then
    // stops the VM the same way `minvmd stop` does: the guest gets the
    // Shutdown RPC so the data volume's ext4 journal stays clean (informed
    // by #705), the VMM child is signalled and reaped, and the main
    // thread's own teardown writes the `Stopped` state, then `main` ends
    // the process by the signal. The whole stop is bounded at
    // `SIGNAL_STOP_BOUND` from the signal's arrival; when it cannot run,
    // fails, or the teardown overruns that deadline, the watcher dies by
    // the signal itself. A second signal meanwhile ends the process at
    // once. A signal during the boot, before `Running`, aborts the boot:
    // the VMM child is signalled without a guest ask (no guest daemon is
    // up to take one), the watcher writes `Stopped`, and it ends the
    // process by the signal, since the main thread is still in its READY
    // wait. It keeps the lifecycle write lock from that write on, and the
    // boot forks only under that lock, so no VMM is forked behind it.
    //
    // Not covered: a terminal Ctrl-C on a foreground run. The VMM child
    // shares the terminal's foreground process group, so the tty delivers
    // SIGINT to it directly, at the same moment as to the supervisor, and
    // the VMM dies before the Shutdown RPC can run; the journal replay
    // backstop bounds that case, as before. Nor is a SIGKILL of the
    // supervisor: the orphaned VMM keeps the alive lock it inherited, so
    // the VM still reads as live, and `min stop --force` is the recovery.
    let signal_state_dir = state_dir.dir().to_path_buf();
    if let Err(error) = crate::control::watch_stop_signals(boxes.clone(), move |signum| {
        let deadline = crate::control::stop_signal_received()
            .map_or_else(std::time::Instant::now, |(_, at)| at)
            + crate::cmd::stop::SIGNAL_STOP_BOUND;
        match crate::cmd::stop::graceful_stop_from_signal(signal_state_dir, deadline) {
            Ok(crate::cmd::stop::SignalStop::TeardownFinished) => {
                // The main thread normally ends the process by the signal
                // once its teardown returns; this is the backstop.
                tracing::info!(signum, "graceful stop after signal complete");
                std::thread::sleep(deadline.saturating_duration_since(std::time::Instant::now()));
                crate::control::die_by_signal(signum);
            }
            Ok(crate::cmd::stop::SignalStop::BootAborted) => {
                // The main thread is still waiting for READY and would not
                // return before the deadline, so the watcher ends the
                // process.
                tracing::info!(signum, "boot aborted after signal; dying by signal");
                crate::control::die_by_signal(signum);
            }
            Err(e) => {
                tracing::warn!(signum, error = %e, "graceful stop after signal failed; dying by signal");
                crate::control::die_by_signal(signum);
            }
        }
    }) {
        tracing::warn!(%error, "could not install the stop-signal handler");
    }

    // The answerer's state — the host fact the CLI surfaces at session
    // start and on `min ls` — created here so both halves that move it can
    // share it: the acquisition loop writes it at every pass (holder,
    // registered, or a port held by a process with no channel), and the
    // control socket below reads it for the read-only status verb. Starting
    // is its pre-acquisition value, and the CLI treats it as "nothing to
    // say yet" rather than a verdict.
    let answerer_status = crate::net::answerer::AnswererStatus::starting();
    // A box's row goes with its shuttle connection: the gate reports which
    // addresses each relay carried at the relay's end, and this drainer thread
    // detaches those rows and withdraws them once their grace passes with no
    // relay carrying them again, for the life of the process (NET-133,
    // NET-138). Each
    // withdrawal hands the box's published address back to the machine's
    // answerer, as the creator's withdrawal does, unless a live row or a
    // registration in flight under the name owns it — so a session ended
    // daemon-side frees its address rather than holding it until this
    // process exits.
    let drainer_answerer = answerer_status.clone();
    boxes.spawn_withdrawal_drainer(move |name| drainer_answerer.release_address(name));
    // The hostname proxy's publish state (T93): the cell the supervisor
    // writes a failed start's cause into and the control socket below
    // serves, so the CLI's surfaces read *why* the proxy is not serving
    // from the host side — the same host-side argument the answerer's read
    // already makes.
    let proxy_publish = crate::control::ProxyPublishStatus::new();

    // The host-side door to the box table (T66): the control socket the
    // activating client registers an own-address box on, reads its
    // allocated switch and loopback addresses from, and asks for the
    // answerer's state — the read that never goes through the in-VM
    // daemon, because a guest relaying a host fact is forgeable from
    // inside the escape boundary — and the guest report door's bridge pair
    // beside it (T94, NET-138). Both are bound before the guest boots, so a
    // session activated against this VM can only ever be handed an address
    // this table holds. A bind failure of either is fatal (#1790): with no
    // control socket no own-address box can register, and the gate admits
    // no unregistered source, so a VM booted without it would run boxes
    // that reach nothing — the supervisor exits naming the socket instead.
    let (_control, guest_report_door) = bind_box_doors(
        &crate::control::resolve_control_sock()
            .context("resolving the box-registration control socket's path")?,
        &boxes,
        &answerer_status,
        &proxy_publish,
    )?;

    // The guest telemetry door (TEL-034): bound only with telemetry on,
    // and handed to the VMM child the same way, so the guest daemon's
    // records reach this process's exporter and spool over the vsock
    // bridge and the guest needs no endpoint. Best-effort like the doors
    // above: a bind failure is warned and the VM boots without it, and the
    // guest then spools alone (TEL-046).
    let guest_telemetry_door = if mlog::otel::telemetry_enabled() {
        crate::control::resolve_control_sock()
            .and_then(|sock_path| crate::guest_telemetry::spawn_guest_telemetry_door(&sock_path))
            .inspect_err(|error| {
                tracing::warn!(
                    %error,
                    "failed to bind the guest telemetry door; the guest daemon's telemetry \
                     stays in the guest's own spool"
                );
            })
            .ok()
    } else {
        None
    };

    // The host answerer (NET-138): the box zone's answerer on the host
    // loopback, answering from this host-authored table — the same
    // semantics the native daemon's answerer gives, over the same shared
    // decision — so the in-VM daemon starts no answerer of its own and the
    // host's resolver has one answerer to be pointed at. The answerer is the
    // machine's, not this VM's, and the channel decides who holds it: this
    // daemon connects to the answerer channel first and publishes its rows
    // there — to the installed host service when the privileged step put one
    // in, or to another VM host daemon holding the port as the recorded
    // single-operator interim — and hosts the answerer itself only when no
    // channel socket exists and the hook port is free, never both, so a
    // second VM's boxes answer too and the installed service, when there is
    // one, is the one answerer the machine runs. Started beside the switch,
    // before the guest boots, so the node row the registration above
    // published answers from the moment the VM does — best-effort at
    // startup, unlike the control socket: a thread that could not spawn is
    // warned and the VM still boots, its names then answering from whatever
    // answerer holds the port.
    if let Err(error) =
        crate::net::answerer::spawn(boxes.clone(), DEFAULT_ANSWERER_PORT, answerer_status)
    {
        tracing::warn!(
            %error,
            "failed to start the zone answerer; this VM's box names answer only from \
             another VM host daemon's table, if one is running"
        );
    }

    // The zone-table dump this daemon's diagnostics carry
    // (`providers/local-minvmd0[/<vm>/]/zone.json`): the same view the
    // answerer answers from, written at start and on every change, so a
    // diagnostic bundle holds the table the answers were given by. Warned
    // and booted without, like the answerer above: a missing diagnostic
    // never fails a VM.
    if let Err(error) = crate::diag::spawn(boxes.clone()) {
        tracing::warn!(
            %error,
            "failed to start the zone-table dump; a diagnostic bundle carries no \
             box-zone table for this VM"
        );
    }

    // Spawn + supervise the host gvproxy switch before the VMM child boots, so
    // its `-listen` switch socket exists when the gate relays into it for the
    // guest shuttle. The switch runtime starts the gate on the socket beside
    // the switch socket — the one libkrun bridges the shuttle's vsock port to
    // — before reporting ready, so the guest that boots next can only reach
    // the switch through it, decided per source address against `boxes`.
    // The guest's root netns (the daemon) attaches a primary tap for egress,
    // and own-IP PTasks attach further taps; both are L2 clients on this one
    // switch, both through the gate. The handle lives for the VM's lifetime
    // and stops gvproxy on drop (after the VMM child exits below), taking the
    // gate with it.
    //
    // Best-effort: when the gvproxy binary is absent (e.g. the boot/session e2e
    // lanes that exercise only the vsock bridge) we warn and boot without
    // egress rather than failing the VM — the daemon then has no network, the
    // pre-existing behaviour.
    // The reaper above decided whether the binary is installed: a switch
    // socket comes back only when it is, so the decision is made once.
    // The Box Egress Proxy's process, when this boot started one. Declared
    // before the switch so the switch drops first: no delivery is in
    // flight when the proxy is stopped.
    let mut _bep_proxy: Option<BepProxy> = None;
    let _gvproxy = match (gvproxy_binary, switch_sock) {
        (binary, Some(switch_sock)) => {
            crate::sock::prepare_socket_dir(&switch_sock).context("preparing switch socket dir")?;
            // The stale gvproxy of a killed supervisor was reaped above,
            // before the node proxy port was drawn, so it can no longer
            // hold the hostname proxy's default port; this block only
            // clears the sockets it left behind. The reaper's argv match
            // and live-minvmd guard are the reaper's own (above).
            crate::sock::remove_stale_socket(&switch_sock)
                .context("removing stale switch socket")?;
            // The gate binds the socket beside the switch socket, so a stale
            // file from a prior run must go or the bind fails EEXIST — the
            // same discipline the switch socket gets.
            let gate_sock =
                crate::net::resolve_gate_sock().context("resolving egress gate socket")?;
            crate::sock::remove_stale_socket(&gate_sock)
                .context("removing stale egress gate socket")?;
            // ── The Box Egress Proxy's delivery wiring (NET-132) ─────────────
            // One token per boot, minted like the marker nonce above: the
            // proof a delivered connection belongs to this boot, written
            // ahead of every delivery's header. The peer receives it
            // in-process, in the wire below; the stand-in acceptor — a
            // test/e2e surface, never a production one — receives the same
            // bytes over its start-up channel, so a same-uid host process
            // that finds the socket's path can never hold the token too.
            let token: [u8; switch::bep_host::TOKEN_LEN] = {
                let mut buf = [0u8; switch::bep_host::TOKEN_LEN];
                std::fs::File::open("/dev/urandom")
                    .and_then(|mut f| f.read_exact(&mut buf))
                    .context("reading /dev/urandom for the box egress proxy token")?;
                buf
            };
            // The proxy's unix socket, named beside the switch and gate
            // sockets the same way: the one path every delivered flow dials.
            // On a production boot `bep serve` listens there (below). When
            // nothing does, nothing binds the pool either (`bep_box_source`
            // below), so a box's connection to the proxy's address is
            // reset, the acceptor-down answer the pool is specified to give.
            let proxy_sock = switch_sock.with_file_name("gvproxy-bep.sock");
            // MINVMD_BEP_STUB is the e2e lane's flag and nothing else's: it
            // is what puts a stand-in acceptor at the path the wire names,
            // so the lane can read what a delivery presents — and the bind
            // below is what decides, through the handle it leaves, whether
            // the pool is partitioned by the table's box rows at all. The
            // handle is underscore-bound: its serving thread owns the
            // socket and outlives this block for the daemon's life, and
            // the supervisor has nothing further to ask of it.
            let stub_enabled = std::env::var_os("MINVMD_BEP_STUB").is_some();
            let _bep_stub = if stub_enabled {
                let (start_tx, start_rx) = std::sync::mpsc::channel();
                match crate::net::bep_stub::spawn(proxy_sock.clone(), start_rx) {
                    Ok(stub) => {
                        let _ = start_tx.send(crate::net::bep_stub::StubStart {
                            token,
                            daemon_pid: std::process::id(),
                            attachments: proxy_attachments.clone(),
                        });
                        tracing::info!(
                            sock = %proxy_sock.display(),
                            "box egress proxy stand-in acceptor up (test/e2e surface)"
                        );
                        Some(stub)
                    }
                    Err(error) => {
                        // Fail the boot, the same argument the
                        // switch-spawn failure beside this block makes: a
                        // boot under the flag exists to be probed through
                        // the stand-in, and a boot without one leaves the
                        // lane waiting on a socket that never comes —
                        // every probe below it failing in terms of an
                        // acceptor that was never there. The bind happens
                        // on the calling thread precisely so this is where
                        // its failure surfaces.
                        return Err(error)
                            .context("binding the box egress proxy stand-in acceptor");
                    }
                }
            } else {
                None
            };
            // ── The Box Egress Proxy itself (BEP-015) ───────────────────────
            // A production boot starts `bep serve` on the socket the wire
            // names, with this boot's token on its standard input: the
            // proxy is the acceptor, and the token reaches no file and no
            // argv. The stand-in replaces it under its flag, so the two
            // never contend for the path. `bep` keeps its keys in the macOS
            // Keychain and runs nowhere else, so another host starts
            // nothing. Best-effort, like a missing gvproxy: a boot without
            // the proxy still runs boxes, without a credentialed lane.
            if !stub_enabled && cfg!(target_os = "macos") {
                _bep_proxy = start_bep_proxy(&proxy_sock, &token);
            }
            // The wire the peer carries: the acceptor's socket, this boot's
            // token, and the per-source cap that is each registered box's
            // share of the pool. The default cap is the recorded working
            // value (spec NET-132), named here so the two cannot drift.
            let wire = switch::bep_host::BepWire::new(proxy_sock, token)
                .with_per_source_cap(switch::bep_host::DEFAULT_PER_SOURCE_CAP);
            match crate::net::HostGvproxy::spawn(
                binary,
                switch_sock,
                crate::net::DEFAULT_DATAPATH_CHECK_INTERVAL,
                &boxes,
                wire,
                bep_box_source(
                    // The stand-in binds before it returns, so it listens
                    // for the boot's life. The proxy listens only once its
                    // watcher sees its socket, and stops with its exit.
                    if _bep_stub.is_some() {
                        Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                            true,
                        )))
                    } else {
                        _bep_proxy.as_ref().map(BepProxy::listening)
                    },
                    boxes.table(),
                    proxy_attachments.clone(),
                ),
            ) {
                Ok(gvproxy) => {
                    let subnet = boxes.subnet();
                    tracing::info!(
                        pid = gvproxy.pid(),
                        proxy_ip = %subnet.box_egress_proxy_address(),
                        proxy_mac = %subnet.bep_mac(),
                        "host gvproxy switch up; box egress proxy peer started",
                    );
                    Some(gvproxy)
                }
                // An own-IP VM cannot work without the switch: fail loudly. A
                // non-own-IP production boot tolerates a switch that will not
                // come up (same as a missing binary below) — sessions still
                // run, without guest egress. The stand-in's flag carries the
                // same argument as own-IP: it is the e2e lane's and nothing
                // else's, and a boot under it exists to be probed through
                // this switch. Worse, the stand-in is bound before the switch
                // is spawned, so a degraded boot looks healthy to a lane that
                // waits on the stand-in's socket — every probe below it then
                // fails in terms of a peer that was never there. Fail here,
                // where the cause is and the error names it, not three steps
                // later in a box's blank answer.
                Err(error) if crate::cmd::own_ip_requested() || stub_enabled => {
                    return Err(error).context("spawning host gvproxy switch");
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "failed to spawn host gvproxy switch; booting without \
                         guest egress"
                    );
                    None
                }
            }
        }
        (binary, None) if crate::cmd::own_ip_requested() => {
            // An own-IP VM cannot work without the switch: fail loudly rather
            // than booting a session that silently has no network.
            bail!(
                "own-IP VM requested but the gvproxy binary was not found at {}; \
                 set MINVMD_GVPROXY_BIN to the gvproxy binary",
                binary.display()
            );
        }
        (binary, None) => {
            // Non-own-IP boots (e.g. the boot/session e2e lanes) tolerate a
            // missing gvproxy: warn and boot without guest egress.
            tracing::warn!(
                path = %binary.display(),
                "gvproxy binary not found; booting without guest egress \
                 (set MINVMD_GVPROXY_BIN to enable networking)"
            );
            None
        }
    };

    // R2.5: record whether the data volume image pre-exists this boot, before
    // the VMM child provisions it — a later boot failure is fatal for a
    // pre-existing image (may hold session data) and recoverable for a blank
    // one freshly created by this boot.
    let volume_path = crate::volume::resolve_data_volume_path();
    let volume_preexisted = crate::cmd::volume_preexists(&volume_path);

    // The gate over the marker socket, for the supervisor's life (T93): the
    // guest's boot beacon and its proxy publish reports — success or the
    // terminal address-in-use refusal — travel the one existing control path
    // from inside a microVM to this daemon, the boot-marker channel, and the
    // gate owns the listener so a report that arrives after READY finds it
    // still accepting. `read_ready_beacon` reads the beacon's own first
    // line, so the gate peeks a connection's first line without consuming it
    // and hands the whole stream to the beacon reader when it is one.
    let ready_timeout: Duration = crate::cmd::ready_timeout();
    let known_hosts_path = crate::cmd::default_vm_known_hosts_path();
    let marker_events = spawn_marker_gate(listener, known_hosts_path);
    // The marker socket's file outlives the first beacon now: the gate keeps
    // accepting, so the path is this guard's to remove, at every exit this
    // supervisor can take after the gate starts.
    let _marker_socket = MarkerSocketFile(marker_sock_path.clone());

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut child;
    let mut child_pid;
    // How many times this start has asked the guest to publish the hostname
    // proxy (T93): the first boot plus every redraw an address-in-use
    // publish forced. The bound is [`crate::control::PUBLISH_TRIES`], and it
    // is the loop below that counts.
    let mut publish_tries: usize = 0;
    // The port whose publish the start left unconfirmed (T93), when it did:
    // the guest's late report, if it ever comes, confirms it after the loop.
    let mut unconfirmed_port = None;
    loop {
        // This boot's publish generation (T93): drawn fresh for every boot,
        // handed beside the port, and echoed by the guest in every publish
        // report, so a report is told apart from a killed boot's even when
        // both boots were handed the same port.
        let publish_generation = draw_publish_generation();
        tracing::info!(
            generation = publish_generation,
            "drew the boot's publish generation"
        );
        // `vm.boot`: from spawning the VMM child to the guest's READY beacon,
        // one span per boot (a T93 redraw boots again under a fresh one). The
        // child and, through the boot line, the guest daemon inherit it as
        // their parent (`telemetry::forward_trace`), so the guest's boot
        // spans land under it in the same trace.
        let boot_span = tracing::info_span!(
            "vm.boot",
            vm = %crate::state::vm_name(),
            otel.status_code = tracing::field::Empty,
        )
        .entered();
        // Every return from here to READY (the spawn's `?`, the lifecycle
        // lock, read and write `?`s, the `bail!` on a lifecycle changed
        // during spawn, a failed wait) exports `vm.boot` with an error
        // status (TEL-035), as `minvmd boot` does; reaching READY clears it.
        let boot_failed = crate::telemetry::ErrorUnlessOk::new(&boot_span);
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("__krun-vmm");
        // Forward the state-dir override and VM name so the VMM child resolves the
        // same per-VM state dir this supervisor does.
        crate::state::forward_identity(&mut cmd);
        crate::telemetry::forward_trace(&mut cmd);
        alive_lock.inherit_into(&mut cmd);
        // The guest report door's path travels the same way the marker
        // socket's does: the child is the process that owns the libkrun
        // context, so it is the one that registers the door's vsock port at
        // [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`] — the door the
        // supervisor bound before the first boot, which is what the env
        // names. A redraw hands the same door to the fresh boot.
        let (name, path) = &guest_report_door;
        cmd.env(name, path);
        if let Some(path) = guest_telemetry_door.as_ref() {
            cmd.env(crate::guest_telemetry::GUEST_TELEMETRY_SOCK_ENV, path);
        }
        cmd.env(MARKER_SOCK_ENV, &marker_sock_path)
            // The node's proxy port travels to the guest through the VMM child's
            // env: the child is a separate process (like the marker socket path),
            // and its backend appends it to the kernel command line, where the
            // kernel hands unrecognized `KEY=VALUE` tokens to init as env vars.
            // The explicit `.env` also shadows any inherited operator override
            // under the same name, so the child carries exactly this resolution —
            // the same port the node row registered. On a redraw (T93) this is
            // the one line that moves: the fresh boot publishes on the port the
            // fresh draw reserved, handed the same way. No answerer port rides:
            // the in-VM daemon starts no answerer on a VM-backed host
            // (NET-138), and the host answerer serves the zone.
            .env(crate::vm::NODE_PROXY_PORT_ENV, node_port.port.to_string())
            .env(
                crate::vm::PUBLISH_GENERATION_ENV,
                publish_generation.to_string(),
            );

        // Fork the VMM child and record its pid under one hold of the
        // lifecycle write lock, so a stopper never sees a lifecycle whose
        // child exists but is not recorded. A concurrent `stop` during
        // Starting signals the pid it reads here. A stop signal's boot abort
        // (`stop::graceful_stop_from_signal`) takes the same lock, writes
        // `Stopped`, and keeps the lock until it has ended the process: it
        // either reads this child's pid and signals it, or holds the lock
        // first, and then this boot never forks.
        {
            let mut lock = state_dir
                .lifecycle_lock()
                .context("opening lifecycle lock")?;
            let _guard = lock.write().context("acquiring lifecycle write lock")?;
            let state = state_dir.read_state().context("reading state")?;
            // A concurrent stop might have already reset us to Stopped; bail
            // before a child exists.
            if !matches!(state.lifecycle, Lifecycle::Starting) {
                bail!(
                    "lifecycle changed to {:?} before spawn; aborting",
                    state.lifecycle
                );
            }
            child = cmd
                .spawn()
                .with_context(|| format!("spawning VMM child: {}", exe.display()))?;
            child_pid = child.id();
            tracing::info!(pid = child_pid, "VMM child spawned");
            state_dir
                .write_state(&State {
                    lifecycle: Lifecycle::Starting,
                    vmm_pid: Some(child_pid),
                    ..State::stopped()
                })
                .context("writing Starting state with vmm_pid")?;
        }

        // Wait for the guest to write `READY\n` on the marker socket. The wait
        // is env-configurable (`MINVMD_READY_TIMEOUT_SECS`): a cold multi-GiB
        // VM can take ~20s+ to reach userspace, so a fixed 5s was too short.
        // A publish report inside the wait is this boot's own when it carries
        // this boot's generation — kept, and handed to the watch below, since
        // nothing in the channel orders a report after READY — and a killed
        // boot's straggler otherwise, skipped rather than mistaken for a
        // beacon.
        let early_report = match wait_boot_beacon(
            &marker_events,
            ready_timeout,
            publish_generation,
            &volume_path,
            volume_preexisted,
        ) {
            Ok(early_report) => early_report,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                crate::cmd::discard_fresh_volume_image(&volume_path, volume_preexisted);
                return Err(e);
                // guard drops here → StartingGuard resets state to Stopped (R4.6)
            }
        };
        boot_failed.ok();
        drop(boot_span);

        // T93: watch what became of the port this start reserved. The guest
        // reports the publish's outcome over the marker channel — served, or
        // refused for address-in-use (a terminal report: the guest has
        // stopped retrying, so nothing else will say it) — and the watch is
        // what makes the outcome a checked fact: the report is re-probed
        // host-side before any decision reads it. A boot with no host
        // switch never publishes at all, and its report never comes, so the
        // watch is skipped and the degraded boot's story stays the warn the
        // switch's own absence already logged.
        publish_tries += 1;
        let decision = if let Some(gvproxy) = &_gvproxy {
            // The processes this supervisor spawned for this VM: the switch
            // that carries the guest's publish to the host's loopback, and
            // the VMM child. A listener on the port with one of these pids
            // is this VM's own publish, whatever the report did.
            let own_pids = [gvproxy.pid(), child_pid];
            let outcome = watch_proxy_publish(
                node_port.port,
                &marker_events,
                &own_pids,
                publish_generation,
                early_report,
            );
            crate::control::decide_publish(!node_port.configured, publish_tries, outcome)
        } else {
            tracing::warn!(
                port = node_port.port,
                "no host switch: the hostname proxy cannot publish; the VM boots degraded"
            );
            crate::control::PublishDecision::Up
        };
        match decision {
            crate::control::PublishDecision::Up => break,
            crate::control::PublishDecision::UpUnconfirmed { port } => {
                // No report, and no holder the host could vouch for: the VM
                // comes up, and the status read says the publish is
                // unconfirmed rather than letting the surfaces call it
                // serving.
                tracing::warn!(
                    port,
                    "the hostname proxy's publish is unconfirmed: no report from the \
                     guest and no listener this VM's own forwarder holds; the VM comes \
                     up and its publish is shown as unconfirmed until a report arrives"
                );
                proxy_publish.set_unconfirmed(port);
                unconfirmed_port = Some((port, publish_generation));
                break;
            }
            crate::control::PublishDecision::Redraw { port } => {
                // A drawn port, taken: draw again under the same reservation
                // discipline and ask the guest to publish again — the fresh
                // boot's first act is the publish, and the redraw is bounded
                // by the tries the decision counts.
                tracing::warn!(
                    port,
                    "the hostname proxy's publish was refused for address-in-use; \
                     redrawing the node port and asking the guest to publish again"
                );
                let _ = child.kill();
                let _ = child.wait();
                // Release this VM's own reservation before the re-draw: a
                // second open's flock contends with the held fd even in this
                // process, so the refused port, freed meanwhile, would read
                // as another VM's reservation and be skipped.
                drop(node_port);
                node_port = assign_node_proxy_port(&ports_dir)
                    .context("redrawing the node's proxy port after a refused publish")?;
                // A row the redraw cannot publish fails the start, which
                // discards a fresh volume image like every other failed boot.
                if let Err(error) = boxes.try_register_node_namespace(node_port.port) {
                    crate::cmd::discard_fresh_volume_image(&volume_path, volume_preexisted);
                    return Err(error)
                        .context("publishing the node namespace's row after a redraw");
                }
                continue;
            }
            crate::control::PublishDecision::FailStart {
                port,
                holder,
                cause,
            } => {
                // The start fails here, naming the port and the holder — one
                // error line (T93) — and the cause is written to the status
                // cell first, so a client reading the control socket in the
                // teardown window reads *why*, not merely that the proxy is
                // down. The reservation drops with the assignment below, so
                // the kernel releases the port this start held.
                proxy_publish.set_down(port, cause.clone());
                let _ = child.kill();
                let _ = child.wait();
                crate::cmd::discard_fresh_volume_image(&volume_path, volume_preexisted);
                // The holder by pid and exe when the host can see it, the
                // decision's generic holder otherwise.
                let holder = port_holder(port)
                    .map(|(_, holder)| holder)
                    .unwrap_or_else(|| holder.to_string());
                let why = match cause {
                    ProxyDownCause::PortHeld => configured_never_redraws(),
                    ProxyDownCause::RedrawsRanOut => {
                        format!("{publish_tries} publish tries exhausted, every drawn port taken")
                    }
                    // Never a failure's cause: an unconfirmed publish is
                    // `UpUnconfirmed`, and a late refusal lands after the
                    // start, never as `FailStart`.
                    ProxyDownCause::PublishUnconfirmed => "the publish is unconfirmed".to_string(),
                    ProxyDownCause::PortHeldAfterStart { .. } => {
                        "the port was held after the start".to_string()
                    }
                };
                tracing::error!(port, %holder, %why, "the VM start failed on the proxy publish");
                bail!("{}", proxy_port_failure(port, &holder, &why));
            }
        }
    }

    // T93: an unconfirmed publish stays unconfirmed until the guest's report
    // says otherwise. The marker channel is the supervisor's to drain from
    // here on — nothing past the start reads it — so a late serving report
    // for the port clears the state, and a late refusal says the port is
    // held after all.
    // Only a report the running boot sent counts: its own generation, or —
    // from a guest too old to echo one — none.
    if let Some((port, generation)) = unconfirmed_port {
        let proxy_publish = proxy_publish.clone();
        // The watcher's lines carry `vm` through a span of its own: it may
        // outlive READY, and keeping the start phase's span would keep that
        // phase from exporting (`telemetry::vm_task`).
        let vm_scope = crate::telemetry::vm_task("proxy.publish.watch");
        std::thread::spawn(move || {
            let _vm_scope = vm_scope.entered();
            for event in marker_events {
                if event.is_straggler_for(generation, true) {
                    continue;
                }
                match event {
                    MarkerEvent::ProxyServing(published, reported) if published == port => {
                        tracing::info!(
                            port,
                            report_generation = %report_generation_field(reported),
                            boot_generation = generation,
                            "the guest's late report confirms the hostname proxy's publish"
                        );
                        proxy_publish.confirm(port);
                        return;
                    }
                    MarkerEvent::ProxyPortHeld(held, reported) if held == port => {
                        // The VM stays up: the cause says so, and names the
                        // holder the host can see now, so the surfaces never
                        // recycle the start failure's words for a VM that
                        // started.
                        let holder = port_holder(port).map(|(_, holder)| holder);
                        tracing::warn!(
                            port,
                            holder = holder.as_deref().unwrap_or("unnamed"),
                            report_generation = %report_generation_field(reported),
                            boot_generation = generation,
                            "the guest's late report says the hostname proxy's port is held"
                        );
                        proxy_publish.set_down(port, ProxyDownCause::PortHeldAfterStart { holder });
                        return;
                    }
                    _ => {}
                }
            }
        });
    }

    // ── Phase 2: Starting → Running (under lock) ────────────────────────────
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mark_running = (|| -> Result<()> {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        let running = next_state(state.lifecycle, Action::MarkRunning)
            .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?;
        // Record the resources the running VM was booted with (R2.6), resolved
        // from a single config read so the (vcpus, ram_mib) pair cannot tear. The
        // VMM child resolves the same effective values from the inherited env +
        // shared config.toml; a `config set` landing inside the brief boot window
        // could still make this parent read diverge from the child's, but the
        // recorded pair itself is always self-consistent.
        let (booted_vcpus, booted_ram_mib) = crate::cmd::effective_resources();
        state_dir
            .write_state(&State {
                lifecycle: running,
                vmm_pid: Some(child_pid),
                started_at: Some(started_at),
                booted_vcpus: Some(booted_vcpus),
                booted_ram_mib: Some(booted_ram_mib),
            })
            .context("writing Running state")?;
        Ok(())
    })();
    if let Err(e) = mark_running {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
        // guard drops here → StartingGuard resets state to Stopped (R4.6)
    }
    guard.commit();
    tracing::info!(pid = child_pid, "VM is up; supervisor is running");

    // Tighten + verify the bridge socket permissions (R3.2): libkrun creates
    // it with default perms, and the shared provider dir is not 0700.
    match crate::sock::resolve_uds_path() {
        Ok(uds_path) => {
            if let Err(e) = crate::sock::enforce_socket_permissions(&uds_path)
                .and_then(|()| crate::sock::verify_socket_permissions(&uds_path))
            {
                tracing::warn!(
                    path = %uds_path.display(),
                    error = %e,
                    "could not secure minimald bridge socket to 0600",
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "minimald bridge socket path resolution failed");
        }
    }

    // The VM is ready: the start phase and the process root end and are
    // flushed now, not when the supervisor exits — which is the VM's whole
    // life later, if ever: a supervisor killed with its VM never exports what
    // is still open. Supervision runs under its own root.
    let _serve_phase = start_phase.ready();

    // ── Phase 3: Supervise until VMM child exits ─────────────────────────────
    let status = child.wait().context("waiting for VMM child")?;
    // The VM is gone, so the guest telemetry door's connection ends: let
    // the door hand the guest's last records (its shutdown) to the host's
    // endpoint before this process exits, bounded (TEL-034). The spool
    // already holds them either way.
    if guest_telemetry_door.is_some() {
        crate::guest_telemetry::drain_at_exit(crate::guest_telemetry::DRAIN_AT_EXIT);
    }
    // The VM is gone, so no answer to a pending ask can still matter: each
    // is cancelled and audited before the supervisor exits (NET-045).
    crate::control::stop_pending_asks(&boxes);
    // The one-per-stop line (NET-055): the supervisor observes every stop of
    // its VM — `min stop`, `minvmd stop`, a guest poweroff, a crash — as the
    // VMM child exiting, and it is the line's only witness: the `minvmd stop`
    // CLI logs none of its own, because whenever it stops something this
    // supervisor is alive and watching (it holds the alive lock `stop`
    // requires). A crash still says so, as the error below.
    crate::cmd::log_stopping_vm(state_dir.dir());

    // ── Phase 4: Running → Stopped (under lock) ─────────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state after VMM child exit")?;
    }

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        // R9.10: host-side analog of `minimal-entry`'s OOM post-mortem. Only a
        // real guest-workload exit code (libkrun `exit()`s the VMM child with it)
        // suggests resource exhaustion; a signal-kill (`code == None`) is a
        // deliberate `minvmd stop` terminating the child, not a crash — so the
        // resource hint would be misleading there and is suppressed.
        if status.code().is_some() {
            eprintln!(
                "minvmd: the VM exited abnormally (code {code}); if a build was killed for lack \
                 of resources, raise them with `minvmd config set --ram-mib <MiB>` / `--vcpus <n>`."
            );
        }
        bail!("VMM child exited with code {code}");
    }

    Ok(())
}

/// The override for the `bep` binary the supervisor starts. Unset, the
/// supervisor looks beside its own binary, where `just minvmd-build` puts
/// it. The installer does not ship `bep` yet: `scripts/dist-build.sh` and
/// the release workflow build only `minvmd`, so an installed `minvmd`
/// finds no proxy and boots without a credentialed lane. #2498
/// (https://github.com/gominimal/minimal/issues/2498) owns that release gap.
const BEP_BIN_ENV: &str = "MINVMD_BEP_BIN";

/// The file beside the proxy's socket that holds its stdout and stderr.
/// `min bug` collects it from the provider dir by the same name.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const BEP_LOG_FILE: &str = "bep.log";

/// The size past which a start moves the proxy's log aside, to
/// [`BEP_LOG_FILE`] with `.old` added, before it opens a fresh one. The log
/// is appended across boots, so without a cap a long-lived host fills its
/// state dir. Each start keeps at most this much from earlier boots twice.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const BEP_LOG_CAP: u64 = 8 * 1024 * 1024;

/// Moves `log` aside to `<log>.old` when it is larger than `cap`, replacing
/// an older `.old`. A log at or under the cap, or no log, stays as it is.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn cap_bep_log(log: &std::path::Path, cap: u64) -> std::io::Result<()> {
    match std::fs::metadata(log) {
        Ok(meta) if meta.len() > cap => {
            let mut old = log.as_os_str().to_owned();
            old.push(".old");
            std::fs::rename(log, old)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The flag that tells `bep serve` to stop when its standard input closes.
/// The supervisor holds the pipe's write end, and the kernel closes it when
/// the supervisor exits, even by SIGKILL, so a supervisor that dies without
/// unwinding still stops its proxy. It is the one mechanism on macOS, which
/// has no parent-death signal. On Linux it backs up `PR_SET_PDEATHSIG`
/// ([`tie_to_parent`]). #2501
/// (https://github.com/gominimal/minimal/issues/2501).
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const BEP_LIFELINE_FLAG: &str = "--exit-on-stdin-close";

/// How often the proxy's watcher looks for an exit or a stop.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const BEP_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// The `bep` binary to start: [`BEP_BIN_ENV`] verbatim, else `bep` beside
/// this process's own binary. `None` when no such file exists.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn resolve_bep_binary() -> Option<std::path::PathBuf> {
    let path = match std::env::var_os(BEP_BIN_ENV).filter(|v| !v.is_empty()) {
        Some(path) => std::path::PathBuf::from(path),
        None => std::env::current_exe().ok()?.with_file_name("bep"),
    };
    path.is_file().then_some(path)
}

/// The running `bep serve` of this boot. A watcher thread owns the child:
/// it logs one warn line when the proxy exits on its own, and it stops the
/// proxy when this handle drops with the supervisor.
///
/// Interim: `bep` starts as minvmd's own user, which is also the user of
/// gvproxy and the VM. Gatehouse §6.10 requires distinct OS users for them
/// (BEP-047). T38, #2285 (https://github.com/gominimal/minimal/issues/2285),
/// owns that split.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
#[derive(Debug)]
struct BepProxy {
    pid: u32,
    /// Whether the proxy listens now: set by the watcher while the child
    /// runs and its listener socket is the one this start made, cleared
    /// when the child exits. The box source reads it at every poll.
    listening: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    watcher: Option<std::thread::JoinHandle<()>>,
}

#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
impl BepProxy {
    /// Starts `binary serve --listener <listener> --exit-on-stdin-close`,
    /// with `token` as 64 hex digits on its standard input and its output
    /// appended to `log`. The standard input stays open after the token for
    /// as long as the child is owned here: it is the supervisor's lifeline
    /// ([`BEP_LIFELINE_FLAG`]).
    fn spawn(
        binary: &std::path::Path,
        listener: &std::path::Path,
        token: &[u8; switch::bep_host::TOKEN_LEN],
        log: &std::path::Path,
    ) -> std::io::Result<Self> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        // The socket a previous boot left at the path, if any. `bep`
        // replaces a stale one, so only a socket that is not this one is
        // the new proxy's.
        let stale = socket_identity(listener);
        if let Err(error) = cap_bep_log(log, BEP_LOG_CAP) {
            tracing::warn!(log = %log.display(), %error, "could not move the full proxy log aside");
        }
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)?;
        let err = out.try_clone()?;
        let mut command = Command::new(binary);
        command
            .arg("serve")
            .arg("--listener")
            .arg(listener)
            .arg(BEP_LIFELINE_FLAG)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        tie_to_parent(&mut command);
        let mut child = command.spawn()?;
        let mut line = String::with_capacity(token.len() * 2 + 1);
        for byte in token {
            line.push_str(&format!("{byte:02x}"));
        }
        line.push('\n');
        // The proxy reads one line, then waits for the end of its input.
        // Our end goes back into the child, so it closes when the watcher
        // drops the child or this process exits for any reason: a crash or
        // SIGKILL closes it too, and the proxy stops (#2501).
        let written = match child.stdin.as_mut() {
            Some(stdin) => stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.flush()),
            None => Err(std::io::Error::other(
                "the proxy's standard input was not piped",
            )),
        };
        if let Err(error) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let pid = child.id();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listening = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let watch = BepWatch {
                stop: std::sync::Arc::clone(&stop),
                listening: std::sync::Arc::clone(&listening),
                listener: listener.to_path_buf(),
                stale,
                log: log.to_path_buf(),
            };
            hand_to_watcher(child, watch, |body| {
                std::thread::Builder::new()
                    .name("bep-watch".into())
                    .spawn(body)
            })?
        };
        Ok(Self {
            pid,
            listening,
            stop,
            watcher: Some(watcher),
        })
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    /// The flag the box source reads: whether the proxy listens now.
    fn listening(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.listening)
    }
}

/// Ties the proxy's life to the supervisor's, so a supervisor that dies
/// without unwinding (SIGKILL, a crash) does not leave `bep serve` running
/// with this boot's token and holding its socket. Linux arms
/// `PR_SET_PDEATHSIG(SIGTERM)` in the child. The signal follows the thread
/// that forks, and the supervisor's boot thread lives as long as the VM.
/// The child exits at once when the supervisor is already gone at the
/// `prctl`. macOS has no parent-death signal, so there the proxy's standard
/// input is the tie: [`BEP_LIFELINE_FLAG`].
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn tie_to_parent(command: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: getpid() is called before the fork. In the child,
        // prctl, getppid and _exit are async-signal-safe, and the closure
        // allocates nothing.
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    libc::_exit(1);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

/// The device, inode and change time of the socket at `path`, or `None`
/// when no socket is there. `bep` removes a stale socket before it binds,
/// so the inode alone can repeat. The change time tells the two apart.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn socket_identity(path: &std::path::Path) -> Option<SocketIdentity> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let meta = std::fs::symlink_metadata(path).ok()?;
    meta.file_type()
        .is_socket()
        .then(|| (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()))
}

/// What [`socket_identity`] returns.
type SocketIdentity = (u64, u64, i64, i64);

/// What the watcher thread holds beside the child.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
struct BepWatch {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    listening: std::sync::Arc<std::sync::atomic::AtomicBool>,
    listener: std::path::PathBuf,
    /// The socket at `listener` before the start, which is not the proxy's.
    stale: Option<SocketIdentity>,
    log: std::path::PathBuf,
}

#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
impl Drop for BepProxy {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

/// The body a watcher thread runs.
type WatchBody = Box<dyn FnOnce() + Send + 'static>;

/// Starts the watcher through `spawn` and hands it `child`. The child
/// stays here until the thread runs, so when the thread cannot start the
/// proxy is killed and reaped, and never runs on with the token unowned.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn hand_to_watcher<S>(
    child: std::process::Child,
    watch: BepWatch,
    spawn: S,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    S: FnOnce(WatchBody) -> std::io::Result<std::thread::JoinHandle<()>>,
{
    let (send, receive) = std::sync::mpsc::channel::<std::process::Child>();
    let body: WatchBody = Box::new(move || {
        if let Ok(child) = receive.recv() {
            watch_bep(child, &watch);
        }
    });
    match spawn(body) {
        Ok(handle) => match send.send(child) {
            Ok(()) => Ok(handle),
            // The thread ended before it took the child.
            Err(std::sync::mpsc::SendError(mut child)) => {
                let _ = handle.join();
                let _ = child.kill();
                let _ = child.wait();
                Err(std::io::Error::other(
                    "the proxy's watcher ended before it took the proxy",
                ))
            }
        },
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

/// The watcher's loop: wait for the proxy to exit, or for a stop.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn watch_bep(mut child: std::process::Child, watch: &BepWatch) {
    use std::sync::atomic::Ordering;
    let pid = child.id();
    let log = watch.log.as_path();
    let stop = watch.stop.as_ref();
    loop {
        let exited = child.try_wait();
        if !matches!(exited, Ok(None)) {
            // Not running, or not knowable: no share may bind to the path.
            watch.listening.store(false, Ordering::SeqCst);
        }
        match exited {
            Ok(Some(status)) => {
                tracing::warn!(
                    pid,
                    %status,
                    log = %log.display(),
                    "box egress proxy exited; boxes have no credentialed lane until the next boot"
                );
                return;
            }
            Ok(None) => {
                // `bep serve` binds its listener once its keys, audit log
                // and root certificates are ready, so a new socket at the
                // path is the proxy listening.
                let bound = socket_identity(&watch.listener)
                    .is_some_and(|identity| Some(identity) != watch.stale);
                if bound != watch.listening.swap(bound, Ordering::SeqCst) {
                    tracing::debug!(pid, listening = bound, "box egress proxy listener");
                }
            }
            Err(error) => {
                // Not knowable is not stopped: stop it here, because the
                // handle's drop can reach the child only through this loop.
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!(pid, %error, "box egress proxy could not be waited on; stopped it");
                return;
            }
        }
        if stop.load(Ordering::SeqCst) {
            watch.listening.store(false, Ordering::SeqCst);
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!(pid, "box egress proxy stopped with the VM");
            return;
        }
        std::thread::sleep(BEP_WATCH_INTERVAL);
    }
}

/// Starts this boot's proxy on `listener`, its log beside it. Logs one
/// info line naming the socket and the pid, or one warn line naming why
/// the boot goes on without the proxy.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn start_bep_proxy(
    listener: &std::path::Path,
    token: &[u8; switch::bep_host::TOKEN_LEN],
) -> Option<BepProxy> {
    let Some(binary) = resolve_bep_binary() else {
        tracing::warn!(
            "box egress proxy binary not found beside minvmd; booting without \
             a credentialed lane (set MINVMD_BEP_BIN to the bep binary)"
        );
        return None;
    };
    let log = listener.with_file_name(BEP_LOG_FILE);
    match BepProxy::spawn(&binary, listener, token, &log) {
        Ok(proxy) => {
            tracing::info!(
                pid = proxy.pid(),
                sock = %listener.display(),
                log = %log.display(),
                binary = %binary.display(),
                "box egress proxy started"
            );
            Some(proxy)
        }
        Err(error) => {
            tracing::warn!(
                %error,
                binary = %binary.display(),
                "failed to start the box egress proxy; booting without a credentialed lane"
            );
            None
        }
    }
}

/// The box source the peer's pool is partitioned by:
/// [`CredentialedBoxes`] when an acceptor was started at the wire's path,
/// and [`switch::bep_host::NoBoxes`] — no row, no share, no socket — when
/// none was.
///
/// A socket in the pool is a lane onto the host for the box whose share
/// holds it. The gate decides who may reach the proxy's address
/// (NET-134, T45, #1885): `egress::proxy_lane_admits` refuses a frame to
/// it from a row that declared no credentialed upstream. The shares follow
/// the same declaration (§7.1), so a row with no lane holds no socket. A
/// production boot that started `bep serve` registers rows, and the proxy
/// admits only a delivery with this boot's token. A production boot with
/// no proxy hands the peer an empty source and the pool binds nothing — a
/// box's connection to the proxy's address meets the stack's own reset.
/// The stand-in's boot (`MINVMD_BEP_STUB`, the e2e lane's flag and nothing
/// else's) registers rows too. The caller passes the acceptor's own
/// `listening` flag — not whether a flag asked for one — so the pool is
/// never partitioned by a path nothing listens on.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn bep_box_source(
    listening: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    table: crate::box_registry::BoxTable,
    attachments: crate::bep_attach::Attachments,
) -> std::sync::Arc<dyn switch::bep_host::BepBoxSource> {
    match listening {
        Some(listening) => std::sync::Arc::new(CredentialedBoxes {
            boxes: crate::box_registry::RegisteredBoxes::new(table.clone(), attachments),
            table,
            listening,
        }),
        None => std::sync::Arc::new(switch::bep_host::NoBoxes),
    }
}

/// The registered box rows that declared a credentialed upstream, while
/// the acceptor listens. The pool polls the addresses every stack turn, so
/// a proxy that starts listening late grows the shares within a turn, and
/// one that exits takes them away.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
struct CredentialedBoxes {
    boxes: crate::box_registry::RegisteredBoxes,
    table: crate::box_registry::BoxTable,
    listening: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl switch::bep_host::BepBoxSource for CredentialedBoxes {
    fn box_switch_addresses(&self) -> Vec<std::net::Ipv4Addr> {
        if !self.listening.load(std::sync::atomic::Ordering::SeqCst) {
            return Vec::new();
        }
        let declared: std::collections::HashSet<std::net::Ipv4Addr> = self
            .table
            .rows()
            .iter()
            .filter(|row| row.declares_credentialed_upstream())
            .map(|row| row.switch_addr())
            .collect();
        self.boxes
            .box_switch_addresses()
            .into_iter()
            .filter(|addr| declared.contains(addr))
            .collect()
    }

    fn box_id_for_source(&self, source: std::net::Ipv4Addr) -> Option<crate::bep_attach::BoxId> {
        self.boxes.box_id_for_source(source)
    }
}

/// The node's proxy and answerer ports, assigned by the VM host before the VM
/// boots: default-first, so a VM sharing a host with a native daemon still
/// lands on the defaults when they are free and only falls to OS-assigned
/// ports when the defaults are actually held.
// Only `run_foreground` calls these, and it needs libkrun; without it the
// crate is a runtime-bailing stub, but the tests below still cover this on
// every target.
/// The default the assignment probes first. It mirrors the native daemon's
/// own default (`DEFAULT_EGRESS_PROXY_PORT` in minimald's `net/proxy.rs`):
/// `minvmd` does not depend on the daemon, so the value is pinned here beside
/// the constant it mirrors.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const NODE_DEFAULT_PROXY_PORT: u16 = 7654;

/// Why a preferred node port was not handed, when it was not: the probe that
/// refused it — the wildcard bind, or the loopback connect that follows it.
/// The two strings are the assignment's own vocabulary
/// ([`log_node_port_assignment`]), so a boot that lands off the default port
/// says which check refused it rather than only that something did.
///
/// The bind probe refused the port: something holds it on the loopback address
/// the hostname surface is published on, or on the wildcard
/// ([`tcp_bind_probe`]).
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const SKIP_BIND_REFUSED: &str = "bind refused";

/// A listener answered the connect probe on the loopback address although both
/// binds succeeded: the backstop behind [`tcp_bind_probe`].
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const SKIP_LOOPBACK_ANSWERING: &str = "a listener is already answering on loopback";

/// Why a candidate the reservation could not take is skipped: another VM's
/// supervisor holds the per-port lock (T93).
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const SKIP_RESERVED_BY_ANOTHER_VM: &str = "another VM's reservation holds it";

/// Why a candidate the node itself binds is skipped, whatever any probe
/// says about it (T93): the node's own daemons hold these ports on every
/// VM-backed boot, so handing one to a VM publishes nothing and moves the
/// port's real holder off a port it never left.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const SKIP_NODE_RESERVED: &str = "the node reserves it for its own daemons";

/// The ports this node itself reserves, skipped by the draw whether or not
/// anything is bound at them at the probe ([`SKIP_NODE_RESERVED`]). The
/// zone answerer's hook port is the one port every VM-backed boot binds on
/// the host: [`crate::net::answerer::DEFAULT_ANSWERER_PORT`]. The in-VM
/// egress and mTLS defaults (:7654/:7655) are not here — a VM-backed host
/// runs its hostname proxy *and* its zone answerer on the host, and those
/// in-guest defaults are exactly the ports a VM's own guest daemons bind
/// inside their VM, not ports the node reserves on the host.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const NODE_RESERVED_PORTS: &[u16] = &[crate::net::answerer::DEFAULT_ANSWERER_PORT];

/// The mode every ports directory is created with, and the widest mode an
/// existing one may carry: per user, so another user's VMs never hold a
/// claim on this user's reservations.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const PORTS_DIR_MODE: u32 = 0o700;

/// The directory this user's node-port reservations live in (T93): one
/// directory per user, so a host's users never arbitrate with each other —
/// the single-operator premise leaves that residual to the bind probe —
/// while a user's own two VMs do, by the per-port lock
/// ([`NodePortReservation`]). The directory is a runtime directory, never
/// a cache or temp directory an OS purges: a purged lock file is a lost
/// reservation, not a released one.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn node_ports_dir() -> Result<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| home.join("Library/Application Support/minimal/run"))
        .ok_or_else(|| {
            anyhow::anyhow!("HOME is not set: nowhere to keep node-port reservations")
        })?;
    #[cfg(not(target_os = "macos"))]
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .map(|runtime| runtime.join("minimal"))
        .unwrap_or_else(|| {
            // The fallback lives under the shared, world-writable `/tmp`, so
            // its base is created 0700 and held to the same owner/mode check
            // as the ports dir: another user who pre-created it could
            // otherwise swap the ports dir out from under this one.
            let uid = unsafe { libc::getuid() };
            std::path::PathBuf::from(format!("/tmp/minimal-{uid}"))
        });
    #[cfg(not(target_os = "macos"))]
    let base_is_shared_tmp = std::env::var_os("XDG_RUNTIME_DIR").is_none_or(|v| v.is_empty());
    #[cfg(target_os = "macos")]
    let base_is_shared_tmp = false;
    node_ports_dir_in(&base, base_is_shared_tmp)
}

/// The pure half of [`node_ports_dir`]: makes `base` and its `ports` dir
/// ready and returns the ports dir.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn node_ports_dir_in(
    base: &std::path::Path,
    base_is_shared_tmp: bool,
) -> Result<std::path::PathBuf> {
    use anyhow::Context as _;
    use std::os::unix::fs::DirBuilderExt as _;
    // The base is this user's own runtime dir (the XDG_RUNTIME_DIR contract,
    // or macOS's Application Support): created 0700 when absent and
    // tightened to 0700 when this user owns it, never refused — the ports dir itself is the one that carries the claim, so
    // it is the one the owner/mode check refuses. The base is also the dir
    // the zone answerer's interim channel binds in, which refuses a dir open
    // to group or other, so a base created here under the umask's mode would
    // leave the interim with no channel. The `/tmp` fallback's base is the
    // exception, created and checked like the ports dir.
    if base_is_shared_tmp {
        create_private_dir(base)?;
    } else if !base.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(PORTS_DIR_MODE)
            .create(base)
            .context("creating the node-port reservation base")?;
    } else {
        // A base an earlier build created under the umask's mode: tightened
        // to 0700 when this user owns it, so the interim channel binds there
        // again; one another user owns is left for the answerer to refuse.
        crate::sock::restrict_owned_dir(base)
            .context("tightening the node-port reservation base")?;
    }
    let ports = base.join("ports");
    create_private_dir(&ports)?;
    Ok(ports)
}

/// Creates `dir` with [`PORTS_DIR_MODE`], or — when it already exists —
/// refuses it unless this user owns it and its mode is no wider
/// ([`verify_ports_dir`]).
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    use anyhow::Context as _;
    use std::os::unix::fs::DirBuilderExt as _;
    match std::fs::DirBuilder::new().mode(PORTS_DIR_MODE).create(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => verify_ports_dir(dir),
        Err(error) => Err(error).with_context(|| {
            format!(
                "creating the node-port reservation directory {}",
                dir.display()
            )
        }),
    }
}

/// A ports directory that already exists is only usable when this user owns
/// it and it is not wider than [`PORTS_DIR_MODE`] (T93): a directory some
/// other user owns, or a world-writable one, would let a claim on this
/// user's VMs' ports be taken or watched by anyone, and a created-here
/// directory is never that. The lock files themselves are never unlinked —
/// a stale file holds nothing, the lock is the advisory lock on it — so
/// the directory's own hygiene is the whole question.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn verify_ports_dir(ports: &std::path::Path) -> Result<()> {
    use anyhow::{Context as _, bail};
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = std::fs::metadata(ports).with_context(|| {
        format!(
            "inspecting the node-port reservation directory {}",
            ports.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!(
            "the node-port reservation directory {} exists and is not a directory",
            ports.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & !PORTS_DIR_MODE != 0 {
        bail!(
            "the node-port reservation directory {} has mode {mode:o}, wider than {:o}: \
             refusing to share reservations through it",
            ports.display(),
            PORTS_DIR_MODE
        );
    }
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != unsafe { libc::getuid() } {
        bail!(
            "the node-port reservation directory {} is owned by another user (uid {}): \
             refusing to share reservations through it",
            ports.display(),
            metadata.uid()
        );
    }
    Ok(())
}

/// The host-wide reservation on one node port (T93): an exclusive advisory
/// lock on the port's own file in this user's ports directory
/// ([`node_ports_dir`]), held by the supervisor as an open file description
/// for the VM's life. The kernel releases it when the supervisor stops the
/// VM, exits, or crashes — no pid files, no stale entries to clean up — and
/// minimal never unlinks the file: the lock is the `flock`, so a leftover
/// file from a dead supervisor holds nothing and the next boot's
/// `flock` takes it.
///
/// `flock`, not `fcntl`: a `flock` is held by the open file description, so
/// two supervisors — two processes, or two threads in one process during a
/// redraw — genuinely contend for it, while an `fcntl` record lock would
/// not arbitrate two opens made by the same process at all.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
#[derive(Debug)]
struct NodePortReservation {
    _lock: std::fs::File,
}

#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
impl NodePortReservation {
    /// Take the port's reservation. `Ok(None)` is the loud skip: another
    /// supervisor of this user holds the port — a VM this host is already
    /// running, or one that died mid-redraw — so the caller logs the skip
    /// ([`SKIP_RESERVED_BY_ANOTHER_VM`]) and draws its next candidate.
    #[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
    fn take(dir: &std::path::Path, port: u16) -> Result<Option<Self>> {
        use anyhow::Context as _;
        use std::os::fd::AsRawFd as _;
        let path = dir.join(format!("{port}.lock"));
        let _lock = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| {
                format!("opening the node-port reservation file {}", path.display())
            })?;
        match unsafe { libc::flock(_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } {
            0 => Ok(Some(Self { _lock })),
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock => {
                Ok(None)
            }
            _ => Err(std::io::Error::last_os_error()).with_context(|| {
                format!("reserving the node port {port} through {}", path.display())
            }),
        }
    }
}

/// One node-port candidate's verdict ([`check_candidate`]): free — and its
/// reservation taken — skipped with the reason a candidate log line
/// carries, or the probe's own failure, which no candidate can be blamed
/// for.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
enum CandidateCheck {
    Free(NodePortReservation),
    Skip(&'static str),
    Error(anyhow::Error),
}

/// Checks one node-port candidate and, when it passes, takes its
/// reservation before returning it (T93): the node-reserved set first
/// ([`NODE_RESERVED_PORTS`], whether or not anything is bound), then the
/// probes — the bind on the published address with the wildcard as the
/// extra holder check, then, for TCP, the connect probe — and the
/// reservation last, so a port another VM of this user holds is skipped
/// and logged with the same one line as every other refusal. Taking the
/// reservation inside the check is what makes the draw atomic: between the
/// probes and the `flock` no second supervisor can land on the port,
/// because the `flock` is the arbiter two concurrent boots race for.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn check_candidate(
    dir: &std::path::Path,
    port: u16,
    udp: bool,
    probe: &dyn Fn(u16) -> std::io::Result<u16>,
) -> CandidateCheck {
    use std::io::ErrorKind::AddrInUse;
    if NODE_RESERVED_PORTS.contains(&port) {
        log_skipped_candidate(port, SKIP_NODE_RESERVED);
        return CandidateCheck::Skip(SKIP_NODE_RESERVED);
    }
    let refused = match probe(port) {
        Err(error) if error.kind() == AddrInUse => Some(SKIP_BIND_REFUSED),
        Err(error) => {
            return CandidateCheck::Error(
                anyhow::Error::from(error).context("probing a node-port candidate"),
            );
        }
        Ok(_) if udp => None,
        Ok(_) if loopback_answers(port) => Some(SKIP_LOOPBACK_ANSWERING),
        Ok(_) => None,
    };
    if let Some(reason) = refused {
        log_skipped_candidate(port, reason);
        return CandidateCheck::Skip(reason);
    }
    match NodePortReservation::take(dir, port) {
        Ok(Some(reservation)) => {
            log_reserved_candidate(port);
            CandidateCheck::Free(reservation)
        }
        Ok(None) => {
            log_skipped_candidate(port, SKIP_RESERVED_BY_ANOTHER_VM);
            CandidateCheck::Skip(SKIP_RESERVED_BY_ANOTHER_VM)
        }
        Err(error) => CandidateCheck::Error(error),
    }
}

/// One line per skipped candidate (T93): the port and the reason it was
/// passed over — another VM's reservation, a port the node reserves for
/// itself, or a bind or connect probe that refused it — so the log says
/// every port a start considered and why it moved on, not just the one it
/// landed on.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn log_skipped_candidate(port: u16, reason: &'static str) {
    tracing::info!(
        candidate_port = port,
        skip_reason = reason,
        "skipped a node-port candidate"
    );
}

/// One line per reserved node port (T93): the port the supervisor holds the
/// reservation on for the VM's life, released by the kernel when the VM's
/// supervisor stops, exits or crashes.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn log_reserved_candidate(port: u16) {
    tracing::info!(reserved_port = port, "reserved the node port");
}

/// One node port's assignment: the port handed to the guest, the port the
/// assignment preferred, and — when the two differ — which check refused the
/// preferred one. The last two fields are the assignment's log line. The
/// assignment owns the port's reservation (T93): the supervisor holds it for
/// the VM's life, and the kernel releases it when the VM's supervisor stops,
/// exits or crashes — the reservation moves with the assignment, never into
/// a registry the exit path has to remember to clean.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
#[derive(Debug)]
struct NodePortAssignment {
    /// The port handed to the guest: the value every consumer binds.
    port: u16,
    /// The port the assignment preferred: the default probed first, or the
    /// operator's pin.
    preferred: u16,
    /// Why `preferred` was not handed, when it was not.
    skipped: Option<&'static str>,
    /// Whether the port came from the operator's pin rather than the draw
    /// (T93): a configured port never redraws, so a publish that finds the
    /// port taken fails the start instead of moving the surface.
    configured: bool,
    /// The host-wide reservation this supervisor holds on `port` for the
    /// VM's life ([`NodePortReservation`]). Never read: holding it is the
    /// whole job, and dropping the assignment is what releases it.
    _reservation: NodePortReservation,
}

/// Assigns the node's hostname-proxy TCP port. The operator's override
/// ([`crate::vm::NODE_PROXY_PORT_ENV`] set in this supervisor's own env) wins
/// over the draw — probed and reserved like any other candidate, but a pin
/// some check refuses fails the start naming the port, because it never
/// redraws (T93) — and the one resolved port is what both the guest handoff
/// (the VMM child's env) and the node row's own publish are written from:
/// handed == registered, never two resolutions. The assignment logs one
/// line ([`log_node_port_assignment`]), which is where a host running two
/// VMs — or a VM beside a native daemon — says whether it took the default
/// or had to give it up, and one line per candidate it skipped along the
/// way ([`log_skipped_candidate`]). The zone answerer's port is deliberately
/// not the node's to hand: on a VM-backed host the in-VM daemon starts no
/// answerer (NET-138) and the host answerer serves the zone, so a handed
/// answerer port would be an admitted port with nothing behind it.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn assign_node_proxy_port(dir: &std::path::Path) -> Result<NodePortAssignment> {
    let proxy = match node_port_override(crate::vm::NODE_PROXY_PORT_ENV)? {
        Some(proxy) => configured_node_port(dir, proxy)?,
        None => assign_node_port(dir, NODE_DEFAULT_PROXY_PORT, false)?,
    };
    log_node_port_assignment("hostname proxy", &proxy);
    Ok(proxy)
}

/// The operator's pin (T93): probed and reserved like a drawn port, but a pin
/// any check refuses fails the start naming the port and the holder — the
/// reason the check carries — because the configured port never redraws: a
/// start that moved the surface would publish a port the operator did not
/// pin, and one that kept going would boot a VM whose proxy serves on a
/// port someone else already holds.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn configured_node_port(dir: &std::path::Path, port: u16) -> Result<NodePortAssignment> {
    let probe = node_port_probe(false);
    match check_candidate(dir, port, false, &probe) {
        CandidateCheck::Free(reservation) => Ok(NodePortAssignment {
            port,
            preferred: port,
            skipped: None,
            configured: true,
            _reservation: reservation,
        }),
        CandidateCheck::Skip(reason) => {
            // Who holds it, as well as the host can say: a process by pid
            // and exe when the bind or connect probe refused it, the node's
            // own reservation, or another of this user's VMs.
            let holder = match reason {
                SKIP_NODE_RESERVED => "the node's own zone answerer (a reserved port)".to_string(),
                SKIP_RESERVED_BY_ANOTHER_VM => "another VM's reservation".to_string(),
                _ => port_holder(port)
                    .map(|(_, holder)| holder)
                    .unwrap_or_else(|| crate::control::HELD_BY_ANOTHER_PROCESS.to_string()),
            };
            let why = format!("{reason}; {}", configured_never_redraws());
            Err(anyhow::anyhow!(
                "{}",
                proxy_port_failure(port, &holder, &why)
            ))
        }
        CandidateCheck::Error(error) => {
            Err(error.context("assigning the configured hostname-proxy port"))
        }
    }
}

/// How every proxy-port start failure begins (T93): the one line the
/// detaching parent lifts out of the supervisor's log ([`proxy_failure_line`])
/// so the CLI's autospawn error names the port, the holder and why inline,
/// rather than pointing at a log file.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const PROXY_PORT_FAILURE_PREFIX: &str = "hostname proxy port ";

/// The one-line proxy-port start failure: the port, who holds it, and why the
/// start ends instead of moving on.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn proxy_port_failure(port: u16, holder: &str, why: &str) -> String {
    format!("{PROXY_PORT_FAILURE_PREFIX}{port} held by {holder}; {why}")
}

/// Why a configured port's failure ends the start: the pin never redraws.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn configured_never_redraws() -> String {
    format!(
        "configured ports never redraw (free the port or unset {})",
        crate::vm::NODE_PROXY_PORT_ENV
    )
}

/// The proxy-port failure line in a supervisor's captured stderr, when the
/// start failed on it ([`PROXY_PORT_FAILURE_PREFIX`]), from the prefix on —
/// anyhow's `Error:` and `Caused by:` framing dropped.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn proxy_failure_line(log: &str) -> Option<&str> {
    log.lines().find_map(|line| {
        line.find(PROXY_PORT_FAILURE_PREFIX)
            .map(|at| line[at..].trim_end())
    })
}

/// Who listens on `port` on this host — its pid, and the holder as
/// `pid <pid> (<exe>)` — when the host lets this user see it (T93): the
/// start failure names the holder so the operator knows what to free, and
/// the publish watch matches the pid against the processes this supervisor
/// spawned. `None` when no visible process holds it — a listener of another
/// user, or a host this cannot read.
#[cfg(target_os = "linux")]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn port_holder(port: u16) -> Option<(u32, String)> {
    port_holder_with(std::path::Path::new("/proc"), port)
}

/// [`port_holder`] read from the procfs mounted at `proc`: a root it cannot
/// read names no holder, so a host this cannot read is `None` — the
/// unnamed holder the publish watch takes as unknown, never as foreign.
#[cfg(target_os = "linux")]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn port_holder_with(proc: &std::path::Path, port: u16) -> Option<(u32, String)> {
    // The listening sockets on the port, on loopback or the wildcard — the
    // addresses whose holder refuses a bind of 127.0.0.1:<port>.
    const HOLDING_ADDRS: &[&str] = &[
        "0100007F",
        "00000000",
        "00000000000000000000000000000000",
        "00000000000000000000000001000000",
        "0000000000000000FFFF00000100007F",
    ];
    let mut sockets = Vec::new();
    for table in ["net/tcp", "net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(proc.join(table)) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // local_address is field 1, st field 3 (0A = LISTEN), inode 9.
            if fields.len() < 10 || fields[3] != "0A" {
                continue;
            }
            let Some((addr, hex_port)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(hex_port, 16).ok() == Some(port) && HOLDING_ADDRS.contains(&addr)
            {
                sockets.push(format!("socket:[{}]", fields[9]));
            }
        }
    }
    if sockets.is_empty() {
        return None;
    }
    for entry in std::fs::read_dir(proc).ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            if sockets.iter().any(|s| target.as_os_str() == s.as_str()) {
                let exe = std::fs::read_link(entry.path().join("exe"))
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .or_else(|| {
                        std::fs::read_to_string(entry.path().join("comm"))
                            .ok()
                            .map(|c| c.trim().to_string())
                    });
                return Some((
                    pid,
                    match exe {
                        Some(exe) => format!("pid {pid} ({exe})"),
                        None => format!("pid {pid}"),
                    },
                ));
            }
        }
    }
    None
}

/// Who listens on `port` on this host (see the Linux twin): macOS has no
/// procfs, so `lsof` answers, for the processes this user may see.
#[cfg(target_os = "macos")]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn port_holder(port: u16) -> Option<(u32, String)> {
    port_holder_with(std::path::Path::new("/usr/sbin/lsof"), port)
}

/// [`port_holder`] asked of the `lsof` at `lsof`: one that is missing or
/// fails names no holder, so the tool's failure is `None` — the unnamed
/// holder the publish watch takes as unknown, never as foreign.
#[cfg(target_os = "macos")]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn port_holder_with(lsof: &std::path::Path, port: u16) -> Option<(u32, String)> {
    let output = std::process::Command::new(lsof)
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fpc"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    lsof_holder(&String::from_utf8_lossy(&output.stdout))
}

/// The first process in `lsof -Fpc` output: its pid, and the holder as
/// `pid <pid> (<command>)`.
#[cfg(target_os = "macos")]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn lsof_holder(output: &str) -> Option<(u32, String)> {
    let mut pid = None;
    for line in output.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse::<u32>().ok();
        } else if let (Some(command), Some(p)) = (line.strip_prefix('c'), pid) {
            return Some((p, format!("pid {p} ({command})")));
        }
    }
    pid.map(|p| (p, format!("pid {p}")))
}

/// No way to name a holder on this host.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn port_holder(_port: u16) -> Option<(u32, String)> {
    None
}

/// One line per node-port assignment: the port the assignment preferred, the
/// port handed to the guest, and — when the preferred port was skipped — the
/// probe that refused it. The skip reason is the half a shared host needs:
/// two VMs and a native daemon can all want the default proxy port, so a boot
/// that landed elsewhere says so here, in the supervisor's own log, rather
/// than leaving a hostname surface that never answered to be found there.
/// A preferred port refused because something holds it names that holder's
/// pid and executable, so the log says which leftover owns the bind the
/// boot moved off.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn log_node_port_assignment(surface: &str, assigned: &NodePortAssignment) {
    // The holder is looked up only for the bind-refused skip: any other skip
    // (loopback answering, reserved by another VM) is not a holder question,
    // and a configured port never reaches here — its refusal fails the
    // start naming the holder already.
    let holder = (assigned.skipped == Some(SKIP_BIND_REFUSED))
        .then(|| port_holder(assigned.preferred))
        .flatten()
        .map(|(_, holder)| holder)
        .unwrap_or_default();
    tracing::info!(
        surface,
        preferred = assigned.preferred,
        handed = assigned.port,
        configured = assigned.configured,
        skip_reason = assigned.skipped.unwrap_or(""),
        port_holder = %holder,
        "assigned the node port"
    );
}

/// Reads one operator override for a node port off this supervisor's env —
/// the same names the child transport decodes, and [`run`] rewrites the
/// resolved values under them before spawning the VMM child, so the child's
/// decode sees exactly this resolution. `Ok(None)` when the variable is
/// absent — the default-first probe decides. A present value that does not
/// parse, or parses to `0`, fails here at the supervisor naming the variable
/// and the value, never a fallback to selection that would publish a pair
/// different from the one the operator pinned.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn node_port_override(name: &'static str) -> Result<Option<u16>> {
    let Some(raw) = std::env::var(name).ok() else {
        return Ok(None);
    };
    match raw.trim().parse::<u16>() {
        Ok(0) => Err(anyhow::anyhow!(
            "environment variable {name} carries {raw:?}: 0 is not a port to pin; \
             unset the variable to let the assignment pick one"
        )),
        Ok(port) => Ok(Some(port)),
        Err(_) => Err(anyhow::anyhow!(
            "environment variable {name} carries {raw:?}, which is not a port"
        )),
    }
}

/// How long [`loopback_answers`] waits before deciding no listener is
/// answering. A loopback connect settles at once — a refusal when nothing
/// listens, or the kernel's own handshake when something does — so this is
/// only the bound that keeps a pathological host from stalling a boot on the
/// probe.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const LOOPBACK_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Whether a listener accepts a connection on the loopback address at `port`.
///
/// A completed connection is a live listener: the kernel completes the
/// handshake for a listening socket before the process behind it ever
/// accepts, so the probe needs the connection and nothing more. It is closed
/// as soon as it is made, so the listener sees a closing client and nothing
/// else. Anything else the connect returns — a refusal, most often, or the
/// timeout — means nothing is answering there.
///
/// This is the second probe a TCP node port must pass, a backstop behind the
/// bind probe ([`tcp_bind_probe`]), which already refuses a port held on the
/// loopback address on every host. See [`assign_node_port`].
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn loopback_answers(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
        LOOPBACK_PROBE_TIMEOUT,
    )
    .is_ok()
}

/// Assigns one node port by probing: bind the preferred port to check the
/// host has it free, release the probe again, and let the OS pick when the
/// preferred port is already held. The probe releases its socket, so between
/// the assignment and the guest's bind inside the VM the port could still be
/// taken by another process — a lost race the guest's own log tail shows
/// (a handed port never silently moves, NET-024).
///
/// For a TCP port, free means the bind probe succeeds on the loopback address
/// the hostname surface is published on and on the wildcard
/// ([`tcp_bind_probe`]), *and* no listener answers a connection on
/// `127.0.0.1` at that port ([`loopback_answers`]); the skip reason names
/// which check refused it. The fallback is held to the same checks
/// ([`fallback_port`]). The answerer's UDP probe is unchanged: a UDP socket
/// never accepts a connection, so the wildcard bind is the whole question
/// there. Every check a candidate passes ends in the reservation being taken
/// ([`check_candidate`], T93): the draw never hands a port it does not hold
/// host-wide, so two VMs booting at the same moment cannot draw the same
/// port — the `flock` is the arbiter, and the loser skips, logs the reason,
/// and draws again.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn assign_node_port(
    dir: &std::path::Path,
    preferred: u16,
    udp: bool,
) -> Result<NodePortAssignment> {
    use anyhow::Context as _;
    let probe = node_port_probe(udp);
    // Why the preferred port was not handed, when it was not: every candidate
    // — the preferred included — is held to the same checks, and each skipped
    // one logs its own line before the draw moves on.
    let skipped = match check_candidate(dir, preferred, udp, &probe) {
        CandidateCheck::Free(reservation) => {
            return Ok(NodePortAssignment {
                port: preferred,
                preferred,
                skipped: None,
                configured: false,
                _reservation: reservation,
            });
        }
        CandidateCheck::Skip(reason) => Some(reason),
        CandidateCheck::Error(error) => {
            return Err(error).context("probing the node's default port");
        }
    };
    let (port, reservation) = fallback_port(dir, || probe(0), udp)?;
    Ok(NodePortAssignment {
        port,
        preferred,
        skipped,
        configured: false,
        _reservation: reservation,
    })
}

/// The bind probe for one node-port family: the wildcard bind the answerer's
/// UDP hook needs, or the two-address TCP bind the hostname proxy's
/// published address needs ([`tcp_bind_probe`]). A `port` of 0 is the OS's
/// own draw, which the probe returns the number of.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn node_port_probe(udp: bool) -> impl Fn(u16) -> std::io::Result<u16> {
    move |port| {
        if udp {
            let socket = std::net::UdpSocket::bind(("0.0.0.0", port))?;
            Ok(socket.local_addr()?.port())
        } else {
            tcp_bind_probe(port)
        }
    }
}

/// The TCP bind probe: binds `127.0.0.1:<port>` — the exact address minimald's
/// hostname proxy (through gvproxy's expose) publishes on — then the wildcard
/// at the same port, releasing each socket before the next bind, and returns
/// the port (the OS's draw when `port` is 0). Either bind refusing is
/// `AddrInUse`.
///
/// Both binds are needed on macOS. std sets `SO_REUSEADDR`, and there
/// that flag lets a wildcard bind succeed over another socket listening on
/// `127.0.0.1:<port>`, and a loopback bind succeed over a wildcard listener.
/// It never lets either bind succeed over a listener on its own exact address.
/// So the loopback bind sees another VM's hostname surface, and the wildcard
/// bind sees a wildcard holder that a loopback bind would otherwise coexist
/// with. On Linux either bind alone refuses both shapes. The flag is kept
/// rather than cleared: without it a `TIME_WAIT` connection left on the port
/// by a stopped VM refuses the bind on both hosts, and a lone VM would be
/// moved off the default port with nothing serving on it.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn tcp_bind_probe(port: u16) -> std::io::Result<u16> {
    let loopback = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    let port = loopback.local_addr()?.port();
    drop(loopback);
    std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))?;
    Ok(port)
}

/// How many candidates the OS-assigned fallback draws before giving up
/// ([`fallback_port`]). The OS draws each candidate out of the ephemeral
/// range, so a candidate that is already served on loopback is a rare draw
/// and the next one lands elsewhere; the bound is only the pathological-host
/// guard, never a shape a shared host reaches.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const FALLBACK_PORT_ATTEMPTS: usize = 8;

/// Hands out the OS-assigned fallback port for a preferred one some check
/// refused ([`assign_node_port`]), holding every candidate it draws to the
/// same checks the preferred port is held to ([`check_candidate`]) and
/// returning the reservation on the first candidate that passes. The OS draws
/// out of the ephemeral range under the same `SO_REUSEADDR` semantics the
/// wildcard bind carries, so on macOS it can hand back a port another VM's
/// hostname surface already serves on the loopback address — the same
/// collision the preferred-port checks exist to prevent. A refused candidate
/// is logged, released, and the next one drawn; a host whose every draw lands
/// on a refused port fails the boot naming the conflict, and never hands a
/// port two VMs would share.
///
/// The candidate source is a parameter so the tests can hand the picker a
/// known sequence: production passes the port-0 bind, which is the OS's own
/// draw, released the moment its number is read.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn fallback_port(
    dir: &std::path::Path,
    mut next: impl FnMut() -> std::io::Result<u16>,
    udp: bool,
) -> Result<(u16, NodePortReservation)> {
    use anyhow::Context as _;
    let probe = node_port_probe(udp);
    for _ in 0..FALLBACK_PORT_ATTEMPTS {
        // A draw whose wildcard half is held is refused like a served one.
        let port = match next() {
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            drawn => drawn
                .context("the node's default port is held and no OS-assigned port is available")?,
        };
        match check_candidate(dir, port, udp, &probe) {
            CandidateCheck::Free(reservation) => return Ok((port, reservation)),
            CandidateCheck::Skip(_) => continue,
            CandidateCheck::Error(error) => return Err(error),
        }
    }
    Err(anyhow::anyhow!(
        "no OS-assigned port is free: every one of the {FALLBACK_PORT_ATTEMPTS} \
         candidates drawn is already held or answering on loopback"
    ))
}

// ── T93: the marker gate, the publish watch ────────────────────────────────
//
// The boot-marker channel is the one existing control path from inside a
// microVM to this daemon the guest can *initiate*: the guest dials the vsock
// port the host bridges to the marker socket, writes, and hangs up. T93
// extends what travels it — the guest's publish reports join the boot beacon
// — and the gate below is the host half: one thread owning the listener for
// the supervisor's life, classifying each connection by the first line it
// peeks, handing each event to the supervisor over one channel.

/// The first line of the guest's terminal publish refusal (T93): the port
/// named on the line after it could not be published because something held
/// it. Pinned beside its guest-side twin (minimald's
/// `PROXY_PORT_HELD_BEACON`); the guest's report is a terminal fact, so the
/// two names must agree for the watch below to see it.
#[cfg(any(minvmd_libkrun, test))]
const PROXY_PORT_HELD_LINE: &str = "PROXY_PORT_HELD";

/// The first line of the guest's publish report (T93): the port named on the
/// line after it is serving. Pinned beside its guest-side twin (minimald's
/// `PROXY_SERVING_BEACON`).
#[cfg(any(minvmd_libkrun, test))]
const PROXY_SERVING_LINE: &str = "PROXY_SERVING";

/// One classified connection off the marker socket (T93): the boot beacon —
/// `READY` or `MOUNT_FAILED` — or one of the guest's publish reports. A
/// report carries the publish generation the guest echoed from its boot
/// line, or `None` from a guest too old to echo one.
#[cfg(any(minvmd_libkrun, test))]
#[derive(Debug, PartialEq, Eq)]
enum MarkerEvent {
    /// The boot beacon, exactly as [`crate::cmd::read_ready_beacon`] leaves
    /// it: `Ok(Ready)`, `Ok(MountFailed)`, or the reason the line was none
    /// of them.
    Beacon(Result<crate::cmd::BootBeacon, String>),
    /// The guest published the hostname proxy: it is serving on the port.
    ProxyServing(u16, Option<u64>),
    /// The guest's publish was refused for address-in-use: the port is
    /// taken, and the guest has stopped retrying — the terminal report.
    ProxyPortHeld(u16, Option<u64>),
}

#[cfg(any(minvmd_libkrun, test))]
impl MarkerEvent {
    /// Whether this event is a publish report some other boot sent
    /// ([`report_fate`]); a beacon never is.
    fn is_straggler_for(&self, boot_generation: u64, after_ready: bool) -> bool {
        match self {
            Self::Beacon(..) => false,
            Self::ProxyServing(_, reported) | Self::ProxyPortHeld(_, reported) => {
                report_fate(*reported, boot_generation, after_ready) == ReportFate::Straggler
            }
        }
    }
}

/// What becomes of one publish report the running boot's watch reads (T93).
#[cfg(any(minvmd_libkrun, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportFate {
    /// The running boot's own report: handed to the publish decision.
    Keep,
    /// Another boot's report — a killed boot's, from a redraw or an earlier
    /// start: dropped with a line naming both generations.
    Straggler,
}

/// Whose report this is, by the publish generation the guest echoed
/// (T93). The port cannot tell: a killed boot and the next one are often
/// handed the same port — the preferred one, across starts — while the
/// generation is drawn fresh for every boot. A report carrying this boot's
/// generation is this boot's, before or after READY, since nothing in the
/// marker channel orders a report after the beacon; any other generation is
/// a straggler. A report with no generation comes from a guest too old to
/// echo one: before READY it is a straggler and after READY it is kept —
/// the behaviour that guest was built against, so mixed versions do not
/// regress.
#[cfg(any(minvmd_libkrun, test))]
fn report_fate(reported: Option<u64>, boot_generation: u64, after_ready: bool) -> ReportFate {
    match reported {
        Some(generation) if generation == boot_generation => ReportFate::Keep,
        Some(_) => ReportFate::Straggler,
        None if after_ready => ReportFate::Keep,
        None => ReportFate::Straggler,
    }
}

/// A fresh publish generation for one boot (T93): a discriminator, not a
/// secret, so it need only be distinct per boot, within a start and across
/// starts. `RandomState` seeds from the OS's
/// randomness once per thread and steps per instance; the pid and the clock
/// folded in keep two supervisors apart even if their seeds met.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn draw_publish_generation() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    hasher.finish()
}

/// Bind the host's two box doors beside each other before the guest boots
/// (T66, T94, NET-138): the box-registration control socket at
/// `control_sock_path`, whose accept loop's handle the caller holds for the
/// daemon's life, and the guest report door beside it, answered as the env
/// pair the VMM child registers the door's vsock port from. Either bind
/// failing is the supervisor's startup error, naming the socket and the
/// cause (#1790): under the in-force gate a box with no host row reaches
/// nothing, so there is no interim a boot without its doors could degrade
/// to.
#[cfg_attr(
    not(minvmd_libkrun),
    allow(
        dead_code,
        reason = "only the libkrun boot loop binds the doors, so every other \
                  target compiles them unreached"
    )
)]
fn bind_box_doors(
    control_sock_path: &std::path::Path,
    boxes: &crate::box_registry::BoxRegistry,
    answerer: &crate::net::answerer::AnswererStatus,
    proxy_publish: &crate::control::ProxyPublishStatus,
) -> Result<(
    std::thread::JoinHandle<()>,
    (&'static str, std::path::PathBuf),
)> {
    use anyhow::Context as _;
    let control = crate::control::spawn(
        control_sock_path.to_path_buf(),
        boxes.clone(),
        answerer.clone(),
        proxy_publish.clone(),
    )
    .with_context(|| {
        format!(
            "binding the box-registration control socket at {}; own-address boxes cannot \
             register without it",
            control_sock_path.display()
        )
    })?;
    let guest_report_door =
        guest_report_door_env(control_sock_path, boxes, answerer, proxy_publish).with_context(
            || {
                format!(
                    "binding the guest report door at {}",
                    control_sock_path
                        .with_file_name(crate::control::GUEST_CONTROL_SOCK_FILE)
                        .display()
                )
            },
        )?;
    Ok((control, guest_report_door))
}

/// Bind the guest report door (T94) beside `control_sock_path` and answer
/// the env pair the VMM child registers the door's vsock port at
/// [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`] from — the bridge's two halves
/// as one step, so the door is bound only once the bridge is up. A bind
/// failure answers no env at all, and [`bind_box_doors`] fails the boot on
/// it: no boot bridges a door it did not bind, and no bound door stands
/// behind a bridge that never comes up.
#[cfg_attr(
    not(minvmd_libkrun),
    allow(
        dead_code,
        reason = "only the libkrun boot loop reaches the door's bind, so every other \
                  target compiles it unreached"
    )
)]
fn guest_report_door_env(
    control_sock_path: &std::path::Path,
    boxes: &crate::box_registry::BoxRegistry,
    answerer: &crate::net::answerer::AnswererStatus,
    proxy_publish: &crate::control::ProxyPublishStatus,
) -> std::io::Result<(&'static str, std::path::PathBuf)> {
    let door = crate::control::spawn_guest_reports_door(
        control_sock_path,
        boxes.clone(),
        answerer.clone(),
        proxy_publish.clone(),
    )?;
    Ok((crate::control::GUEST_REPORT_SOCK_ENV, door))
}

/// Parses one publish report's lines (T93): the verb, the port, and the
/// publish generation the guest echoed — an empty third line, which is what
/// a guest too old to echo one leaves, is `None`. `None` overall when the
/// report is malformed: an unknown verb, a port that is not one, or a
/// generation that does not parse.
#[cfg(any(minvmd_libkrun, test))]
fn parse_publish_report(verb: &str, port: &str, generation: &str) -> Option<MarkerEvent> {
    let port = port.trim().parse::<u16>().ok()?;
    let generation = match generation.trim() {
        "" => None,
        raw => Some(raw.parse::<u64>().ok()?),
    };
    match verb.trim() {
        PROXY_PORT_HELD_LINE => Some(MarkerEvent::ProxyPortHeld(port, generation)),
        PROXY_SERVING_LINE => Some(MarkerEvent::ProxyServing(port, generation)),
        _ => None,
    }
}

/// The marker socket's file, removed at the supervisor's exit (T93): the
/// gate keeps the listener accepting past the first beacon, so the path is
/// held for the supervisor's life and taken away once at whatever exit it
/// takes — a failed start, a stop, or a crash that ends the process anyway.
#[cfg(minvmd_libkrun)]
struct MarkerSocketFile(std::path::PathBuf);

#[cfg(minvmd_libkrun)]
impl Drop for MarkerSocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Accepts on the marker socket for the supervisor's life, classifying each
/// connection into one [`MarkerEvent`] for the supervisor's one channel
/// (T93). A report whose port does not parse is warned and dropped: the
/// reports are a courtesy the decisions never hang on, and a malformed one
/// fails nothing on its own.
#[cfg(minvmd_libkrun)]
fn spawn_marker_gate(
    listener: std::os::unix::net::UnixListener,
    known_hosts_path: std::path::PathBuf,
) -> std::sync::mpsc::Receiver<MarkerEvent> {
    let (events, events_rx) = std::sync::mpsc::channel::<MarkerEvent>();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                return; // the listener closed: the supervisor is gone
            };
            let event =
                classify_marker_connection(&mut std::io::BufReader::new(stream), &known_hosts_path);
            match event {
                Some(event) => {
                    if events.send(event).is_err() {
                        return; // the supervisor is gone
                    }
                }
                None => continue,
            }
        }
    });
    events_rx
}

/// Classifies one marker connection by peeking its first line without
/// consuming it (T93): [`crate::cmd::read_ready_beacon`] reads the beacon's
/// own first line, so the gate may only peek. A publish report consumes its
/// two lines here — verb, then port — and anything else is handed to the
/// beacon reader whole. A report's third line is the publish generation,
/// absent from an older guest's report ([`parse_publish_report`]). `None` is
/// a report that did not parse: warned here, dropped, and the connection
/// over with.
#[cfg(minvmd_libkrun)]
fn classify_marker_connection(
    reader: &mut std::io::BufReader<std::os::unix::net::UnixStream>,
    known_hosts_path: &std::path::Path,
) -> Option<MarkerEvent> {
    use std::io::BufRead as _;
    let peeked = reader.fill_buf().ok()?;
    if peeked.starts_with(PROXY_PORT_HELD_LINE.as_bytes())
        || peeked.starts_with(PROXY_SERVING_LINE.as_bytes())
    {
        let mut verb = String::new();
        let mut port = String::new();
        let mut generation = String::new();
        let _ = reader.read_line(&mut verb);
        let _ = reader.read_line(&mut port);
        // The guest half-closes after its report, so an older guest's
        // two-line report ends here at EOF with the line left empty.
        let _ = reader.read_line(&mut generation);
        let event = parse_publish_report(&verb, &port, &generation);
        if event.is_none() {
            tracing::warn!(
                verb = verb.trim(),
                port = port.trim(),
                generation = generation.trim(),
                "a malformed publish report arrived on the marker socket; ignoring it"
            );
        }
        event
    } else {
        Some(MarkerEvent::Beacon(crate::cmd::read_ready_beacon(
            reader,
            known_hosts_path,
        )))
    }
}

/// Waits for this boot's READY beacon, the env-configurable bound around it
/// (T93's redraws reuse it: every fresh boot is a boot). A publish report
/// carrying this boot's generation ([`report_fate`]) is this boot's own —
/// the guest's publish drive runs beside its boot path, and nothing in the
/// marker channel orders the report after READY — so it is kept and
/// returned for the publish watch; any other report is a killed boot's
/// straggler, skipped with a line, never mistaken for the beacon.
#[cfg(minvmd_libkrun)]
fn wait_boot_beacon(
    events: &std::sync::mpsc::Receiver<MarkerEvent>,
    ready_timeout: std::time::Duration,
    boot_generation: u64,
    volume_path: &std::path::Path,
    volume_preexisted: bool,
) -> Result<Option<crate::control::GuestPublish>> {
    let Ok(BootBeaconWait {
        beacon,
        early_report,
    }) = await_boot_beacon(events, ready_timeout, boot_generation)
    else {
        return Err(anyhow::anyhow!(
            "boot timed out waiting for READY marker after {} s (raise {} to wait longer)",
            ready_timeout.as_secs(),
            crate::cmd::READY_TIMEOUT_ENV,
        ));
    };
    match beacon {
        Ok(crate::cmd::BootBeacon::Ready) => Ok(early_report),
        Ok(crate::cmd::BootBeacon::MountFailed { reason }) => Err(crate::cmd::mount_failed_error(
            &reason,
            volume_path,
            volume_preexisted,
        )),
        Err(e) => Err(anyhow::anyhow!("boot failed: {e}")),
    }
}

/// What the READY wait read ([`await_boot_beacon`]): the boot beacon, and
/// this boot's own publish report when it arrived first.
#[cfg(any(minvmd_libkrun, test))]
#[derive(Debug)]
struct BootBeaconWait {
    beacon: Result<crate::cmd::BootBeacon, String>,
    early_report: Option<crate::control::GuestPublish>,
}

/// The channel half of [`wait_boot_beacon`]: reads events until the beacon,
/// keeping the first report this boot sent ([`report_fate`], before READY)
/// and skipping every straggler. `Err` when the bound expires first.
#[cfg(any(minvmd_libkrun, test))]
fn await_boot_beacon(
    events: &std::sync::mpsc::Receiver<MarkerEvent>,
    ready_timeout: std::time::Duration,
    boot_generation: u64,
) -> Result<BootBeaconWait, std::sync::mpsc::RecvTimeoutError> {
    let deadline = std::time::Instant::now() + ready_timeout;
    let mut early_report = None;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(remaining)? {
            MarkerEvent::Beacon(beacon) => {
                return Ok(BootBeaconWait {
                    beacon,
                    early_report,
                });
            }
            event if event.is_straggler_for(boot_generation, false) => {
                log_straggler(
                    &event,
                    boot_generation,
                    "while waiting for the READY marker",
                );
            }
            event => {
                if early_report.is_none() {
                    early_report = publish_report_of(event, boot_generation);
                }
            }
        }
    }
}

/// One line per dropped straggler report (T93): the port it names, the
/// generation it carried, and this boot's generation, so the log says whose
/// report was skipped and why.
#[cfg(any(minvmd_libkrun, test))]
fn log_straggler(event: &MarkerEvent, boot_generation: u64, when: &str) {
    if let MarkerEvent::ProxyServing(port, reported) | MarkerEvent::ProxyPortHeld(port, reported) =
        event
    {
        tracing::warn!(
            port,
            report_generation = %report_generation_field(*reported),
            boot_generation,
            when,
            "skipped a publish report another boot sent"
        );
    }
}

/// How a publish report's generation reads in the log (T93): the
/// generation the guest echoed, or `absent` for a report that carried none —
/// a word, never a number, so a token-less report cannot pass for one.
#[cfg(any(minvmd_libkrun, test))]
fn report_generation_field(reported: Option<u64>) -> String {
    reported.map_or_else(|| "absent".to_owned(), |generation| generation.to_string())
}

/// A kept publish report as the decision reads it, re-probed host-side and
/// logged (T93), so the daemon's log names the outcome the supervisor
/// *checked* for the port, not only the one the guest claimed — and the
/// generation the report carried beside this boot's, so a report that lost
/// its generation on the way is visible, not silently kept. `None` for a
/// beacon.
#[cfg(any(minvmd_libkrun, test))]
fn publish_report_of(
    event: MarkerEvent,
    boot_generation: u64,
) -> Option<crate::control::GuestPublish> {
    match event {
        MarkerEvent::ProxyServing(published, reported) => {
            tracing::info!(
                port = published,
                port_answers = loopback_answers(published),
                report_generation = %report_generation_field(reported),
                boot_generation,
                "the guest published the hostname proxy; re-probed the port"
            );
            Some(crate::control::GuestPublish::Serving { port: published })
        }
        MarkerEvent::ProxyPortHeld(held, reported) => {
            tracing::info!(
                port = held,
                port_answers = loopback_answers(held),
                report_generation = %report_generation_field(reported),
                boot_generation,
                "the guest's publish was refused for address-in-use; re-probed the port"
            );
            Some(crate::control::GuestPublish::PortHeld { port: held })
        }
        MarkerEvent::Beacon(..) => None,
    }
}

/// How long the supervisor waits for the guest's publish reports after the
/// READY beacon (T93). The reports settle within the guest's own first
/// publish attempt — the proxy task starts with the daemon's serve loop,
/// and its expose rides the shuttle — so this is only the bound that keeps
/// a guest that never reports (a degraded boot whose publish keeps its
/// existing backoff) from stalling the start; a healthy boot's report ends
/// the watch early.
#[cfg(minvmd_libkrun)]
const PUBLISH_WATCH_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// How much longer the watch waits for the guest's report when the bound
/// expired with the port answering but its holder unnameable (T93): a short
/// grace, because ambiguity alone must never redraw, and the report is the
/// one voice that can settle it.
#[cfg(minvmd_libkrun)]
const NO_REPORT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Watches what became of the port this start reserved (T93): the guest's
/// report — serving, or refused for address-in-use — or, at the bound, the
/// supervisor's own identification of the port's holder. Whichever report
/// arrives is re-probed host-side and the check logged, so the daemon's log
/// names the publish outcome the supervisor *checked* for the port, not only
/// the one the guest claimed; and nothing the guest says changes which port
/// is reserved — the report names a fact, the reservation is the
/// supervisor's own and moves only by its own decision. Only this boot's
/// report counts ([`report_fate`]): `early_report` is the one the READY
/// wait already kept, and the watch reads it first.
///
/// With no report at the bound, the holder decides
/// ([`crate::control::NoReportHolder`]): a listener whose pid is one of
/// `own_pids` — the processes this supervisor spawned for this VM — is this
/// VM's own late publish; any other named pid is another process holding
/// the port; and a listener the host will not name earns a short grace
/// ([`NO_REPORT_GRACE`]) for the report before the watch calls it unknown.
#[cfg(minvmd_libkrun)]
fn watch_proxy_publish(
    port: u16,
    events: &std::sync::mpsc::Receiver<MarkerEvent>,
    own_pids: &[u32],
    boot_generation: u64,
    early_report: Option<crate::control::GuestPublish>,
) -> crate::control::GuestPublish {
    use crate::control::{GuestPublish, NoReportHolder, classify_no_report_holder};
    // This boot's report, when it beat READY: the READY wait already kept
    // and re-probed it.
    if let Some(reported) = early_report {
        return reported;
    }
    if let Some(reported) = await_publish_report(events, PUBLISH_WATCH_BOUND, boot_generation) {
        return reported;
    }
    let port_answers = loopback_answers(port);
    let holder_found = if port_answers {
        port_holder(port)
    } else {
        None
    };
    let holder = classify_no_report_holder(
        port_answers,
        holder_found.as_ref().map(|(pid, _)| *pid),
        own_pids,
    );
    let holder_named = holder_found.as_ref().map(|(_, named)| named.as_str());
    match holder {
        NoReportHolder::OwnForwarder => tracing::warn!(
            port,
            holder = holder_named.unwrap_or(""),
            "the guest's publish report was late: this VM's own forwarder holds \
             the port, so the publish landed"
        ),
        NoReportHolder::Foreign => tracing::warn!(
            port,
            holder = holder_named.unwrap_or(""),
            "the publish watch expired without the guest's report and another \
             process holds the port"
        ),
        NoReportHolder::NotAnswering => tracing::warn!(
            port,
            "the publish watch expired without the guest's report and nothing \
             answers on the port"
        ),
        NoReportHolder::Unknown => {
            tracing::warn!(
                port,
                grace_secs = NO_REPORT_GRACE.as_secs(),
                "the publish watch expired without the guest's report and the \
                 port's holder cannot be named; waiting a short grace for the report"
            );
            if let Some(reported) = await_publish_report(events, NO_REPORT_GRACE, boot_generation) {
                return reported;
            }
        }
    }
    GuestPublish::NoReport { port, holder }
}

/// The guest's publish report, if one arrives inside `bound` (T93): served,
/// or refused for address-in-use, each re-probed and logged
/// ([`publish_report_of`]). A report another boot sent ([`report_fate`],
/// after READY) is skipped with a line, and so is a beacon inside the wait —
/// a straggler from a redraw's killed boot, since this boot's beacon is
/// already read. `None` at the bound.
#[cfg(any(minvmd_libkrun, test))]
fn await_publish_report(
    events: &std::sync::mpsc::Receiver<MarkerEvent>,
    bound: std::time::Duration,
    boot_generation: u64,
) -> Option<crate::control::GuestPublish> {
    let deadline = std::time::Instant::now() + bound;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(remaining) {
            Ok(MarkerEvent::Beacon(..)) => continue,
            Ok(event) if event.is_straggler_for(boot_generation, true) => {
                log_straggler(&event, boot_generation, "while watching the publish");
            }
            Ok(event) => return publish_report_of(event, boot_generation),
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    // BEP-043: the daemon's start path sends a live box's revocation to the
    // proxy's control socket under the home directory.
    #[test]
    fn supervisor_registry_sends_revocations_to_the_home_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let registry = super::supervisor_registry(
            crate::bep_attach::Attachments::new(),
            false,
            dir.path().join("registry.json"),
        );
        assert_eq!(
            registry.proxy_control(),
            crate::box_registry::home_proxy_control().as_deref()
        );
        assert!(registry.proxy_control().is_some());
    }

    #[cfg(not(minvmd_libkrun))]
    use super::*;

    #[cfg(not(minvmd_libkrun))]
    #[test]
    fn run_bails_without_libkrun() {
        let err = run(false, None, tracing::Span::none().entered()).unwrap_err();
        assert!(
            err.to_string().contains("requires libkrun"),
            "expected libkrun-required message, got: {err}"
        );
    }

    #[cfg(not(minvmd_libkrun))]
    #[test]
    fn run_rejects_timeout_without_detach() {
        let err = run(false, Some(5), tracing::Span::none().entered()).unwrap_err();
        assert!(
            err.to_string()
                .contains("`--timeout` only applies with `--detach`"),
            "expected --timeout guard message, got: {err}"
        );
    }

    fn exited(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(code << 8)
    }

    /// The marker channel as the gate feeds it: every event already sent,
    /// the sender dropped, so a wait reads them in order and then ends.
    fn marker_channel(
        events: Vec<super::MarkerEvent>,
    ) -> std::sync::mpsc::Receiver<super::MarkerEvent> {
        let (tx, rx) = std::sync::mpsc::channel();
        for event in events {
            tx.send(event).unwrap();
        }
        rx
    }

    fn ready() -> super::MarkerEvent {
        super::MarkerEvent::Beacon(Ok(crate::cmd::BootBeacon::Ready))
    }

    const WAIT: std::time::Duration = std::time::Duration::from_millis(200);

    #[test]
    fn a_publish_refusal_before_ready_is_not_dropped() {
        // T93: the guest's publish drive runs beside its boot path, so this
        // boot's refusal can reach the marker channel before READY. It
        // carries this boot's generation, so the READY wait keeps it, the
        // watch reads it, and the decision redraws the drawn port instead
        // of calling the publish unconfirmed.
        let (port, generation) = (7654, 41);
        let events = marker_channel(vec![
            super::MarkerEvent::ProxyPortHeld(port, Some(generation)),
            ready(),
        ]);
        let wait = super::await_boot_beacon(&events, WAIT, generation).unwrap();
        assert_eq!(wait.beacon, Ok(crate::cmd::BootBeacon::Ready));
        let outcome = wait.early_report;
        assert_eq!(
            outcome,
            Some(crate::control::GuestPublish::PortHeld { port })
        );
        assert_eq!(
            crate::control::decide_publish(true, 1, outcome.unwrap()),
            crate::control::PublishDecision::Redraw { port },
            "a drawn port the guest found taken is redrawn"
        );
    }

    #[test]
    fn a_killed_boots_report_with_the_same_port_is_dropped() {
        // A killed boot and the next one are often handed the same port, so
        // only the generation tells them apart: the killed boot's report is
        // skipped before READY and after it, and the watch proceeds to this
        // boot's own report.
        let (port, killed, current) = (7654, 7, 8);
        let events = marker_channel(vec![
            super::MarkerEvent::ProxyPortHeld(port, Some(killed)),
            ready(),
            super::MarkerEvent::ProxyPortHeld(port, Some(killed)),
            super::MarkerEvent::ProxyServing(port, Some(current)),
        ]);
        let wait = super::await_boot_beacon(&events, WAIT, current).unwrap();
        assert_eq!(wait.beacon, Ok(crate::cmd::BootBeacon::Ready));
        assert_eq!(
            wait.early_report, None,
            "the killed boot's report is dropped"
        );
        assert_eq!(
            super::await_publish_report(&events, WAIT, current),
            Some(crate::control::GuestPublish::Serving { port }),
            "the watch skips the straggler and reads this boot's report"
        );
    }

    #[test]
    fn an_older_guests_tokenless_report_counts_only_after_ready() {
        // A guest too old to echo a generation: before READY its report is
        // a straggler, after READY it is the running boot's — today's
        // behaviour, so mixed versions do not regress.
        let port = 7654;
        let events = marker_channel(vec![
            super::MarkerEvent::ProxyServing(port, None),
            ready(),
            super::MarkerEvent::ProxyPortHeld(port, None),
        ]);
        let wait = super::await_boot_beacon(&events, WAIT, 3).unwrap();
        assert_eq!(wait.early_report, None);
        assert_eq!(
            super::await_publish_report(&events, WAIT, 3),
            Some(crate::control::GuestPublish::PortHeld { port })
        );
    }

    #[test]
    fn report_fate_keeps_only_the_running_boots_reports() {
        use super::{ReportFate, report_fate};
        assert_eq!(report_fate(Some(5), 5, false), ReportFate::Keep);
        assert_eq!(report_fate(Some(5), 5, true), ReportFate::Keep);
        assert_eq!(report_fate(Some(4), 5, false), ReportFate::Straggler);
        assert_eq!(report_fate(Some(4), 5, true), ReportFate::Straggler);
        assert_eq!(report_fate(None, 5, false), ReportFate::Straggler);
        assert_eq!(report_fate(None, 5, true), ReportFate::Keep);
    }

    #[test]
    fn a_publish_report_parses_with_its_generation() {
        assert_eq!(
            super::parse_publish_report("PROXY_PORT_HELD\n", "7654\n", "123\n"),
            Some(super::MarkerEvent::ProxyPortHeld(7654, Some(123)))
        );
        assert_eq!(
            super::parse_publish_report("PROXY_SERVING\n", "7654\n", "123\n"),
            Some(super::MarkerEvent::ProxyServing(7654, Some(123)))
        );
    }

    #[test]
    fn a_publish_report_without_a_generation_still_parses() {
        // An older guest's two-line report: the third read meets EOF.
        assert_eq!(
            super::parse_publish_report("PROXY_PORT_HELD\n", "7654\n", ""),
            Some(super::MarkerEvent::ProxyPortHeld(7654, None))
        );
        assert_eq!(
            super::parse_publish_report("PROXY_SERVING\n", "7654\n", ""),
            Some(super::MarkerEvent::ProxyServing(7654, None))
        );
    }

    #[test]
    fn a_malformed_publish_report_is_rejected() {
        assert_eq!(super::parse_publish_report("PROXY_SERVING", "x", ""), None);
        assert_eq!(
            super::parse_publish_report("PROXY_SERVING", "7654", "x"),
            None
        );
        assert_eq!(super::parse_publish_report("PROXY_ELSE", "7654", ""), None);
    }

    #[test]
    fn a_report_generation_logs_as_its_number_or_absent() {
        assert_eq!(super::report_generation_field(Some(41)), "41");
        assert_eq!(
            super::report_generation_field(Some(u64::MAX)),
            u64::MAX.to_string()
        );
        assert_eq!(super::report_generation_field(None), "absent");
    }

    #[test]
    fn every_boot_draws_its_own_publish_generation() {
        assert_ne!(
            super::draw_publish_generation(),
            super::draw_publish_generation()
        );
    }

    #[test]
    fn detach_poll_ready_predicate_wins_over_child_exit() {
        // The child exited, but the readiness predicate already holds: the VM
        // is serving, so this is success regardless of the exit.
        assert!(matches!(
            super::classify_detach_poll(true, Some(exited(1)), true, None, false),
            super::DetachPoll::Ready
        ));
    }

    #[test]
    fn detach_poll_lost_race_keeps_waiting() {
        // The supervisor exited because a peer already holds the alive lock —
        // the winner is still coming up. Keep waiting rather than reporting a
        // startup failure that isn't one. The recorded VMM pid is not alive
        // (None, or a pid that doesn't exist), so this is a genuine race, not
        // a leak.
        assert!(matches!(
            super::classify_detach_poll(false, Some(exited(1)), true, None, false),
            super::DetachPoll::Keep
        ));
    }

    #[test]
    fn detach_poll_child_exit_without_daemon_is_failure() {
        // Child exited and nothing holds the alive lock: a genuine startup
        // failure, still surfaced as an error.
        assert!(matches!(
            super::classify_detach_poll(false, Some(exited(1)), false, None, false),
            super::DetachPoll::Failed(_)
        ));
    }

    #[test]
    fn detach_poll_leaked_vmm_detected() {
        // The supervisor exited but the alive lock is still held AND the
        // recorded VMM pid is still alive: the VMM is orphaned. Fail fast
        // with the leaked pid.
        let my_pid = std::process::id();
        assert!(matches!(
            super::classify_detach_poll(false, Some(exited(1)), true, Some(my_pid), false),
            super::DetachPoll::LeakedVmm(pid) if pid == my_pid
        ));
    }

    #[test]
    fn detach_poll_competing_supervisor_vmm_is_not_a_leak() {
        // The supervisor exited but the alive lock is still held AND the
        // recorded VMM pid is still alive. However, that VMM's parent is a
        // live supervisor (a competing supervisor that won the autospawn
        // race), so this is not a leak — keep waiting for the winner to serve.
        let my_pid = std::process::id();
        assert!(matches!(
            super::classify_detach_poll(false, Some(exited(1)), true, Some(my_pid), true),
            super::DetachPoll::Keep
        ));
    }

    #[test]
    fn detach_poll_dead_vmm_pid_is_not_a_leak() {
        // The supervisor exited, daemon is alive, but the recorded VMM pid
        // is no longer running (e.g. a stale state file). This is not a
        // leaked VMM — keep waiting (autospawn race).
        // Use a pid that almost certainly doesn't exist. `u32::MAX` would
        // wrap to -1 as `pid_t`, which `kill(-1, 0)` treats as "all
        // processes" and would wrongly report alive; `i32::MAX` stays
        // positive and is above any real `pid_max`.
        assert!(matches!(
            super::classify_detach_poll(false, Some(exited(1)), true, Some(i32::MAX as u32), false),
            super::DetachPoll::Keep
        ));
    }

    #[cfg(minvmd_libkrun)]
    #[test]
    fn detach_poll_cannot_determine_owner_keeps_waiting() {
        // When `vmm_owned_by_live_supervisor` cannot determine ownership
        // (e.g. macOS where /proc/<pid>/stat doesn't exist, or any OS where
        // the lookup fails), it returns `true` — treat the VMM as owned and
        // keep waiting rather than misclassifying a healthy booting VMM as
        // leaked. This test uses a pid that doesn't exist, so the parent-pid
        // lookup will fail, and the function should return `true`.
        let nonexistent = i32::MAX as u32;
        assert!(
            super::vmm_owned_by_live_supervisor(nonexistent),
            "cannot-determine-owner must return true (keep waiting)"
        );
    }

    #[cfg(minvmd_libkrun)]
    #[test]
    fn vmm_with_live_non_init_parent_is_owned() {
        // Our own process has a live parent (the test runner) that is not
        // init, so it counts as owned on every platform — on macOS this
        // needs the proc_pidinfo lookup, since /proc does not exist there.
        // SAFETY: getppid() has no preconditions and cannot fail.
        if unsafe { libc::getppid() } == 1 {
            // Running as a direct child of init (e.g. a container pid-1
            // runner): the premise does not hold.
            return;
        }
        assert!(super::vmm_owned_by_live_supervisor(std::process::id()));
    }

    #[cfg(minvmd_libkrun)]
    #[test]
    fn parent_pid_of_own_process_is_consistent() {
        // The lookup for our own pid must agree with getppid(). This
        // exercises the platform's parent-pid path (proc_pidinfo on macOS,
        // /proc/<pid>/stat on Linux).
        // SAFETY: getppid() has no preconditions and cannot fail.
        let expected = unsafe { libc::getppid() } as u32;
        assert_eq!(super::parent_pid(std::process::id()), Some(expected));
    }

    #[test]
    fn node_port_probe_skips_a_port_served_on_loopback() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // The hostname surface a VM holds on the host is the loopback address
        // (minimald's proxy binds `127.0.0.1:<port>`), so the port one VM is
        // serving on is exactly the port the next VM wants: the assignment has
        // to skip it. Hold it the way the holder really does — on the loopback
        // address alone, not the wildcard. One VM keeps its surface and the
        // other is handed a port that is nobody else's, and the assignment's
        // log line says which probe refused it.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let served = held.local_addr().unwrap().port();
        assert!(
            super::loopback_answers(served),
            "the loopback probe sees the listener on 127.0.0.1:{served}"
        );
        let assigned = super::assign_node_port(ports.path(), served, false).unwrap();
        assert_ne!(
            assigned.port, served,
            "a port another VM is serving on loopback is not handed as-is"
        );
        assert!(
            matches!(
                assigned.skipped,
                Some(super::SKIP_BIND_REFUSED) | Some(super::SKIP_LOOPBACK_ANSWERING)
            ),
            "the skip names the probe that refused it, got: {:?}",
            assigned.skipped
        );
    }

    #[test]
    fn node_port_bind_probe_refuses_a_port_held_on_loopback() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // The bind probe alone reports a port another VM serves on
        // `127.0.0.1` as taken, on macOS as on Linux: std's SO_REUSEADDR lets
        // a macOS wildcard bind succeed over that listener, so the probe binds
        // the loopback address itself, where the flag masks nothing.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let served = held.local_addr().unwrap().port();
        let refused = super::tcp_bind_probe(served).unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::AddrInUse,
            "the bind probe reports 127.0.0.1:{served} as taken"
        );
        let assigned = super::assign_node_port(ports.path(), served, false).unwrap();
        assert_ne!(assigned.port, served, "the served port is not handed");
        assert_eq!(
            assigned.skipped,
            Some(super::SKIP_BIND_REFUSED),
            "the bind probe, not the connect backstop, refuses it"
        );

        // A wildcard holder is taken too: on macOS a loopback bind with
        // SO_REUSEADDR succeeds over it, which the wildcard half catches.
        let held_any = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let served_any = held_any.local_addr().unwrap().port();
        let refused_any = super::tcp_bind_probe(served_any).unwrap_err();
        assert_eq!(
            refused_any.kind(),
            std::io::ErrorKind::AddrInUse,
            "the bind probe reports a wildcard holder of {served_any} as taken"
        );
    }

    #[test]
    fn node_port_probe_keeps_a_free_preferred_port() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // A port with nothing on it is handed as asked: the loopback half of
        // the TCP probe refuses nothing that is actually free, so a lone VM
        // still lands on the default proxy port — the case the session e2e's
        // hardcoded 7654 depends on.
        let freed = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let free = freed.local_addr().unwrap().port();
        drop(freed);
        assert!(
            !super::loopback_answers(free),
            "the loopback probe leaves a free port alone"
        );
        let assigned = super::assign_node_port(ports.path(), free, false).unwrap();
        assert_eq!(
            assigned.port, free,
            "a free preferred port is handed unchanged"
        );
        assert_eq!(
            assigned.preferred, free,
            "the preferred port is the one the assignment was asked for"
        );
        assert_eq!(
            assigned.skipped, None,
            "a free port is not skipped, and says so"
        );

        // The answerer's UDP probe is unchanged by the TCP probe's second
        // check: a free UDP port is handed as asked.
        let freed_udp = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let free_udp = freed_udp.local_addr().unwrap().port();
        drop(freed_udp);
        let assigned_udp = super::assign_node_port(ports.path(), free_udp, true).unwrap();
        assert_eq!(
            assigned_udp.port, free_udp,
            "a free UDP preferred port is handed unchanged"
        );
    }

    #[test]
    fn node_port_fallback_skips_a_candidate_served_on_loopback() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // The OS-assigned fallback draws its candidates under the same
        // SO_REUSEADDR semantics the wildcard bind carries, so on macOS a draw
        // can land on a port another VM's hostname surface already serves on
        // the loopback address — the very collision the preferred-port probes
        // exist to prevent. The candidate source is injected here because the
        // OS cannot be asked for a particular draw, and the sequence is one
        // served draw before a free one: the fallback has to release the
        // served candidate and hand the free one, never the served draw as-is.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let served = held.local_addr().unwrap().port();
        assert!(
            super::loopback_answers(served),
            "the loopback probe sees the listener on 127.0.0.1:{served}"
        );
        // A candidate no listener answers at, drawn from the same OS the
        // production picker draws from and released before use — and redrawn
        // in the one case the draw lands on the port this test holds, which
        // is a real shape on macOS (see [`super::loopback_answers`]).
        let free = (0..16)
            .map(|_| {
                let draw = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
                let port = draw.local_addr().unwrap().port();
                drop(draw);
                port
            })
            .find(|port| *port != served && !super::loopback_answers(*port))
            .expect("a candidate with no listener answering on loopback");
        let candidates = [served, free];
        let mut drawn = candidates.into_iter();
        let (handed, _reservation) =
            super::fallback_port(ports.path(), || Ok(drawn.next().unwrap()), false).unwrap();
        assert_eq!(
            handed, free,
            "the fallback hands the first candidate no listener answers on"
        );
    }

    #[test]
    fn node_port_fallback_fails_when_every_drawn_candidate_is_served() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // A host whose every draw lands on a served port fails the boot naming
        // the conflict: handing the candidate anyway would hand two VMs one
        // hostname surface, which is the collision this assignment exists to
        // prevent. The refusal is bounded, not a spin.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let served = held.local_addr().unwrap().port();
        let mut drawn = 0usize;
        let err = super::fallback_port(
            ports.path(),
            || {
                drawn += 1;
                Ok(served)
            },
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("answering on loopback"),
            "the refusal names the conflict, got: {err}"
        );
        assert_eq!(
            drawn,
            super::FALLBACK_PORT_ATTEMPTS,
            "the fallback gives up after its bounded attempts, it does not spin"
        );
    }

    #[test]
    fn node_port_fallback_hands_udp_candidates_without_the_loopback_probe() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // The answerer's UDP probe is unchanged on the fallback path too: a
        // UDP socket never accepts a connection, so a listener answering TCP on
        // the loopback address is no conflict for it and the first candidate
        // drawn is handed as drawn.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let served = held.local_addr().unwrap().port();
        assert!(
            super::loopback_answers(served),
            "the loopback probe sees the listener on 127.0.0.1:{served}"
        );
        let mut drawn = 0usize;
        let (handed, _reservation) = super::fallback_port(
            ports.path(),
            || {
                drawn += 1;
                Ok(served)
            },
            true,
        )
        .unwrap();
        assert_eq!(handed, served, "the UDP fallback hands the first draw");
        assert_eq!(drawn, 1, "one candidate drawn, no TCP probe applied to it");
    }

    #[test]
    fn node_port_assigned_on_host_and_handed_to_daemon() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // A port the test holds is busy: the assignment falls through to an
        // OS-assigned port rather than failing the boot over a shared-host
        // conflict — the case of a native daemon and a VM on one host. The
        // hold is on the wildcard address the assigner itself probes, so the
        // collision is one every host agrees on: a specific-address hold
        // collides with a wildcard probe on Linux and not everywhere else.
        // The loopback-address hold — the shape a second VM's own hostname
        // surface has — is the two tests above.
        let held = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let busy = held.local_addr().unwrap().port();
        let assigned = super::assign_node_port(ports.path(), busy, false).unwrap();
        assert_ne!(assigned.port, busy, "a held port is not assigned as-is");
        assert!(assigned.port != 0, "the fallback is a real port");

        // A port the test just released is free again: the default-first
        // probe assigns it as asked — the case the session e2e's hardcoded
        // default proxy port depends on. Released on the wildcard the probe
        // addresses, like the hold above.
        let freed = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let free = freed.local_addr().unwrap().port();
        drop(freed);
        assert_eq!(
            super::assign_node_port(ports.path(), free, false)
                .unwrap()
                .port,
            free,
            "a free port is assigned as asked"
        );

        // The supervisor assigns the proxy port and hands it to the guest:
        // whatever the host picked, it is a real port the guest can bind as
        // handed (the cmdline and bind halves are the vm.rs and minimald
        // tests of the same name).
        let assigned = super::assign_node_proxy_port(ports.path()).unwrap();
        assert!(assigned.port != 0, "the node's proxy port is assigned");

        // The answerer's probe is the same default-first over UDP, held on
        // the same wildcard the UDP probe addresses.
        let held_udp = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let busy_udp = held_udp.local_addr().unwrap().port();
        let assigned_udp = super::assign_node_port(ports.path(), busy_udp, true).unwrap();
        assert_ne!(
            assigned_udp.port, busy_udp,
            "a held UDP port is not assigned as-is"
        );

        // The operator's override resolves the port, and the one resolved
        // port is written twice from the same value: handed to the guest
        // through the VMM child's env, and declared as the node row's own
        // publish. The pin is held to the same checks a drawn port is
        // (T93), so pin a port this test knows is free — and the one
        // resolved port is what both the handoff and the row carry.
        let previous = std::env::var(crate::vm::NODE_PROXY_PORT_ENV).ok();
        let freed_pin = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let pin = freed_pin.local_addr().unwrap().port();
        drop(freed_pin);
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, pin.to_string()) };
        let pinned = super::assign_node_proxy_port(ports.path()).unwrap();
        assert_eq!(pinned.port, pin, "the override is the resolution");
        assert!(
            pinned.configured,
            "the assignment says the port came from the pin"
        );
        let registry = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let node = registry.register_node_namespace(pinned.port);
        assert_eq!(
            node.admitted_ports(),
            [pin],
            "the row publishes the port the guest is handed — the hostname \
             proxy only, the answerer is not the node's to admit (NET-138)"
        );

        // A pin some check refuses fails the start naming the port and the
        // holder (T93): the configured port never redraws, so there is no
        // fallback to a port the operator did not pin.
        let held_pin = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let refused_pin = held_pin.local_addr().unwrap().port();
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, refused_pin.to_string()) };
        let err = super::assign_node_proxy_port(ports.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("hostname proxy port {refused_pin} held by"))
                && err.contains("configured ports never redraw")
                && err.contains(super::SKIP_BIND_REFUSED),
            "a held pin fails the start naming the port and why, got: {err}"
        );
        // The holder is this test process, by pid: the listener is its own.
        assert!(
            err.contains(&format!("pid {}", std::process::id())),
            "a held pin names the holder's pid, got: {err}"
        );
        drop(held_pin);

        // The override's own garbage fails at the supervisor, naming the
        // variable and the value — never a fallback to selection that would
        // hand the guest a port different from the one the operator pinned.
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, "no-port-here") };
        let err = super::assign_node_proxy_port(ports.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("MINVMD_NODE_PROXY_PORT") && err.contains("no-port-here"),
            "an undecodable override names the variable and the value, got: {err}"
        );
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, "0") };
        let err = super::assign_node_proxy_port(ports.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a port to pin"),
            "a zero override is refused, got: {err}"
        );
        match &previous {
            Some(previous) => unsafe {
                std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, previous)
            },
            None => unsafe { std::env::remove_var(crate::vm::NODE_PROXY_PORT_ENV) },
        }
    }

    #[test]
    fn detach_error_names_proxy_port_and_holder() {
        // The supervisor's start failure, as its stderr lands in run.log —
        // anyhow's `Error:` framing and the boot's context above it — is the
        // line the detaching parent lifts for the CLI (T93).
        let failure = super::proxy_port_failure(7654, "pid 4242 (python3)", "why");
        let err = anyhow::anyhow!("{failure}").context("assigning the node's proxy port");
        let log = format!("some gvproxy line\nError: {err:?}\n");
        assert_eq!(
            super::proxy_failure_line(&log),
            Some("hostname proxy port 7654 held by pid 4242 (python3); why"),
            "the failure line is lifted whole, framing dropped, from: {log}"
        );
        assert_eq!(
            super::proxy_failure_line("Error: boot timed out\n"),
            None,
            "a start that failed on something else lifts nothing"
        );
    }

    /// A preferred port something holds is skipped with `bind refused`, and
    /// the same draw hands it back once the holder releases it. This pins
    /// only the draw's half of the reap-before-draw fix: the order of the
    /// reap and the draw in `run_foreground` needs a real VM, so only the
    /// e2e lanes check it.
    #[test]
    fn node_port_draw_skips_a_held_preferred_port_and_hands_it_back_once_released() {
        // The preferred port: hold it on the loopback the TCP probe
        // addresses, so the first draw sees it refused.
        let stale = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let default = stale.local_addr().unwrap().port();
        let ports = tempfile::tempdir().expect("a test reservation dir");
        let drawn_before = super::assign_node_port(ports.path(), default, false).unwrap();
        assert_eq!(drawn_before.preferred, default);
        assert_eq!(drawn_before.skipped, Some(super::SKIP_BIND_REFUSED));
        assert_ne!(
            drawn_before.port, default,
            "the held default is not handed to the proxy"
        );

        // Release the holder, and the same draw hands the port back.
        drop(stale);
        let drawn_after = super::assign_node_port(ports.path(), default, false).unwrap();
        assert_eq!(drawn_after.port, default);
        assert_eq!(drawn_after.skipped, None);
    }

    /// The holder lookup names the pid of a listener in another process —
    /// procfs on Linux, `lsof` on macOS — which is what the publish watch
    /// matches against the pids this supervisor spawned (T93).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn port_holder_identifies_a_child_listener_pid() {
        use std::io::BufRead;
        // A separate process listening on a port it draws itself, printing
        // its own pid and the port once it listens (its own pid, not the
        // spawned one: a python3 shim may re-exec); it exits when its stdin
        // closes.
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                "import os, socket, sys\n\
                 s = socket.socket()\n\
                 s.bind(('127.0.0.1', 0))\n\
                 s.listen()\n\
                 print(os.getpid(), s.getsockname()[1], flush=True)\n\
                 sys.stdin.read()\n",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("python3 runs the child listener");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().expect("the child's stdout"))
            .read_line(&mut line)
            .expect("the child prints its pid and port");
        let mut fields = line.split_whitespace();
        let pid: u32 = fields
            .next()
            .and_then(|f| f.parse().ok())
            .expect("the child's pid");
        let port: u16 = fields
            .next()
            .and_then(|f| f.parse().ok())
            .expect("the child's port");
        let holder = super::port_holder(port);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            holder.map(|(pid, _)| pid),
            Some(pid),
            "the holder is the child that listens on 127.0.0.1:{port}"
        );
    }

    /// A lookup tool that is missing or fails names no holder: `None`, which
    /// the publish watch classifies as unknown, never as foreign
    /// (`control::tests::no_report_unknown_or_silent_is_up_unconfirmed` covers
    /// `classify_no_report_holder(true, None, ..)`).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn port_holder_is_none_when_the_lookup_fails() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a listener");
        let port = listener.local_addr().expect("its address").port();
        let missing = std::path::Path::new("/nonexistent/port-holder-tool");
        assert_eq!(
            super::port_holder_with(missing, port),
            None,
            "a missing lookup tool names no holder"
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            super::port_holder_with(std::path::Path::new("/usr/bin/false"), port),
            None,
            "a failing lsof names no holder"
        );
        #[cfg(target_os = "linux")]
        {
            // The listener is visible in the tables, but no process's fds
            // are readable: the host would not name the holder.
            let proc = tempfile::tempdir().expect("a fake procfs");
            std::fs::create_dir(proc.path().join("net")).expect("its net dir");
            for table in ["tcp", "tcp6"] {
                std::fs::copy(
                    std::path::Path::new("/proc/net").join(table),
                    proc.path().join("net").join(table),
                )
                .expect("the real socket table");
            }
            assert_eq!(
                super::port_holder_with(proc.path(), port),
                None,
                "a listener whose holder the host will not show names no holder"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lsof_output_names_the_holder() {
        assert_eq!(
            super::lsof_holder("p4242\ncpython3\nf3\n"),
            Some((4242, "pid 4242 (python3)".to_string()))
        );
        assert_eq!(super::lsof_holder(""), None);
    }

    #[test]
    fn an_absent_ports_base_is_created_private() {
        use std::os::unix::fs::PermissionsExt as _;
        // The base is the per-user run dir the zone answerer's interim
        // channel binds in, and that bind refuses a dir open to group or
        // other: a base created under the umask's mode (0755) would leave
        // the interim with no channel for another state dir's node.
        let root = tempfile::tempdir().expect("a test runtime dir");
        let base = root.path().join("minimal");
        let ports = super::node_ports_dir_in(&base, false).expect("the ports dir is made");
        assert_eq!(ports, base.join("ports"));
        for dir in [&base, &ports] {
            let mode = std::fs::metadata(dir)
                .expect("the dir exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{} is created 0700", dir.display());
        }
    }

    #[test]
    fn an_owned_wide_ports_base_is_tightened() {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        // A base an earlier build left at the umask's mode keeps the
        // interim channel from binding; the next boot tightens it.
        let root = tempfile::tempdir().expect("a test runtime dir");
        let base = root.path().join("minimal");
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&base)
            .expect("a wide base");
        super::node_ports_dir_in(&base, false).expect("the ports dir is made");
        let mode = std::fs::metadata(&base)
            .expect("the base exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "{} is tightened to 0700",
            base.display()
        );
    }

    #[test]
    fn concurrent_boots_never_draw_the_same_proxy_port() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // Two supervisors drawing at the same moment contend for the port in
        // the kernel (T93): the flock is held by the open file description,
        // so the second draw — another thread here, another process in
        // production — finds the first's reservation held, skips the port
        // with its reason, and draws again. Exactly one walk lands on the
        // preferred port and the two never share one, whatever the OS's own
        // draws would have handed.
        let freed = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let preferred = freed.local_addr().unwrap().port();
        drop(freed);

        // One shared dir, as two supervisors of one user share theirs.
        let (dir_a, dir_b) = (ports.path().to_path_buf(), ports.path().to_path_buf());
        let first =
            std::thread::spawn(move || super::assign_node_port(&dir_a, preferred, false).unwrap());
        let second =
            std::thread::spawn(move || super::assign_node_port(&dir_b, preferred, false).unwrap());
        let first = first.join().expect("the first draw finishes");
        let second = second.join().expect("the second draw finishes");

        assert_ne!(
            first.port, second.port,
            "two boots drawing at the same moment never take the same port"
        );
        assert!(
            (first.port == preferred) != (second.port == preferred),
            "exactly one draw lands on the preferred port — the reservation, not \
             the probes, is the arbiter (first {}, second {preferred})",
            first.port
        );
        let loser = if first.port == preferred {
            &second
        } else {
            &first
        };
        // The loser's skip reason is whichever check it lost to: the
        // reservation when both walks' probes passed, or a bind probe that
        // collided with the winner's own probe — which holds the port
        // momentarily. Both are the draw telling the host why it moved on;
        // the invariant the test owns is the one above: the two walks never
        // share a port, and the reservation (the test below) is what keeps
        // it that way when the probes both pass.
        assert!(
            matches!(
                loser.skipped,
                Some(super::SKIP_RESERVED_BY_ANOTHER_VM) | Some(super::SKIP_BIND_REFUSED)
            ),
            "the draw that moved on says why, got {:?}",
            loser.skipped
        );
    }

    #[test]
    fn reservation_is_released_when_the_vm_stops() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // The reservation is the supervisor's open file, no pid file and no
        // stale entry to clean (T93): held, a second supervisor's take is
        // refused; dropped — the VM stopped, the supervisor exited, or it
        // crashed and the kernel closed the fd — the same port is free to
        // the next boot's take. The lock file itself stays: minimal never
        // unlinks one, because the lock is the flock on it, and a file no
        // process holds a lock on reserves nothing.
        let freed = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = freed.local_addr().unwrap().port();
        drop(freed);

        let held = super::NodePortReservation::take(ports.path(), port)
            .unwrap()
            .expect("a free port's reservation is taken");
        assert!(
            super::NodePortReservation::take(ports.path(), port)
                .unwrap()
                .is_none(),
            "a second supervisor's reservation of the held port is refused"
        );
        drop(held);
        assert!(
            super::NodePortReservation::take(ports.path(), port)
                .unwrap()
                .is_some(),
            "the kernel released the reservation with the fd: the next boot \
             takes the same port"
        );
        let lock_file = ports.path().join(format!("{port}.lock"));
        assert!(
            lock_file.exists(),
            "the lock file is never unlinked, and holds nothing a take does not prove"
        );
    }

    #[test]
    fn draw_skips_the_answerer_hook_port_while_free() {
        // Its own reservation dir: no test takes a flock in the real one.
        let ports = tempfile::tempdir().expect("a test reservation dir");
        // The answerer's hook port is the node's own, whatever any probe
        // says about it (T93): nothing binds it while this test runs, and
        // the draw still never hands it — a VM handed the hook port would
        // publish on the port the host's zone answerer serves from
        // (NET-138), so the skip is a fact about the port, not a fact
        // about what happens to be bound at it now.
        let hook = crate::net::answerer::DEFAULT_ANSWERER_PORT;
        assert!(
            !super::loopback_answers(hook),
            "nothing binds the answerer's hook port while this test runs"
        );
        assert!(
            super::NODE_RESERVED_PORTS.contains(&hook),
            "the node-reserved set names the answerer's hook port"
        );
        let assigned = super::assign_node_port(ports.path(), hook, false).unwrap();
        assert_ne!(
            assigned.port, hook,
            "the draw never hands the node's own port, even with it free"
        );
        assert_eq!(
            assigned.skipped,
            Some(super::SKIP_NODE_RESERVED),
            "the skip names the reservation's reason, not a probe's"
        );
    }

    /// NET-132/T69: a boot with no acceptor binds no pool socket. The
    /// supervisor hands the peer an empty box source — rows registered or
    /// not, the node namespace's row included — and the pool a peer would
    /// build holds nothing. A listening acceptor (`bep serve`, or the
    /// stand-in under its flag) is what registers rows, and only the rows
    /// that declared a credentialed upstream (NET-134).
    #[tokio::test]
    async fn production_wiring_leaves_pool_len_zero_with_rows_registered() {
        let subnet = switch::SwitchSubnet::default();
        let attachments = crate::bep_attach::Attachments::new();
        let registry = crate::box_registry::BoxRegistry::new(subnet)
            .feeding_proxy_attachments(attachments.clone());
        registry.register_node_namespace(7654);
        registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "box-a".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: Some(boxes::CredentialedUpstream::default()),
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a switch address to hand out");
        // A box with no credentialed lane: the gate refuses its frames to
        // the proxy's address, so it holds no share either.
        registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "box-b".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a switch address to hand out");

        let dir = tempfile::tempdir().expect("tempdir");
        let wire = switch::bep_host::BepWire::new(
            dir.path().join("proxy.sock"),
            [0u8; switch::bep_host::TOKEN_LEN],
        )
        .with_per_source_cap(switch::bep_host::DEFAULT_PER_SOURCE_CAP);

        // The production wiring: rows sit in the table — the node
        // namespace's and a client box's — and still buy no share.
        let mut lane = switch::bep_host::test_util::TestLane::new(
            subnet,
            wire.clone(),
            super::bep_box_source(None, registry.table(), attachments.clone()),
        );
        for _ in 0..2 {
            lane.step().await;
        }
        assert_eq!(
            lane.pool_len(),
            0,
            "a production boot binds no pool socket, rows registered or not"
        );

        // An acceptor that is not listening yet binds nothing either.
        let listening = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut acceptor_lane = switch::bep_host::test_util::TestLane::new(
            subnet,
            wire,
            super::bep_box_source(
                Some(std::sync::Arc::clone(&listening)),
                registry.table(),
                attachments,
            ),
        );
        for _ in 0..2 {
            acceptor_lane.step().await;
        }
        assert_eq!(
            acceptor_lane.pool_len(),
            0,
            "no share binds to a path nothing listens on"
        );

        // Once it listens, the rows that declared a lane get shares: one
        // declared box, one share. The undeclared box and the node
        // namespace's row add none.
        listening.store(true, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..2 {
            acceptor_lane.step().await;
        }
        assert_eq!(
            acceptor_lane.pool_len(),
            switch::bep_host::DEFAULT_PER_SOURCE_CAP,
            "a listening acceptor registers the declared boxes' shares, and \
             only theirs"
        );

        // An acceptor that exits takes the shares with it.
        listening.store(false, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..2 {
            acceptor_lane.step().await;
        }
        assert_eq!(
            acceptor_lane.pool_len(),
            0,
            "the shares go when the acceptor stops listening"
        );
    }

    /// A registry with one box that declares a credentialed upstream and
    /// one that does not, and the [`super::CredentialedBoxes`] source over it.
    fn credentialed_boxes_with_two_rows(
        listening: bool,
    ) -> (
        super::CredentialedBoxes,
        std::net::Ipv4Addr,
        std::net::Ipv4Addr,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let attachments = crate::bep_attach::Attachments::new();
        let registry = crate::box_registry::BoxRegistry::new(switch::SwitchSubnet::default())
            .feeding_proxy_attachments(attachments.clone());
        let spec = |name: &str, credentialed: bool| crate::box_registry::ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: Vec::new(),
            egress: None,
            credentialed_upstream: credentialed.then(boxes::CredentialedUpstream::default),
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let declared = registry
            .register_client_box(spec("box-lane", true))
            .expect("the plan has a switch address to hand out")
            .switch_addr();
        let undeclared = registry
            .register_client_box(spec("box-no-lane", false))
            .expect("the plan has a switch address to hand out")
            .switch_addr();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(listening));
        let table = registry.table();
        let source = super::CredentialedBoxes {
            boxes: crate::box_registry::RegisteredBoxes::new(table.clone(), attachments),
            table,
            listening: std::sync::Arc::clone(&flag),
        };
        (source, declared, undeclared, flag)
    }

    /// NET-134: while the proxy listens, a registered row that declared no
    /// credentialed upstream gets no share.
    #[test]
    fn credentialed_boxes_skip_a_row_without_a_credentialed_upstream() {
        use switch::bep_host::BepBoxSource as _;
        let (source, _declared, undeclared, _flag) = credentialed_boxes_with_two_rows(true);
        assert!(
            !source.box_switch_addresses().contains(&undeclared),
            "a row with no credentialed upstream holds no share"
        );
    }

    /// NET-134: while the proxy listens, a registered row that declared a
    /// credentialed upstream gets its share, and it is the only one.
    #[test]
    fn credentialed_boxes_share_a_row_with_a_credentialed_upstream() {
        use switch::bep_host::BepBoxSource as _;
        let (source, declared, _undeclared, _flag) = credentialed_boxes_with_two_rows(true);
        assert_eq!(
            source.box_switch_addresses(),
            vec![declared],
            "the declared row gets its share, and only it"
        );
    }

    /// No row gets a share while the proxy does not listen, and the shares
    /// follow the flag when it changes.
    #[test]
    fn credentialed_boxes_share_nothing_while_not_listening() {
        use switch::bep_host::BepBoxSource as _;
        let (source, declared, _undeclared, flag) = credentialed_boxes_with_two_rows(false);
        assert!(
            source.box_switch_addresses().is_empty(),
            "no row holds a share while nothing listens"
        );
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(source.box_switch_addresses(), vec![declared]);
        flag.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            source.box_switch_addresses().is_empty(),
            "the shares go when the proxy stops listening"
        );
    }

    /// T94: the guest report door's bridge is one step. Binding the door
    /// and answering the env the VMM child registers the door's vsock port
    /// from happen together, so the door is bound only once the bridge is
    /// up: the pair names a live socket at the door's own file name beside
    /// the control socket, and a bind that cannot happen answers no env at
    /// all — no boot bridges a door it did not bind (the boot fails on it,
    /// [`super::bind_box_doors`]).
    #[test]
    fn guest_report_door_bound_only_behind_its_bridge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let control_sock = dir.path().join(crate::control::CONTROL_SOCK_FILE);
        let boxes = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let answerer = crate::net::answerer::AnswererStatus::starting();
        let proxy_publish = crate::control::ProxyPublishStatus::new();

        // The bound half: the pair names the door's path under its env.
        let (name, door) =
            super::guest_report_door_env(&control_sock, &boxes, &answerer, &proxy_publish)
                .expect("the guest report door binds beside the control socket");
        assert_eq!(
            name,
            crate::control::GUEST_REPORT_SOCK_ENV,
            "the env the child registers the door's vsock port from is the \
             report door's own name"
        );
        assert_eq!(
            door,
            control_sock.with_file_name(crate::control::GUEST_CONTROL_SOCK_FILE),
            "the env names the guest door's own socket beside the control socket"
        );
        assert!(
            std::os::unix::net::UnixStream::connect(&door).is_ok(),
            "the door the env names is a live socket the child can register: {}",
            door.display()
        );

        // The refused half: a path that cannot carry the door refuses the
        // bind, and with it the env — the boot loop hands the child
        // nothing, and no bridge comes up over a door that never bound.
        let blocked = tempfile::tempdir().expect("tempdir");
        let blocked_sock = blocked.path().join(crate::control::CONTROL_SOCK_FILE);
        std::fs::write(
            blocked_sock.with_file_name(crate::control::GUEST_CONTROL_SOCK_FILE),
            "not a socket",
        )
        .expect("seeding the blocking file");
        assert!(
            super::guest_report_door_env(&blocked_sock, &boxes, &answerer, &proxy_publish).is_err(),
            "a guest-door path held by a non-socket file refuses the bind, and \
             the env the child would register it from"
        );
    }

    /// #1790: a door that cannot bind is the supervisor's startup error,
    /// never a warning the VM boots past. A non-socket file at the control
    /// socket's path refuses the control bind, and one at the guest door's
    /// path refuses the door's; each error names the path it could not
    /// bind and the cause.
    #[test]
    fn box_door_bind_failure_is_a_startup_error() {
        let boxes = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let answerer = crate::net::answerer::AnswererStatus::starting();
        let proxy_publish = crate::control::ProxyPublishStatus::new();

        let dir = tempfile::tempdir().expect("tempdir");
        let control_sock = dir.path().join(crate::control::CONTROL_SOCK_FILE);
        std::fs::write(&control_sock, "not a socket").expect("seeding the blocking file");
        let error = super::bind_box_doors(&control_sock, &boxes, &answerer, &proxy_publish)
            .expect_err("a control socket path held by a non-socket file fails the startup");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!(
                "binding the box-registration control socket at {}",
                control_sock.display()
            )) && message.contains("is not a socket"),
            "the error names the control socket and the cause: {message}"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let control_sock = dir.path().join(crate::control::CONTROL_SOCK_FILE);
        let door = control_sock.with_file_name(crate::control::GUEST_CONTROL_SOCK_FILE);
        std::fs::write(&door, "not a socket").expect("seeding the blocking file");
        let error = super::bind_box_doors(&control_sock, &boxes, &answerer, &proxy_publish)
            .expect_err("a guest door path held by a non-socket file fails the startup");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!(
                "binding the guest report door at {}",
                door.display()
            )),
            "the error names the guest report door: {message}"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let control_sock = dir.path().join(crate::control::CONTROL_SOCK_FILE);
        let (_control, (name, door)) =
            super::bind_box_doors(&control_sock, &boxes, &answerer, &proxy_publish)
                .expect("both doors bind on a clear path");
        assert_eq!(name, crate::control::GUEST_REPORT_SOCK_ENV);
        assert!(
            std::os::unix::net::UnixStream::connect(&control_sock).is_ok()
                && std::os::unix::net::UnixStream::connect(&door).is_ok(),
            "both doors are live sockets once the startup binds them"
        );
    }

    /// BEP-015: the supervisor starts `bep serve` on the wire's socket, with
    /// this boot's token as 64 hex digits on standard input and never in
    /// argv. Its output lands in the log beside the socket, and dropping the
    /// handle stops the proxy.
    #[test]
    fn proxy_is_started_with_the_per_boot_token() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let seen = dir.path().join("seen");
        let bin = dir.path().join("bep");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" > '{seen}.args'\n\
                 IFS= read -r token\n\
                 printf '%s' \"$token\" > '{seen}.token'\n\
                 echo 'the proxy is serving' >&2\n\
                 exec sleep 30\n",
                seen = seen.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let listener = dir.path().join("gvproxy-bep.sock");
        // A socket a previous boot left behind is not the proxy listening.
        let stale = std::os::unix::net::UnixListener::bind(&listener).expect("stale socket");
        let log = listener.with_file_name(super::BEP_LOG_FILE);
        let mut token = [0u8; switch::bep_host::TOKEN_LEN];
        for (i, byte) in token.iter_mut().enumerate() {
            *byte = u8::try_from(i * 7 + 1).unwrap();
        }
        let proxy = super::BepProxy::spawn(&bin, &listener, &token, &log).expect("spawn");
        assert_ne!(proxy.pid(), 0);

        let token_file = seen.with_extension("token");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(token_file.exists()
            && std::fs::read_to_string(&log).is_ok_and(|l| l.contains("serving")))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the proxy never read its token"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), 64);
        assert_eq!(std::fs::read_to_string(&token_file).unwrap(), hex);
        let args = std::fs::read_to_string(seen.with_extension("args")).unwrap();
        assert_eq!(
            args.trim_end(),
            format!(
                "serve --listener {} {}",
                listener.display(),
                super::BEP_LIFELINE_FLAG
            )
        );
        assert!(!args.contains(&hex), "the token never rides in argv");
        assert!(
            std::fs::read_to_string(&log)
                .unwrap()
                .contains("the proxy is serving"),
            "the proxy's output lands in the log beside its socket"
        );

        // The watcher looks every interval. A stale socket never counts.
        let listening = proxy.listening();
        std::thread::sleep(super::BEP_WATCH_INTERVAL * 3);
        assert!(
            !listening.load(std::sync::atomic::Ordering::SeqCst),
            "a stale socket at the path is not the proxy listening"
        );
        // The proxy binds its own socket over the stale one, as `bep`
        // does: bound at a staging path, then renamed onto the path.
        let staging = dir.path().join("staging.sock");
        let _bound = std::os::unix::net::UnixListener::bind(&staging).expect("bind");
        std::fs::rename(&staging, &listener).unwrap();
        drop(stale);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !listening.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the watcher never saw the proxy's socket"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let pid = proxy.pid();
        drop(proxy);
        assert!(
            !listening.load(std::sync::atomic::Ordering::SeqCst),
            "a stopped proxy is not listening"
        );
        // The watcher reaped the child, so the pid names no process of ours.
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .unwrap()
            .success();
        assert!(!alive, "dropping the handle stops the proxy");
    }

    /// BEP-015: a supervisor that dies without unwinding leaves no
    /// `bep serve` behind. The thread that starts the proxy exits here
    /// while the handle lives on, as a SIGKILL'd supervisor would, and the
    /// parent-death signal stops the child.
    #[cfg(target_os = "linux")]
    #[test]
    fn proxy_is_started_with_the_per_boot_token_and_stops_when_its_parent_dies() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bep");
        std::fs::write(&bin, "#!/bin/sh\nIFS= read -r token\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let listener = dir.path().join("gvproxy-bep.sock");
        let log = listener.with_file_name(super::BEP_LOG_FILE);
        let token = [7u8; switch::bep_host::TOKEN_LEN];

        let proxy = std::thread::spawn({
            let (bin, listener, log) = (bin.clone(), listener.clone(), log.clone());
            move || super::BepProxy::spawn(&bin, &listener, &token, &log).expect("spawn")
        })
        .join()
        .expect("the starting thread");
        let pid = libc::pid_t::try_from(proxy.pid()).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // SAFETY: kill with signal 0 only probes whether the pid exists.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the proxy outlived the thread that started it"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        drop(proxy);
    }

    /// #2501: the proxy's standard input stays open after the token for as
    /// long as the supervisor owns the child, and closes when it lets go.
    /// The kernel closes the same end when the supervisor dies without
    /// unwinding (`bep::supervisor` proves that half with a SIGKILL'd
    /// writer), so `bep serve --exit-on-stdin-close` stops on any host.
    #[test]
    fn proxy_is_started_with_the_per_boot_token_and_a_lifeline_on_its_input() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let eof = dir.path().join("eof");
        let bin = dir.path().join("bep");
        // A reader in the background holds the input past the token, as
        // `bep serve` does, and records the end of input. An asynchronous
        // list's input is /dev/null unless redirected, hence fd 3.
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 IFS= read -r token\n\
                 exec 3<&0\n\
                 ( cat <&3 >/dev/null; echo closed > '{eof}' ) &\n\
                 exec sleep 30\n",
                eof = eof.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let listener = dir.path().join("gvproxy-bep.sock");
        let log = listener.with_file_name(super::BEP_LOG_FILE);
        let token = [9u8; switch::bep_host::TOKEN_LEN];

        let proxy = super::BepProxy::spawn(&bin, &listener, &token, &log).expect("spawn");
        std::thread::sleep(super::BEP_WATCH_INTERVAL * 3);
        assert!(
            !eof.exists(),
            "the input stays open after the token while the supervisor lives"
        );

        drop(proxy);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !eof.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the input never closed when the supervisor let go"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// The proxy's log, appended across boots, moves aside to `bep.log.old`
    /// at a start once it passes its cap, so it cannot fill the state dir.
    #[test]
    fn proxy_is_started_with_the_per_boot_token_and_a_full_log_moves_aside() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join(super::BEP_LOG_FILE);
        let old = dir.path().join(format!("{}.old", super::BEP_LOG_FILE));

        super::cap_bep_log(&log, 4).expect("no log is not an error");
        assert!(!log.exists() && !old.exists());

        std::fs::write(&log, b"1234").unwrap();
        super::cap_bep_log(&log, 4).unwrap();
        assert_eq!(
            std::fs::read(&log).unwrap(),
            b"1234",
            "a log at the cap stays"
        );
        assert!(!old.exists());

        std::fs::write(&old, b"older").unwrap();
        std::fs::write(&log, b"12345").unwrap();
        super::cap_bep_log(&log, 4).unwrap();
        assert!(!log.exists(), "a log past the cap moves aside");
        assert_eq!(
            std::fs::read(&old).unwrap(),
            b"12345",
            "and replaces the older copy"
        );
    }

    /// A watcher thread that cannot start leaves no proxy running with the
    /// token: the child is killed and reaped before the error returns.
    #[test]
    fn proxy_is_started_with_the_per_boot_token_and_stopped_when_no_watcher_starts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let watch = super::BepWatch {
            stop: std::sync::Arc::default(),
            listening: std::sync::Arc::default(),
            listener: dir.path().join("gvproxy-bep.sock"),
            stale: None,
            log: dir.path().join(super::BEP_LOG_FILE),
        };
        let error = super::hand_to_watcher(child, watch, |_body| {
            Err(std::io::Error::other("no thread for the watcher"))
        })
        .expect_err("a watcher that cannot start fails the start");
        assert_eq!(error.to_string(), "no thread for the watcher");
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .unwrap()
            .success();
        assert!(!alive, "the proxy does not outlive a failed watcher start");
    }
}
