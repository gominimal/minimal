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
pub fn run(detach: bool, timeout_secs: Option<u64>) -> Result<()> {
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
    return run_supervisor(detach, timeout_secs);

    #[cfg(not(minvmd_libkrun))]
    {
        let _ = (detach, timeout_secs);
        bail!("`minvmd run` requires libkrun (macOS, or Linux with libkrun installed)");
    }
}

#[cfg(minvmd_libkrun)]
fn run_supervisor(detach: bool, timeout_secs: u64) -> Result<()> {
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
        return run_detach(timeout_secs);
    }
    run_foreground()
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
            DetachPoll::Failed(status) => bail!(
                "the detached supervisor exited during startup ({status}); \
                 see {} for its error output",
                log_path.display()
            ),
            DetachPoll::LeakedVmm(pid) => bail!(
                "the supervisor exited but a leaked __krun-vmm (pid {pid}) still holds the \
                 alive lock; run `min stop` or kill {pid}, then retry"
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

/// Foreground supervisor: boot the VM, manage lifecycle state, supervise until
/// the VMM child exits.
#[cfg(minvmd_libkrun)]
fn run_foreground() -> Result<()> {
    use std::io::{BufReader, Read as _};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::cmd::MARKER_SOCK_ENV;
    use crate::image::resolve_boot_images;
    use crate::lifecycle::{Action, Lifecycle, next_state};
    use crate::state::{StartingGuard, State, StateDir};

    // One span per supervised VM, like minimald's per-connection `conn` span:
    // every record the supervisor emits carries `vm`, so a detached
    // supervisor's lines in the shared log (`<state>/logs/minvmd.log`, common
    // to every VM on the host) stay attributable once a second VM runs —
    // grep instead of manual fields on each line.
    let _vm_scope = tracing::info_span!("supervisor", vm = %crate::state::vm_name()).entered();

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
    // An own-address box's lease is not a row this process can name: the guest
    // daemon's own allocator mints it inside the VM, so no host-side process
    // knows it — not this supervisor, and not the CLI that asked for the box.
    // Until the creator-side registration (T66, #1711) supplies those rows,
    // such a source is what the gate's announced interim is for: an address
    // inside the plan's lease block but held by no row is admitted — with a
    // warn naming T66 on every admit — so an own-address box keeps the egress
    // it had before the gate existed, while everything outside the block, and
    // every row that *is* published, stays exactly as decided.
    //
    // What that admits, said plainly: under the interim the host-side gate
    // cannot attribute a frame to the box it came from unless a row holds the
    // address, so a box with restrictive rules can be escaped by sourcing
    // frames from any unregistered in-block address — NET-081's host-side
    // guarantee is deferred to T66 until its rows land and its flip of
    // `UNREGISTERED_SOURCE_PHASE` (egress_gate) puts the per-box default in
    // force. Every admit under the interim is rate-limited-warned, so a
    // diagnostic bundle's daemon log tail shows a host running it.
    // `UNREGISTERED_SOURCE_PHASE` (egress_gate) is the constant T66 flips.
    let boxes = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
    // The node's own ports are resolved once before the VM boots — the
    // operator's override (`MINVMD_NODE_*_PORT` in this supervisor's env) or
    // the default-first probe, so a VM sharing a host with a native daemon
    // still lands on the default proxy port when it is free — and the one
    // resolved pair is written twice: handed to the guest through the VMM
    // child's env onto the kernel command line, and declared as the node
    // row's own publishes. The daemon's setup publishes them at its address
    // (NET-025); the pair it publishes is the pair the guest binds.
    let node_ports =
        assign_node_ports().context("assigning the node's proxy and answerer ports")?;
    boxes.register_node_namespace(node_ports.proxy_port(), node_ports.answerer_port());
    // A box's row goes with its shuttle connection: the gate reports which
    // addresses each relay carried at the relay's end, and this drainer thread
    // applies the reports for the life of the process (NET-133).
    boxes.spawn_withdrawal_drainer();

    // The host-side door to the box table (T66): the control socket the
    // activating client registers an own-address box on and reads its
    // allocated switch and loopback addresses from — the addresses the
    // create request then carries, so the in-VM daemon attaches with the
    // handed one. Bound before the guest boots, so a session activated
    // against this VM can only ever be handed an address this table holds.
    // Best-effort at startup, like the switch above: a bind failure is
    // warned and the VM still boots — a registration then degrades to the
    // gate's announced interim, exactly as against a supervisor predating
    // the socket — rather than failing a boot the client could still
    // activate against.
    let _control = crate::control::resolve_control_sock()
        .and_then(|sock_path| crate::control::spawn(sock_path, boxes.clone()))
        .inspect_err(|error| {
            tracing::warn!(
                %error,
                "failed to bind the box-registration control socket; own-address \
                 activations will not be handed addresses (the egress gate's \
                 announced interim applies)"
            );
        })
        .ok();

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
    let _gvproxy = match crate::image::resolve_gvproxy_path() {
        binary if binary.exists() => {
            let switch_sock =
                crate::net::resolve_switch_sock().context("resolving switch socket")?;
            crate::sock::prepare_socket_dir(&switch_sock).context("preparing switch socket dir")?;
            crate::sock::remove_stale_socket(&switch_sock)
                .context("removing stale switch socket")?;
            // The gate binds the socket beside the switch socket, so a stale
            // file from a prior run must go or the bind fails EEXIST — the
            // same discipline the switch socket gets.
            let gate_sock =
                crate::net::resolve_gate_sock().context("resolving egress gate socket")?;
            crate::sock::remove_stale_socket(&gate_sock)
                .context("removing stale egress gate socket")?;
            match crate::net::HostGvproxy::spawn(
                binary,
                switch_sock,
                crate::net::DEFAULT_DATAPATH_CHECK_INTERVAL,
                &boxes,
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
                // non-own-IP boot tolerates it (same as a missing binary below).
                Err(error) if crate::cmd::own_ip_requested() => {
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
        binary if crate::cmd::own_ip_requested() => {
            // An own-IP VM cannot work without the switch: fail loudly rather
            // than booting a session that silently has no network.
            bail!(
                "own-IP VM requested but the gvproxy binary was not found at {}; \
                 set MINVMD_GVPROXY_BIN to the gvproxy binary",
                binary.display()
            );
        }
        binary => {
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

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("__krun-vmm");
    // Forward the state-dir override and VM name so the VMM child resolves the
    // same per-VM state dir this supervisor does.
    crate::state::forward_identity(&mut cmd);
    alive_lock.inherit_into(&mut cmd);
    let mut child = cmd
        .env(MARKER_SOCK_ENV, &marker_sock_path)
        // The node ports travel to the guest through the VMM child's env: the
        // child is a separate process (like the marker socket path), and its
        // backend appends them to the kernel command line, where the kernel
        // hands unrecognized `KEY=VALUE` tokens to init as env vars. The
        // explicit `.env` also shadows any inherited operator override under
        // the same names, so the child carries exactly this resolution — the
        // same pair the node row registered.
        .env(
            crate::vm::NODE_PROXY_PORT_ENV,
            node_ports.proxy_port().to_string(),
        )
        .env(
            crate::vm::NODE_ANSWERER_PORT_ENV,
            node_ports.answerer_port().to_string(),
        )
        .spawn()
        .with_context(|| format!("spawning VMM child: {}", exe.display()))?;

    let child_pid = child.id();
    tracing::info!(pid = child_pid, "VMM child spawned");

    // Update state with the known pid so that concurrent `stop` invocations
    // during Starting can signal the correct process.
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        // A concurrent stop might have already reset us to Stopped; bail early.
        if !matches!(state.lifecycle, Lifecycle::Starting) {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "lifecycle changed to {:?} during spawn; aborting",
                state.lifecycle
            );
        }
        state_dir
            .write_state(&State {
                lifecycle: Lifecycle::Starting,
                vmm_pid: Some(child_pid),
                ..State::stopped()
            })
            .context("writing Starting state with vmm_pid")?;
    }

    // Wait for the guest to write `READY\n` on the marker socket. The wait is
    // env-configurable (`MINVMD_READY_TIMEOUT_SECS`): a cold multi-GiB VM can
    // take ~20s+ to reach userspace, so a fixed 5s was too short.
    let ready_timeout: Duration = crate::cmd::ready_timeout();
    let known_hosts_path = crate::cmd::default_vm_known_hosts_path();
    let (tx, rx) = std::sync::mpsc::channel::<Result<crate::cmd::BootBeacon, String>>();
    let sock_clone = marker_sock_path.clone();
    std::thread::spawn(move || {
        let result = (|| -> Result<crate::cmd::BootBeacon, String> {
            let (stream, _) = listener
                .accept()
                .map_err(|e| format!("accept on READY-marker socket: {e}"))?;
            let mut reader = BufReader::new(stream);
            crate::cmd::read_ready_beacon(&mut reader, &known_hosts_path)
        })();
        let _ = tx.send(result);
        let _ = std::fs::remove_file(&sock_clone);
    });

    let boot_result = match rx.recv_timeout(ready_timeout) {
        Ok(Ok(crate::cmd::BootBeacon::Ready)) => Ok(()),
        Ok(Ok(crate::cmd::BootBeacon::MountFailed { reason })) => Err(
            crate::cmd::mount_failed_error(&reason, &volume_path, volume_preexisted),
        ),
        Ok(Err(e)) => Err(anyhow::anyhow!("boot failed: {e}")),
        Err(_) => Err(anyhow::anyhow!(
            "boot timed out waiting for READY marker after {} s (raise {} to wait longer)",
            ready_timeout.as_secs(),
            crate::cmd::READY_TIMEOUT_ENV,
        )),
    };

    if let Err(e) = boot_result {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&marker_sock_path);
        crate::cmd::discard_fresh_volume_image(&volume_path, volume_preexisted);
        return Err(e);
        // guard drops here → StartingGuard resets state to Stopped (R4.6)
    }

    // ── Phase 2: Starting → Running (under lock) ────────────────────────────
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
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

    // ── Phase 3: Supervise until VMM child exits ─────────────────────────────
    let status = child.wait().context("waiting for VMM child")?;
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

/// The node's proxy and answerer ports, assigned by the VM host before the VM
/// boots: default-first, so a VM sharing a host with a native daemon still
/// lands on the defaults when they are free and only falls to OS-assigned
/// ports when the defaults are actually held.
// Only `run_foreground` calls these, and it needs libkrun; without it the
// crate is a runtime-bailing stub, but the tests below still cover this on
// every target.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodePorts {
    proxy: u16,
    answerer: u16,
}

impl NodePorts {
    /// The hostname proxy's TCP port the guest daemon binds as handed (NET-025).
    #[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
    pub(crate) fn proxy_port(&self) -> u16 {
        self.proxy
    }

    /// The zone answerer's UDP port the guest daemon binds as handed (NET-025).
    #[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
    pub(crate) fn answerer_port(&self) -> u16 {
        self.answerer
    }
}

/// The defaults the assignment probes first. They mirror the native daemon's
/// own defaults (`DEFAULT_EGRESS_PROXY_PORT` in minimald's `net/proxy.rs`,
/// `ANSWERER_PORT` in its `net/answerer.rs`): `minvmd` does not depend on the
/// daemon, so the values are pinned here beside the constants they mirror.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const NODE_DEFAULT_PROXY_PORT: u16 = 7654;
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
const NODE_DEFAULT_ANSWERER_PORT: u16 = 7656;

/// Assigns both node ports: TCP for the proxy, UDP for the answerer. The
/// operator's override ([`crate::vm::NODE_PROXY_PORT_ENV`] /
/// [`crate::vm::NODE_ANSWERER_PORT_ENV`] set in this supervisor's own env)
/// wins over the probe, and the one resolved pair is what both the guest
/// handoff (the VMM child's env) and the node row's own publishes are
/// written from — handed == registered, never two resolutions.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn assign_node_ports() -> Result<NodePorts> {
    let proxy = match node_port_override(crate::vm::NODE_PROXY_PORT_ENV)? {
        Some(proxy) => proxy,
        None => assign_node_port(NODE_DEFAULT_PROXY_PORT, false)?,
    };
    let answerer = match node_port_override(crate::vm::NODE_ANSWERER_PORT_ENV)? {
        Some(answerer) => answerer,
        None => assign_node_port(NODE_DEFAULT_ANSWERER_PORT, true)?,
    };
    Ok(NodePorts { proxy, answerer })
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

/// Assigns one node port by probing: bind the preferred port to check the
/// host has it free, release the probe again, and let the OS pick when the
/// preferred port is already held. The probe releases its socket, so between
/// the assignment and the guest's bind inside the VM the port could still be
/// taken by another process — a lost race the guest's own log tail shows
/// (a handed port never silently moves, NET-024).
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn assign_node_port(preferred: u16, udp: bool) -> Result<u16> {
    use anyhow::Context as _;
    let probe = |port: u16| -> std::io::Result<u16> {
        if udp {
            let socket = std::net::UdpSocket::bind(("0.0.0.0", port))?;
            Ok(socket.local_addr()?.port())
        } else {
            let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
            Ok(listener.local_addr()?.port())
        }
    };
    match probe(preferred) {
        Ok(assigned) => Ok(assigned),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            probe(0).context("the node's default port is held and no OS-assigned port is available")
        }
        Err(error) => Err(error).context("probing the node's default port"),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(minvmd_libkrun))]
    use super::*;

    #[cfg(not(minvmd_libkrun))]
    #[test]
    fn run_bails_without_libkrun() {
        let err = run(false, None).unwrap_err();
        assert!(
            err.to_string().contains("requires libkrun"),
            "expected libkrun-required message, got: {err}"
        );
    }

    #[cfg(not(minvmd_libkrun))]
    #[test]
    fn run_rejects_timeout_without_detach() {
        let err = run(false, Some(5)).unwrap_err();
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
    fn parent_pid_of_own_process_is_consistent() {
        // The lookup for our own pid must agree with getppid(). This
        // exercises the platform's parent-pid path (proc_pidinfo on macOS,
        // /proc/<pid>/stat on Linux).
        // SAFETY: getppid() has no preconditions and cannot fail.
        let expected = unsafe { libc::getppid() } as u32;
        assert_eq!(super::parent_pid(std::process::id()), Some(expected));
    }

    #[test]
    fn node_port_assigned_on_host_and_handed_to_daemon() {
        // A port the test holds is busy: the assignment falls through to an
        // OS-assigned port rather than failing the boot over a shared-host
        // conflict — the case of a native daemon and a VM on one host. The
        // hold is on the wildcard address the assigner itself probes, so the
        // collision is one every host agrees on: a specific-address hold
        // collides with a wildcard probe on Linux and not everywhere else.
        let held = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let busy = held.local_addr().unwrap().port();
        let assigned = super::assign_node_port(busy, false).unwrap();
        assert_ne!(assigned, busy, "a held port is not assigned as-is");
        assert!(assigned != 0, "the fallback is a real port");

        // A port the test just released is free again: the default-first
        // probe assigns it as asked — the case the session e2e's hardcoded
        // default proxy port depends on. Released on the wildcard the probe
        // addresses, like the hold above.
        let freed = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let free = freed.local_addr().unwrap().port();
        drop(freed);
        assert_eq!(
            super::assign_node_port(free, false).unwrap(),
            free,
            "a free port is assigned as asked"
        );

        // The answerer's probe is the same default-first over UDP, held on
        // the same wildcard the UDP probe addresses.
        let held_udp = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let busy_udp = held_udp.local_addr().unwrap().port();
        let assigned_udp = super::assign_node_port(busy_udp, true).unwrap();
        assert_ne!(
            assigned_udp, busy_udp,
            "a held UDP port is not assigned as-is"
        );

        // The supervisor assigns both ports as a pair and hands them to the
        // guest: whatever the host picked, each is a real port the guest can
        // bind as handed (the cmdline and bind halves are the vm.rs and
        // minimald tests of the same name).
        let ports = super::assign_node_ports().unwrap();
        assert!(
            ports.proxy_port() != 0 && ports.answerer_port() != 0,
            "both node ports are assigned"
        );

        // The operator's override resolves the pair, and the one resolved
        // pair is written twice from the same value: handed to the guest
        // through the VMM child's env, and declared as the node row's own
        // publishes. Pinned here through the override env, so the assertion
        // can name both carries of the same values — handed == registered.
        let previous = (
            std::env::var(crate::vm::NODE_PROXY_PORT_ENV).ok(),
            std::env::var(crate::vm::NODE_ANSWERER_PORT_ENV).ok(),
        );
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, "17901") };
        unsafe { std::env::set_var(crate::vm::NODE_ANSWERER_PORT_ENV, "17902") };
        let pinned = super::assign_node_ports().unwrap();
        assert_eq!(pinned.proxy_port(), 17901, "the override is the resolution");
        assert_eq!(
            pinned.answerer_port(),
            17902,
            "the override is the resolution"
        );
        let registry = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let node = registry.register_node_namespace(pinned.proxy_port(), pinned.answerer_port());
        assert_eq!(
            node.admitted_ports(),
            [17901, 17902],
            "the row publishes the pair the guest is handed"
        );

        // The override's own garbage fails at the supervisor, naming the
        // variable and the value — never a fallback to selection that would
        // hand the guest a pair different from the one the operator pinned.
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, "no-port-here") };
        let err = super::assign_node_ports().unwrap_err().to_string();
        assert!(
            err.contains("MINVMD_NODE_PROXY_PORT") && err.contains("no-port-here"),
            "an undecodable override names the variable and the value, got: {err}"
        );
        unsafe { std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, "0") };
        let err = super::assign_node_ports().unwrap_err().to_string();
        assert!(
            err.contains("not a port to pin"),
            "a zero override is refused, got: {err}"
        );
        match &previous.0 {
            Some(previous) => unsafe {
                std::env::set_var(crate::vm::NODE_PROXY_PORT_ENV, previous)
            },
            None => unsafe { std::env::remove_var(crate::vm::NODE_PROXY_PORT_ENV) },
        }
        match &previous.1 {
            Some(previous) => unsafe {
                std::env::set_var(crate::vm::NODE_ANSWERER_PORT_ENV, previous)
            },
            None => unsafe { std::env::remove_var(crate::vm::NODE_ANSWERER_PORT_ENV) },
        }
    }
}
