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

/// Foreground supervisor: boot the VM, manage lifecycle state, supervise until
/// the VMM child exits.
#[cfg(minvmd_libkrun)]
fn run_foreground() -> Result<()> {
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
    let boxes = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET)
        .feeding_proxy_attachments(proxy_attachments.clone());
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
    let mut node_port =
        assign_node_proxy_port(&ports_dir).context("assigning the node's proxy port")?;
    boxes.register_node_namespace(node_port.port);
    // A box's row goes with its shuttle connection: the gate reports which
    // addresses each relay carried at the relay's end, and this drainer thread
    // applies the reports for the life of the process (NET-133).
    boxes.spawn_withdrawal_drainer();

    // The answerer's state — the host fact the CLI surfaces at session
    // start and on `min ls` — created here so both halves that move it can
    // share it: the acquisition loop writes it at every pass (holder,
    // registered, or a port held by a process with no channel), and the
    // control socket below reads it for the read-only status verb. Starting
    // is its pre-acquisition value, and the CLI treats it as "nothing to
    // say yet" rather than a verdict.
    let answerer_status = crate::net::answerer::AnswererStatus::starting();
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
    // inside the escape boundary. Bound before the guest boots, so a
    // session activated against this VM can only ever be handed an address
    // this table holds. Best-effort at startup, like the switch above: a
    // bind failure is warned and the VM still boots — a registration then
    // degrades to the gate's announced interim, exactly as against a
    // supervisor predating the socket — rather than failing a boot the
    // client could still activate against.
    let _control = crate::control::resolve_control_sock()
        .and_then(|sock_path| {
            crate::control::spawn(
                sock_path,
                boxes.clone(),
                answerer_status.clone(),
                proxy_publish.clone(),
            )
        })
        .inspect_err(|error| {
            tracing::warn!(
                %error,
                "failed to bind the box-registration control socket; own-address \
                 activations will not be handed addresses (the egress gate's \
                 announced interim applies)"
            );
        })
        .ok();

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
    // startup, like the control socket: a thread that could not spawn is
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
            // Nothing listens there on a production boot — the proxy's own
            // acceptor is a later task — and nothing binds the pool on one
            // either (`bep_box_source` below), so a box's connection to
            // the proxy's address is reset, the acceptor-down answer the
            // pool is specified to give.
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
                    _bep_stub.is_some(),
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
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("__krun-vmm");
        // Forward the state-dir override and VM name so the VMM child resolves the
        // same per-VM state dir this supervisor does.
        crate::state::forward_identity(&mut cmd);
        alive_lock.inherit_into(&mut cmd);
        child = cmd
            .env(MARKER_SOCK_ENV, &marker_sock_path)
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
            )
            .spawn()
            .with_context(|| format!("spawning VMM child: {}", exe.display()))?;

        child_pid = child.id();
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
                boxes.register_node_namespace(node_port.port);
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
        // The watcher keeps the supervisor's span, so its lines carry `vm`.
        let vm_scope = tracing::Span::current();
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

/// The box source the peer's pool is partitioned by: the table's box rows
/// with their attachments — [`crate::box_registry::RegisteredBoxes`] —
/// when a stand-in acceptor actually bound at the wire's path, and
/// [`switch::bep_host::NoBoxes`] — no row, no share, no socket — when one
/// did not.
///
/// A socket in the pool is a lane onto the host for the box whose share
/// holds it, and nothing yet stands between one and whatever reaches it:
/// the credentialed-only gate rule (NET-145, T45, #1665) is still ahead.
/// So a production boot hands the peer an empty source and the pool binds
/// nothing — a box's connection to the proxy's address meets the stack's
/// own reset — until that rule lands and lets the shares bind. The
/// stand-in's own boot (`MINVMD_BEP_STUB`, the e2e lane's flag and nothing
/// else's) is the one wiring that registers rows, and only a lane that
/// asked for it gets them; the caller passes the stand-in's own handle —
/// whether one is bound, not whether the flag that asks for one was set —
/// so the pool can never be partitioned by a path nothing is listening on.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn bep_box_source(
    stand_in_bound: bool,
    table: crate::box_registry::BoxTable,
    attachments: crate::bep_attach::Attachments,
) -> std::sync::Arc<dyn switch::bep_host::BepBoxSource> {
    if stand_in_bound {
        std::sync::Arc::new(crate::box_registry::RegisteredBoxes::new(
            table,
            attachments,
        ))
    } else {
        std::sync::Arc::new(switch::bep_host::NoBoxes)
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
    use anyhow::Context as _;
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

    // The base is this user's own runtime dir (the XDG_RUNTIME_DIR contract,
    // or macOS's Application Support): create it when absent, the default
    // mode — the ports dir itself is the one that carries the claim, so it
    // is the one created 0700 and the one the owner/mode check refuses. The
    // `/tmp` fallback's base is the exception, created and checked like the
    // ports dir.
    if base_is_shared_tmp {
        create_private_dir(&base)?;
    } else if !base.exists() {
        std::fs::create_dir_all(&base).context("creating the node-port reservation base")?;
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
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn log_node_port_assignment(surface: &str, assigned: &NodePortAssignment) {
    tracing::info!(
        surface,
        preferred = assigned.preferred,
        handed = assigned.port,
        configured = assigned.configured,
        skip_reason = assigned.skipped.unwrap_or(""),
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

    /// NET-132/T69: a production boot binds no pool socket. The
    /// credentialed-only gate rule (T45, #1665) is still ahead, so the
    /// supervisor hands the peer an empty box source — rows registered or
    /// not, the node namespace's row included — and the pool a peer would
    /// build holds nothing. The stand-in's wiring is the one that
    /// registers rows, and only a lane that asked for it gets them.
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
                credentialed_upstream: None,
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
            super::bep_box_source(false, registry.table(), attachments.clone()),
        );
        for _ in 0..2 {
            lane.step().await;
        }
        assert_eq!(
            lane.pool_len(),
            0,
            "a production boot binds no pool socket, rows registered or not"
        );

        // The stand-in's wiring registers rows, and only the boxes': one
        // client box, one share — the node namespace's row adds none.
        let mut stub_lane = switch::bep_host::test_util::TestLane::new(
            subnet,
            wire,
            super::bep_box_source(true, registry.table(), attachments),
        );
        for _ in 0..2 {
            stub_lane.step().await;
        }
        assert_eq!(
            stub_lane.pool_len(),
            switch::bep_host::DEFAULT_PER_SOURCE_CAP,
            "the stand-in's wiring registers the boxes' shares, and only \
             the boxes'"
        );
    }
}
