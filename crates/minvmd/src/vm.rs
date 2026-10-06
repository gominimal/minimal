//! VM configuration builder.
//!
//! [`VmConfig`] collects the parameters needed to configure a libkrun context
//! (vcpus, RAM, kernel, initramfs, root disk, network mode). The network mode
//! selects how the VM attaches to the per-host gvproxy switch supervised by
//! [`crate::net`] (R1.4, R1.5).

use std::borrow::Cow;
use std::path::PathBuf;

use minimald_rpc::{EgressPolicy, NetworkMode};

use crate::error::VmError;

/// Environment variable selecting the data volume's `sync_mode` (spec R1.9).
/// Accepts `none` / `relaxed` / `full` (case-insensitive), the legacy booleans
/// `false` → none and `true` → relaxed, or the raw libkrun codes `0` / `1` / `2`.
/// Defaults to `relaxed` — libkrun's recommended mode: it honours flush but, on
/// macOS, skips the drive-level sync, bounding the crash data-loss window
/// without the throughput cost of full sync.
pub const DISK_SYNC_ENV: &str = "MINVMD_DISK_SYNC";

/// Host environment variable forwarded to the guest over the kernel command
/// line, so the guest daemon's log filter can be set from the host. Skipped
/// when it cannot survive the boot line, and it must never carry a secret —
/// see `kernel_cmdline` for both.
pub const GUEST_LOG_ENV: &str = "RUST_LOG";

/// The environment variable the supervisor (`cmd/run`) hands the VMM child
/// the node's proxy port in. The child is a separate process, so the env is
/// the transport — the same vector the marker-socket path rides — and the
/// backend appends the value to the kernel command line for the guest to
/// read (see `HOSTNAME_PROXY_PORT_TOKEN`).
pub(crate) const NODE_PROXY_PORT_ENV: &str = "MINVMD_NODE_PROXY_PORT";

/// The boot token the node's hostname-proxy port rides to the guest on. The
/// kernel starts `/init` with an empty environment, so the boot line is the
/// only vector: unrecognized `KEY=VALUE` tokens reach init as env vars (the
/// same vector `RUST_LOG` rides), and the guest daemon binds the port as
/// handed (NET-025).
const HOSTNAME_PROXY_PORT_TOKEN: &str = "MINIMALD_HOSTNAME_PROXY_PORT";

/// The environment variable the supervisor hands the VMM child this boot's
/// publish generation in (T93), beside [`NODE_PROXY_PORT_ENV`] and by the
/// same transport: a token the supervisor draws fresh for every boot it
/// spawns, so a publish report can be told apart from a killed boot's even
/// when both boots were handed the same port.
pub(crate) const PUBLISH_GENERATION_ENV: &str = "MINVMD_PUBLISH_GENERATION";

/// The boot token the publish generation rides to the guest on, beside the
/// port's token: the guest daemon echoes it in every publish report.
/// Mirrors minimald's `HANDED_PUBLISH_GENERATION_TOKEN` — keep the two in
/// step.
const PUBLISH_GENERATION_TOKEN: &str = "MINIMALD_PUBLISH_GENERATION";

/// The environment variable the operator sets to opt the VM out of the
/// deny-all egress default (NET-077). Read twice: by the supervisor, whose
/// host-side registry compiles an undeclared box's row by it, and by the VMM
/// child, which writes it onto the kernel command line for the guest daemon
/// to read (see `EGRESS_DENY_ALL_OPT_OUT_TOKEN`), so the gate on each side of
/// the escape boundary keeps the same default. Inherited through the process
/// tree like [`OWN_IP_ENV`]: the operator sets it in the environment that
/// starts `minvmd run`/`boot`, and the supervisor hands it to the VMM child
/// by inheritance.
pub(crate) const EGRESS_DENY_ALL_OPT_OUT_ENV: &str = "MINVMD_EGRESS_DENY_ALL_OPT_OUT";

/// The boot token the egress opt-out rides to the guest on, beside the port's
/// token: the guest daemon runs the same egress default its host was started
/// with. Mirrors minimald's `HANDED_EGRESS_DENY_ALL_OPT_OUT_TOKEN` — keep the
/// two in step.
const EGRESS_DENY_ALL_OPT_OUT_TOKEN: &str = "MINIMALD_EGRESS_DENY_ALL_OPT_OUT";

/// Kernel command line every microVM boots with: the console the guest's
/// stdout/stderr reaches the host boot log through, and IPv6 disabled (the v1
/// network posture is IPv4-only — design §4.2 keeps IPv6 ULA dual-stack as a
/// later additive, which retires the parameter when it lands). `ipv6.disable=1`
/// is the `ipv6` module's `disable` parameter (`net/ipv6/af_inet6.c`); the
/// kernel parses it for built-in and loadable alike, and `inet6_init` returns
/// before registering anything, so the guest's IPv6 stack never comes up: no
/// interface configures an IPv6 address and the route table never gains an
/// IPv6 entry, loopback included — nothing inside the escape boundary gets a
/// v6 family to ride or for an egress verdict to decide. That is the inside
/// half of the posture only: a guest kernel the attacker holds can be rebuilt
/// with it, so the rule that survives an escape is the host-side egress gate
/// dropping every foreign-family frame; this parameter removes the v6 family
/// from inside the boundary, the gate is what enforces it. `kernel_cmdline`
/// extends the line; nothing else in it is optional.
const BASE_KERNEL_CMDLINE: &str = "console=hvc0 ipv6.disable=1";

/// The kernel's `COMMAND_LINE_SIZE` — the buffer the boot line (including its
/// NUL terminator) must fit in. 2048 on both arm64 and x86_64, the two
/// architectures libkrun boots.
const COMMAND_LINE_SIZE: usize = 2048;

/// Bytes libkrun appends to the line minvmd hands `krun_set_kernel` before
/// the guest kernel sees it, so [`BOOT_LINE_BUDGET`] keeps the whole line
/// inside [`COMMAND_LINE_SIZE`]. minvmd is not the boot line's only writer.
///
/// libkrun v1.19.4 (728df812, `vendor/libkrun/libkrun.lock`) composes the
/// line as minvmd's string, then `krun_env`, then `tsi_hijack`, then an
/// epilog, each `insert_str` preceded by one space and checked against
/// `CMDLINE_MAX_SIZE` by an `unwrap` that panics inside `krun_start_enter`
/// (`src/vmm/src/builder.rs:584-595` and `:1050-1073`,
/// `src/kernel/src/cmdline/mod.rs:94-100`: `len + more + space < capacity`).
/// For the context minvmd builds (no `krun_set_exec`, `_workdir`, `_root`,
/// `_rlimits` or `_env`; vsock ports and no virtio-net device, so TSI is
/// implicit; no DHCP) that is:
///
/// - `krun_env`, `" {} {} {} {} {}"` of five empty parts
///   (`src/libkrun/src/lib.rs:2907-2914`): 5 bytes, 6 with its separator;
/// - `tsi_hijack` (`builder.rs:1053`): 11 bytes;
/// - the epilog `" -- "` with no args (`lib.rs:2915`, `builder.rs:1073`):
///   5 bytes;
///
/// 22 bytes on aarch64, whose `CMDLINE_MAX_SIZE` is 2048
/// (`src/arch/src/aarch64/layout.rs:63`). On x86_64 libkrun's capacity is
/// 64 KiB (`src/arch/src/x86_64/layout.rs:16`), so nothing panics, but it
/// also inserts one ` virtio_mmio.device=4K@0x........:NN` per device
/// (`src/vmm/src/device_manager/kvm/mmio.rs:178-181`, up to 36 bytes; this
/// boot registers balloon, rng, console, root disk, data disk and vsock)
/// before the epilog, and the guest kernel then truncates at its own
/// 2048-byte `COMMAND_LINE_SIZE`, which would cut those device tokens:
/// 22 + 6 × 36 = 238 bytes. 256 covers both, with room for one more device.
const LIBKRUN_CMDLINE_RESERVE: usize = 256;

/// The most bytes minvmd's own part of the boot line may hold:
/// [`COMMAND_LINE_SIZE`] less the NUL terminator and less
/// [`LIBKRUN_CMDLINE_RESERVE`].
const BOOT_LINE_BUDGET: usize = COMMAND_LINE_SIZE - 1 - LIBKRUN_CMDLINE_RESERVE;

/// Environment variable toggling `direct_io` (bypass the host page cache) on the
/// data volume (spec R1.9). Accepts `true` / `1` (any other value is false).
/// Defaults to `false`, correct for guest ext4 (the guest journal and page cache
/// interact poorly with host `O_DIRECT`).
pub const DISK_DIRECT_IO_ENV: &str = "MINVMD_DISK_DIRECT_IO";

/// Which of the spec's deployment models (DM1–DM5) a minvmd host runs under.
///
/// minvmd manages libkrun VMs, which only exist on DM1/DM3/DM4; DM2 is native
/// Linux with no VM boundary. The distinction matters for VM-wide egress
/// (R2.5): a `vm_egress` policy is meaningful only where a VM exists, and is a
/// configuration error on DM2 (see [`VmConfig::validate_for`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// macOS + one or more libkrun Linux VMs.
    Dm1,
    /// Native Linux, minimald on the host directly (no VM).
    Dm2,
    /// Native Linux + one or more Linux VMs.
    Dm3,
    /// DM2 + DM3 combined.
    Dm4,
    /// Any of the above with a network-accessible, authenticated minimald.
    Dm5,
}

/// Configuration parameters for a single microVM.
///
/// Build with [`VmConfig::new`] and apply to a libkrun
/// [`Context`][crate::krun::Context] with [`VmConfig::apply`]. The network mode
/// defaults to [`NetworkMode::HostNet`]; override it with
/// [`VmConfig::with_network_mode`].
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Number of virtual CPUs.
    pub num_vcpus: u8,
    /// RAM in mebibytes.
    pub ram_mib: u32,
    /// Kernel image path.
    pub kernel_path: PathBuf,
    /// Path to the read-only ext4 root disk image (loaded via `krun_add_disk2`
    /// as `/dev/vda`). The initramfs `/init` (minimald) mounts + chroots into it.
    pub rootfs_path: PathBuf,
    /// Initramfs image the kernel boots: it unpacks into a RAM root and runs its
    /// `/init` (minimald as pid-1), instead of booting a block-device root. This
    /// is how minimald is shipped as pid-1 without baking it into the rootfs.
    pub initramfs: PathBuf,
    /// How this VM attaches to the per-host gvproxy switch (R1.5). Defaults to
    /// [`NetworkMode::HostNet`]; an `OwnIp` VM is wired to the switch as a
    /// client via the per-PTask vsock shuttle.
    pub network_mode: NetworkMode,
    /// VM-wide egress policy applied to all traffic from this VM, regardless of
    /// per-PTask mode (R2.5). Only meaningful on a deployment model with a VM
    /// boundary (DM1/DM3/DM4); rejected on DM2 by [`VmConfig::validate_for`].
    /// `None` means no VM-wide egress restriction.
    pub vm_egress: Option<EgressPolicy>,
    /// Path to the per-VM writable data volume image, attached as `/dev/vdb`
    /// via `krun_add_disk3` (spec R1.4). `None` means no data volume is attached
    /// (legacy tmpfs-only boot). Provision the image with
    /// [`crate::volume::ensure_sparse_raw`] before setting this.
    pub data_volume_path: Option<PathBuf>,
}

impl VmConfig {
    /// Construct a new `VmConfig`.
    #[must_use]
    pub fn new(
        num_vcpus: u8,
        ram_mib: u32,
        kernel_path: PathBuf,
        rootfs_path: PathBuf,
        initramfs: PathBuf,
    ) -> Self {
        Self {
            num_vcpus,
            ram_mib,
            kernel_path,
            rootfs_path,
            initramfs,
            network_mode: NetworkMode::default(),
            vm_egress: None,
            data_volume_path: None,
        }
    }

    /// Set the VM network mode (R1.5), consuming and returning `self`.
    #[must_use]
    pub fn with_network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = network_mode;
        self
    }

    /// Attach a per-VM writable data volume image as `/dev/vdb` (spec R1.4),
    /// consuming and returning `self`. The image must already be provisioned
    /// (see [`crate::volume::ensure_sparse_raw`]).
    #[must_use]
    pub fn with_data_volume(mut self, data_volume_path: PathBuf) -> Self {
        self.data_volume_path = Some(data_volume_path);
        self
    }

    /// Set the VM-wide egress policy (R2.5), consuming and returning `self`.
    #[must_use]
    pub fn with_vm_egress(mut self, vm_egress: EgressPolicy) -> Self {
        self.vm_egress = Some(vm_egress);
        self
    }

    /// Validates this config against the active deployment model (R2.5).
    ///
    /// `vm_egress` is VM-wide egress, meaningful only where a VM boundary exists
    /// (DM1/DM3/DM4). On DM2 (native Linux, minimald on the host with no VM) it
    /// has nothing to apply to and collapses to per-PTask egress (UC3), so a
    /// `vm_egress` set on DM2 is a configuration error rather than a silent
    /// no-op. [`DeploymentMode::Dm5`] does not by itself encode an underlying
    /// model, so it may resolve to DM2 (no VM boundary); `vm_egress` is rejected
    /// there too — fail closed rather than silently accept a policy that might
    /// have nothing to enforce it — until the underlying model is resolved.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::Configuration`] when `vm_egress` is set and `mode` is
    /// [`DeploymentMode::Dm2`] or [`DeploymentMode::Dm5`], or
    /// [`VmError::InvalidEgressSubnet`] when `vm_egress` is accepted for `mode`
    /// but carries an `allow_subnets` entry that is not a valid CIDR prefix.
    pub fn validate_for(&self, mode: DeploymentMode) -> Result<(), VmError> {
        if let Some(vm_egress) = self.vm_egress.as_ref() {
            let reason = match mode {
                DeploymentMode::Dm2 => Some(
                    "VM-wide egress is not applicable on DM2 (native Linux has no VM \
                     boundary); use per-PTask egress instead",
                ),
                DeploymentMode::Dm5 => Some(
                    "VM-wide egress cannot be applied on DM5 until its underlying \
                     deployment model is resolved; DM5 does not by itself guarantee a \
                     VM boundary to enforce it",
                ),
                DeploymentMode::Dm1 | DeploymentMode::Dm3 | DeploymentMode::Dm4 => None,
            };
            if let Some(reason) = reason {
                return Err(VmError::Configuration {
                    what: "vm_egress",
                    reason,
                });
            }
            // vm_egress is accepted for this mode (a VM boundary exists); validate
            // that each allow_subnets entry is a syntactically valid CIDR prefix,
            // mirroring the per-PTask egress check in
            // `sessions::Record::validate_policy`, so a misconfigured subnet is
            // named here rather than failing opaquely when #553's enforcement
            // layer parses it.
            if let Some(bad) = vm_egress.first_invalid_subnet() {
                return Err(VmError::InvalidEgressSubnet {
                    cidr: bad.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Whether this VM joins the per-host gvproxy switch as an own-IP client.
    ///
    /// Only an [`NetworkMode::OwnIp`] VM provisions a tap + relay; `HostNet` and
    /// `NoNet` never attach to the switch (R1.5).
    #[must_use]
    pub fn is_own_ip(&self) -> bool {
        matches!(self.network_mode, NetworkMode::OwnIp)
    }

    /// The tap interface name this VM's own-IP PTask is bridged onto, derived
    /// from `index` so each PTask on a host gets a distinct, deterministic name.
    ///
    /// The name fits the kernel's 15-char `IFNAMSIZ` limit for any `u32` index.
    #[must_use]
    pub fn tap_name(index: u32) -> String {
        format!("vmtap{index}")
    }

    /// Apply this configuration to an existing libkrun [`Context`][crate::krun::Context].
    ///
    /// Configures vcpus, RAM, kernel + initramfs, the ext4 root disk, and the
    /// host UDS↔vsock bridge for minimald (R3.1).
    #[cfg(minvmd_libkrun)]
    pub fn apply(&self, ctx: &mut crate::krun::Context) -> Result<(), crate::error::VmError> {
        ctx.set_vm_config(self.num_vcpus, self.ram_mib)?;

        // Initramfs boot: the kernel unpacks the initramfs into a RAM root and
        // runs its `/init` (no `root=`/`init=` cmdline). minimald-as-/init mounts
        // devtmpfs itself, then mounts the rootfs disk below and chroots into it.
        //
        // The boot line also carries the host's RUST_LOG and the supervisor's
        // node proxy port to the guest daemon as environment variables: the
        // kernel command line is the only vector, since the guest `/init` is
        // minimald itself and the kernel starts it with an empty environment
        // (see `kernel_cmdline`). Bound to a local so the &str handed to
        // `set_kernel` outlives the call.
        let rust_log = std::env::var(GUEST_LOG_ENV).ok();
        let node_proxy_port = node_proxy_port_from_env()?;
        let publish_generation = publish_generation_from_env()?;
        let egress_deny_all_opt_out = egress_deny_all_opt_out_from_env();
        // The host's telemetry decision crosses the same way, under the
        // guest's own `MINIMAL_` names and never with an endpoint, headers
        // or credentials (`telemetry::guest_env`, TEL-033); nothing is
        // added when telemetry is off on the host. The `TRACEPARENT` this
        // process inherited from the supervisor makes the guest daemon's boot
        // spans children of the supervisor's `vm.boot`.
        let guest_env = crate::telemetry::guest_env(
            |k| std::env::var(k).ok(),
            mlog::otel::telemetry_enabled(),
            // The forward port crosses when the supervisor bound the door
            // this child registers the port for (TEL-034).
            std::env::var_os(crate::guest_telemetry::GUEST_TELEMETRY_SOCK_ENV)
                .filter(|p| !p.is_empty())
                .map(|_| crate::guest_telemetry::VSOCK_TELEMETRY_PORT),
            std::env::var(minimald_rpc::trace::TRACEPARENT_ENV)
                .ok()
                .as_deref(),
        );
        let cmdline = with_guest_env(
            kernel_cmdline(
                rust_log.as_deref(),
                node_proxy_port,
                publish_generation,
                egress_deny_all_opt_out,
            ),
            &guest_env,
        );
        // The boot line at info, not debug: the kernel echoes it back as
        // `Kernel command line: …` only once its console is up, and this is
        // the one line that says what the guest was told to boot with — a
        // missing or mistyped parameter (`ipv6.disable=1` among them) is
        // diagnosable from the host before the guest says anything.
        // The telemetry tokens by name only (TEL-040): minvmd's info log is
        // exported and spooled when telemetry is on.
        tracing::info!(
            cmdline = %loggable_boot_line(&cmdline, &guest_env),
            "composed the guest boot line"
        );
        ctx.set_kernel(
            &self.kernel_path,
            crate::image::kernel_format(),
            Some(&self.initramfs),
            Some(cmdline.as_ref()),
        )?;
        // Attach the rootfs as a block device (/dev/vda) for the initramfs
        // `/init` to mount + chroot into; the kernel root is the initramfs.
        ctx.add_disk(
            "root",
            &self.rootfs_path,
            crate::krun::DiskFormat::Raw,
            true,
        )?;
        // Attach the per-VM writable data volume as /dev/vdb (spec R1.4). Disks
        // are enumerated vd{a,b,…} in registration order, so this follows the
        // read-only root. The sync/cache posture is resolved from the R1.9
        // tunables rather than hardcoded, so its throughput cost can be measured
        // (Proof Artifact 4) and tuned per platform.
        if let Some(data_path) = &self.data_volume_path {
            let (direct_io, sync_mode) = resolve_disk_flags();
            tracing::info!(
                data_path = %data_path.display(),
                direct_io,
                ?sync_mode,
                "attaching writable data volume as /dev/vdb",
            );
            ctx.add_disk_with_sync(
                "data",
                data_path,
                crate::krun::DiskFormat::Raw,
                false,
                direct_io,
                sync_mode,
            )?;
        }
        // Network attachment (R1.5): the VM joins the per-host gvproxy switch
        // supervised by `crate::net` according to `network_mode`. The libkrun
        // device wiring (tap fd handed to gvproxy over the per-PTask vsock
        // shuttle) is driven by the switch handle, not configured here; record
        // the selected mode so a stuck boot can be diagnosed.
        tracing::debug!(network_mode = %self.network_mode.word(), "VM network mode selected");

        // R3.1: register the host UDS bridge (listen=true). libkrun listens on
        // the host UDS and bridges each accepted connection to the guest process
        // listening on vsock VSOCK_BRIDGE_PORT.
        let uds_path = crate::sock::resolve_uds_path()
            .map_err(|source| crate::error::VmError::Io { source })?;
        crate::sock::check_uds_path_len(&uds_path)
            .map_err(|source| crate::error::VmError::Io { source })?;
        crate::sock::prepare_socket_dir(&uds_path)
            .map_err(|source| crate::error::VmError::Io { source })?;
        // Drop a stale socket from a prior run; libkrun's listen-bind fails
        // EEXIST otherwise (e.g. on a persistent runner).
        crate::sock::remove_stale_socket(&uds_path)
            .map_err(|source| crate::error::VmError::Io { source })?;
        // R3.5: TSI ~62-concurrent-connection cap. libkrun's TSI layer
        // multiplexes guest vsock connections over a single host transport; the
        // practical ceiling is ~62 concurrent connections on this port before
        // new ones queue. Acceptable for v0.1 workloads (<10 concurrent).
        ctx.add_vsock_port2(crate::sock::VSOCK_BRIDGE_PORT, &uds_path, true)?;

        // gvproxy shuttle bridge, through the host-side egress gate (NET-081).
        // The guest connects to AF_VSOCK CID 2 (the host) on
        // VSOCK_GVPROXY_SHUTTLE_PORT; with `listen = false` libkrun dials the
        // named host socket and splices the two, carrying raw L2 frames between
        // a guest tap and the host. Since NET-081 the named socket is the
        // **egress gate's**, not the switch's own: the gate — started by the
        // switch runtime before the VM boots (see `crate::net`) — decides every
        // frame against the host-side table of published namespaces
        // (`crate::box_registry`) by the source address it carries, and relays
        // only what the shared frame verdict admits on to the gvproxy switch (the
        // single gVisor stack). Per-box egress rules are thereby applied **outside
        // the VM**, where nothing inside the escape boundary can change them, and
        // a frame whose source address no namespace holds is dropped outside the
        // plan's lease block — everywhere, once the per-box default binds; under
        // the announced interim this build ships, an in-plan source no row holds
        // is admitted, every admit warned (`egress_gate` carries the phase and
        // why). Registered for every VM, not just own-IP: the guest's root netns (the
        // daemon) attaches a primary tap here for egress, and own-IP PTasks
        // attach further taps as additional clients on the same switch. If the
        // gate (or the switch behind it) did not come up, the guest's connect
        // simply fails and the relay reports no egress — boot is unaffected.
        let gate_sock = crate::net::resolve_gate_sock()
            .map_err(|source| crate::error::VmError::Io { source })?;
        crate::sock::check_uds_path_len(&gate_sock)
            .map_err(|source| crate::error::VmError::Io { source })?;
        ctx.add_vsock_port2(crate::net::VSOCK_GVPROXY_SHUTTLE_PORT, &gate_sock, false)?;
        tracing::info!(
            port = crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            gate_sock = %gate_sock.display(),
            "registered gvproxy shuttle vsock bridge behind the host-side egress gate",
        );
        Ok(())
    }
}

/// One `KEY=VALUE` boot token carrying a host-supplied `value` to the guest,
/// or why `value` cannot be one. Every such token minvmd puts on the boot
/// line is built here ([`kernel_cmdline`] for `RUST_LOG`,
/// `telemetry::guest_env` for the telemetry settings), so the line's grammar
/// has one writer.
///
/// The line has two readers, and a value must be exactly one token to both:
///
/// - libkrun's `Cmdline` accepts only `' '..='~'` and `unwrap`s the insert,
///   so any other char — a UTF-8 multibyte, a C0 control — panics inside
///   `krun_start_enter` and aborts minvmd (libkrun v1.19.4
///   `src/kernel/src/cmdline/mod.rs:51-52`, `src/vmm/src/builder.rs:586`);
/// - the kernel's `next_arg` (`lib/cmdline.c`) splits on `isspace` outside
///   quotes, toggles quote state on every `"`, and strips a quote pair around
///   a value, so whitespace splits a value into further tokens and a `"`
///   merges every later token into this one, or silently unquotes it.
///
/// The alphabet is their intersection: printable ASCII `0x21..=0x7E` minus
/// `"`. A value outside it is refused, never rewritten or quoted (a value
/// with a byte cut out means something else), and the caller warns and
/// boots without it. Within the alphabet the value crosses byte for byte.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
pub(crate) fn boot_token(key: &str, value: &str) -> Result<String, &'static str> {
    if let Some(fault) = token_fault(value.as_bytes()) {
        return Err(fault.reason());
    }
    // Copied, not formatted: the token is the key, `=` and the value byte
    // for byte, and a copy is what the tests below can follow.
    let mut token = String::with_capacity(key.len() + 1 + value.len());
    token.push_str(key);
    token.push('=');
    token.push_str(value);
    Ok(token)
}

/// Why a value cannot be a boot token: the class of its first byte outside
/// the alphabet, or that it has no bytes at all. One variant per class so a
/// proof can compare verdicts without comparing strings; [`Self::reason`]
/// is the text a caller logs.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenFault {
    /// No bytes: `key=` would hand the guest an empty variable.
    Empty,
    /// A `"`, which the kernel's tokenizer would merge later tokens into.
    Quote,
    /// ASCII whitespace, which the kernel would split the value on.
    Whitespace,
    /// Any other byte outside printable ASCII, which libkrun refuses.
    Outside,
}

impl TokenFault {
    /// The reason a caller logs; fixed text per class.
    #[cfg_attr(
        all(not(minvmd_libkrun), not(test), not(kani)),
        expect(
            dead_code,
            reason = "used only by the libkrun build; the tests and proofs cover it on every target"
        )
    )]
    fn reason(self) -> &'static str {
        match self {
            Self::Empty => "value is empty",
            Self::Quote => {
                "value contains a double quote, which the kernel would merge later tokens into"
            }
            Self::Whitespace => {
                "value contains whitespace, which the kernel would split into separate boot tokens"
            }
            Self::Outside => "value contains a byte outside printable ASCII, which libkrun refuses",
        }
    }
}

/// The recognizer behind [`boot_token`], on bytes alone: `None` when
/// `value` is non-empty and every byte passes [`boot_byte`], else the class
/// of the first byte that does not (or [`TokenFault::Empty`]). No string is
/// built or compared here, so a proof can run it over every byte value in
/// every position of a short value.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
fn token_fault(value: &[u8]) -> Option<TokenFault> {
    if value.is_empty() {
        return Some(TokenFault::Empty);
    }
    match value.iter().find(|b| !boot_byte(**b)) {
        None => None,
        Some(b'"') => Some(TokenFault::Quote),
        Some(b) if b.is_ascii_whitespace() => Some(TokenFault::Whitespace),
        Some(_) => Some(TokenFault::Outside),
    }
}

/// Whether `b` may appear in a boot token: printable ASCII minus `"`; see
/// [`boot_token`].
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
fn boot_byte(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != b'"'
}

/// The bytes a line of `base_len` bytes takes once every token in
/// `token_lens` follows it, one separating space before each. The one
/// place the boot line's length is reckoned, so [`append_tokens`] and the
/// proofs below judge the same sum.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
fn line_len(base_len: usize, token_lens: impl IntoIterator<Item = usize>) -> usize {
    token_lens
        .into_iter()
        .fold(base_len, |len, token| len + 1 + token)
}

/// The verdict on a line of `base_len` bytes with tokens of `token_lens`
/// after it, passed on lengths alone: the length [`line_len`] reckons, as
/// `Ok` when it is within [`BOOT_LINE_BUDGET`] and as `Err` when it is not.
/// The one place that decides whether tokens cross, so [`append_tokens`]
/// and the proofs below pass the same judgement — and the proofs state it
/// on lengths, never on a string, which keeps them cheap to verify.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
fn within_budget(
    base_len: usize,
    token_lens: impl IntoIterator<Item = usize>,
) -> Result<usize, usize> {
    let total = line_len(base_len, token_lens);
    if total > BOOT_LINE_BUDGET {
        Err(total)
    } else {
        Ok(total)
    }
}

/// `base` with every token in `tokens` after it, one space before each, when
/// that line is within [`BOOT_LINE_BUDGET`]; otherwise the length the line
/// would have had, and no line. The pure core of [`kernel_cmdline`]'s filter
/// step and of [`with_guest_env`]: a line comes back whole or not at all,
/// never cut inside a token. [`within_budget`] decides; this only copies.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test), not(kani)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests and proofs cover it on every target"
    )
)]
fn append_tokens(base: &str, tokens: &[String]) -> Result<String, usize> {
    let total = within_budget(base.len(), tokens.iter().map(String::len))?;
    let mut line = String::with_capacity(total);
    line.push_str(base);
    for t in tokens {
        line.push(' ');
        line.push_str(t);
    }
    Ok(line)
}

/// Build the guest kernel command line, forwarding `RUST_LOG` when the host has
/// one worth forwarding and the node's proxy port when the supervisor handed
/// it.
///
/// The microVM's `/init` **is** minimald, so the kernel starts it with an empty
/// environment — nothing from the host process crosses the VM boundary, and the
/// guest daemon's log level is otherwise unraisable from the host. The kernel
/// hands init every `KEY=VALUE` boot token it does not recognise itself
/// (`init/main.c`: `unknown_bootoption` → `envp_init`), so `RUST_LOG=<value>` on
/// the command line arrives as an environment variable and reaches minimald's
/// `EnvFilter::try_from_default_env()`, and the proxy port arrives the same way
/// (`node_proxy_port_from_env` reads it from the VMM child's env, where the
/// supervisor put it — `cmd/run` assigns it before the boot, NET-025). The
/// zone-answerer port is deliberately not handed: on a VM-backed host the
/// in-VM daemon starts no answerer (NET-138) and the host's answerer serves the
/// zone, so a token carrying an answerer port would be an admitted port with
/// nothing behind it.
///
/// Two things a caller setting `RUST_LOG` must know:
///
/// - It **replaces** minimald's default filter outright, including that
///   default's `topiary=off` and `libcgroups=off` directives (see
///   `crates/minimald/src/main.rs`). `RUST_LOG=debug` therefore also turns those
///   subsystems on; repeat the directives in the value to keep them off.
/// - The boot line is world-readable inside the guest as `/proc/cmdline`, so it
///   must never carry a secret.
///
/// The values are injected rather than read from the process environment here,
/// so this stays pure and unit-testable; the caller passes
/// `std::env::var(GUEST_LOG_ENV).ok()`, `node_proxy_port_from_env()`,
/// `publish_generation_from_env()` and `egress_deny_all_opt_out_from_env()` —
/// the boot's publish generation (T93), which the guest daemon echoes in its
/// publish reports, rides beside the port and, like it, is never skipped; the
/// egress opt-out (NET-077) rides the same way, and is only written when the
/// operator set it. A `RUST_LOG` value that cannot survive the boot line is
/// skipped (leaving the base line plus the port, generation and opt-out
/// tokens byte-identical) with a warning, rather than corrupting the boot: a
/// value outside the boot alphabet is not one token to the kernel or not a
/// line libkrun accepts ([`boot_token`]), an empty value carries nothing, and
/// an over-long one would push the line past [`BOOT_LINE_BUDGET`]. The port,
/// the generation and the opt-out are never skipped — the guest binds the
/// port as handed — so their tokens count against the budget when the
/// filter's length is judged. Commas are untouched — `info,russh=debug` is
/// the normal form.
// Only `apply` calls this, and `apply` needs libkrun; without it the crate is a
// runtime-bailing stub, but the tests below still cover this on every target.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
fn kernel_cmdline(
    rust_log: Option<&str>,
    proxy_port: Option<u16>,
    publish_generation: Option<u64>,
    egress_deny_all_opt_out: bool,
) -> Cow<'static, str> {
    // The port rides the boot line first: base, then the port token, then the
    // publish generation beside it, then the egress opt-out when the operator
    // set it, then the filter when one is forwarded.
    let base_with_port = match (proxy_port, publish_generation) {
        (Some(proxy), Some(generation)) => Cow::Owned(format!(
            "{BASE_KERNEL_CMDLINE} {HOSTNAME_PROXY_PORT_TOKEN}={proxy} \
             {PUBLISH_GENERATION_TOKEN}={generation}"
        )),
        (Some(proxy), None) => Cow::Owned(format!(
            "{BASE_KERNEL_CMDLINE} {HOSTNAME_PROXY_PORT_TOKEN}={proxy}"
        )),
        (None, Some(generation)) => Cow::Owned(format!(
            "{BASE_KERNEL_CMDLINE} {PUBLISH_GENERATION_TOKEN}={generation}"
        )),
        (None, None) => Cow::Borrowed(BASE_KERNEL_CMDLINE),
    };

    let base_with_port = if egress_deny_all_opt_out {
        Cow::Owned(format!(
            "{base_with_port} {EGRESS_DENY_ALL_OPT_OUT_TOKEN}=1"
        ))
    } else {
        base_with_port
    };

    let Some(value) = rust_log else {
        return base_with_port;
    };

    // `<base-with-port> RUST_LOG=<value>`, judged against the budget that
    // leaves libkrun's suffix and the NUL inside the kernel's buffer.
    let token = match boot_token(GUEST_LOG_ENV, value) {
        Ok(token) => token,
        Err(reason) => return skip_log_filter(base_with_port, value, reason),
    };
    match append_tokens(&base_with_port, std::slice::from_ref(&token)) {
        Ok(line) => Cow::Owned(line),
        Err(_) => skip_log_filter(
            base_with_port,
            value,
            "value would push the boot line past the budget that keeps libkrun's suffix inside \
             the kernel's COMMAND_LINE_SIZE",
        ),
    }
}

/// The boot line without the host's `RUST_LOG`, warning why it was skipped;
/// see [`kernel_cmdline`].
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
fn skip_log_filter(
    base_with_port: Cow<'static, str>,
    value: &str,
    reason: &'static str,
) -> Cow<'static, str> {
    tracing::warn!(
        env = GUEST_LOG_ENV,
        value_len = value.len(),
        reason,
        "not forwarding the host log filter to the guest; the guest keeps minimald's default \
         filter",
    );
    base_with_port
}

/// Reads the node's proxy port the supervisor handed the VMM child in its env
/// (see [`NODE_PROXY_PORT_ENV`]). Transport decoding only — the supervisor
/// resolves the port once (override or selection, `cmd/run.rs`) and hands
/// the one resolution down, so anything this decode cannot accept is a boot
/// error naming the variable and the value, never a silent fallback that
/// would let the guest select a port different from the one the node row
/// registered. `Ok(None)` when the variable is absent — the boot does
/// not run under the supervisor, and the guest daemon then selects its own
/// ports, the pre-handoff behaviour. A `0` passes through: the guest's own
/// handed-port policy reads it as "select one yourself".
// Only `apply` calls this; see `kernel_cmdline` for the cfg note.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn node_proxy_port_from_env() -> Result<Option<u16>, crate::error::VmError> {
    node_proxy_port_from_raw(std::env::var(NODE_PROXY_PORT_ENV).ok().as_deref())
}

/// Decodes a handed node proxy port from its raw env value. A value that does
/// not decode fails the boot naming the variable and the value.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn node_proxy_port_from_raw(proxy: Option<&str>) -> Result<Option<u16>, crate::error::VmError> {
    let Some(raw) = proxy else {
        return Ok(None);
    };
    match raw.trim().parse::<u16>() {
        Ok(port) => Ok(Some(port)),
        Err(_) => Err(crate::error::VmError::Io {
            source: std::io::Error::other(format!(
                "environment variable {NODE_PROXY_PORT_ENV} carries {raw:?}, which is not a port"
            )),
        }),
    }
}

/// Reads this boot's publish generation the supervisor handed the VMM child
/// (see [`PUBLISH_GENERATION_ENV`]). Strict like the port's decode: absent
/// is a boot outside the supervisor (no token), and a value that is not a
/// generation fails the boot naming the variable and the value.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn publish_generation_from_env() -> Result<Option<u64>, crate::error::VmError> {
    publish_generation_from_raw(std::env::var(PUBLISH_GENERATION_ENV).ok().as_deref())
}

/// Decodes a handed publish generation from its raw env value.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn publish_generation_from_raw(raw: Option<&str>) -> Result<Option<u64>, crate::error::VmError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw.trim().parse::<u64>() {
        Ok(generation) => Ok(Some(generation)),
        Err(_) => Err(crate::error::VmError::Io {
            source: std::io::Error::other(format!(
                "environment variable {PUBLISH_GENERATION_ENV} carries {raw:?}, \
                 which is not a publish generation"
            )),
        }),
    }
}

/// Whether the operator opted the VM out of the deny-all egress default
/// (NET-077), read from [`EGRESS_DENY_ALL_OPT_OUT_ENV`] through the parse the
/// guest shares ([`sessions::egress_deny_all_opt_out_from_raw`]):
/// `1`/`true`/`yes`/`on`, case-insensitive; unset or any other value is
/// `false` — the build's egress default. Read by both processes that need it,
/// as [`OWN_IP_ENV`] is: the supervisor, for the host-side registry's
/// undeclared-row default, and the VMM child, which writes it onto the boot
/// line. Both inherit the operator's environment, so the value set on the
/// process that starts `minvmd run`/`boot` reaches each.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) fn egress_deny_all_opt_out_from_env() -> bool {
    sessions::egress_deny_all_opt_out_from_raw(
        std::env::var(EGRESS_DENY_ALL_OPT_OUT_ENV).ok().as_deref(),
    )
}

/// Append `tokens` (`KEY=VALUE` boot tokens from [`crate::telemetry::guest_env`],
/// each built by [`boot_token`]) to `base`, all of them or none: if they
/// would push the line past [`BOOT_LINE_BUDGET`], the guest boots with
/// `base` and a warning, since a half-forwarded telemetry configuration (an
/// enable without its endpoint) would export somewhere unintended or
/// nowhere. The cut is at a token boundary, never inside a value.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
fn with_guest_env(base: Cow<'static, str>, tokens: &[String]) -> Cow<'static, str> {
    if tokens.is_empty() {
        return base;
    }
    match append_tokens(&base, tokens) {
        Ok(line) => Cow::Owned(line),
        Err(total) => {
            tracing::warn!(
                tokens = tokens.len(),
                total,
                budget = BOOT_LINE_BUDGET,
                "not forwarding telemetry settings to the guest: the boot line would pass the \
                 budget that keeps libkrun's suffix inside the kernel's COMMAND_LINE_SIZE",
            );
            base
        }
    }
}

/// `cmdline` as minvmd logs it: every word as it is, except a telemetry
/// token from `tokens` ([`crate::telemetry::guest_env`]), which is logged
/// as its key alone, `KEY=…`. The kernel's own parameters stay readable,
/// so a missing or mistyped one is still diagnosable from the host, and no
/// telemetry value (the filter, `TRACEPARENT`) reaches the log, which is
/// exported and spooled when telemetry is on (TEL-040). A token the budget
/// dropped is not in `cmdline` and is not logged at all.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
fn loggable_boot_line(cmdline: &str, tokens: &[String]) -> String {
    cmdline
        .split(' ')
        .map(|word| match word.split_once('=') {
            Some((key, _)) if tokens.iter().any(|t| t == word) => format!("{key}=…"),
            _ => word.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Resolve the data-volume `(direct_io, sync_mode)` from the R1.9 environment
/// tunables ([`DISK_DIRECT_IO_ENV`], [`DISK_SYNC_ENV`]). Defaults: `direct_io =
/// false`, `sync_mode = Relaxed`.
#[cfg(minvmd_libkrun)]
fn resolve_disk_flags() -> (bool, crate::krun::SyncMode) {
    use crate::krun::SyncMode;

    let direct_io = match std::env::var(DISK_DIRECT_IO_ENV) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => {
                tracing::warn!(
                    env = DISK_DIRECT_IO_ENV,
                    value = %v,
                    "unrecognized value; using default direct_io=false",
                );
                false
            }
        },
        Err(_) => false,
    };

    let sync_mode = match std::env::var(DISK_SYNC_ENV) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "none" | "false" | "0" => SyncMode::None,
            "relaxed" | "true" | "1" => SyncMode::Relaxed,
            "full" | "2" => SyncMode::Full,
            _ => {
                tracing::warn!(
                    env = DISK_SYNC_ENV,
                    value = %v,
                    "unrecognized value; using default sync_mode=relaxed",
                );
                SyncMode::Relaxed
            }
        },
        Err(_) => SyncMode::Relaxed,
    };

    (direct_io, sync_mode)
}

/// The widest line [`kernel_cmdline`] can make before the filter: every
/// token it adds to the base line present, the port and the publish
/// generation at their most digits and the egress opt-out set. The proofs
/// take it as the bound on the base line, and
/// `widest_base_len_covers_every_base_token` checks it against
/// `kernel_cmdline` itself, so a token added there has to be added here.
#[cfg(any(test, kani))]
fn widest_base_len() -> usize {
    line_len(
        BASE_KERNEL_CMDLINE.len(),
        [
            HOSTNAME_PROXY_PORT_TOKEN.len() + 1 + "65535".len(),
            PUBLISH_GENERATION_TOKEN.len() + 1 + "18446744073709551615".len(),
            EGRESS_DENY_ALL_OPT_OUT_TOKEN.len() + "=1".len(),
        ],
    )
}

#[cfg(kani)]
mod kani_proofs {
    //! Bounded proofs over the boot line, all on bytes and lengths, never
    //! on a `String`. The two alphabet proofs run `boot_byte` over every
    //! byte and `token_fault` over every byte value in every position of a
    //! value of up to `N` bytes; the three budget proofs state the budget
    //! on symbolic `usize`s into `line_len` and `within_budget`. CBMC
    //! models every byte of a `String`, and a `String` of symbolic chars
    //! (UTF-8 encoding, `push_str`, `with_capacity`, a memcmp of the result)
    //! is what took the lane past 300 GB and then past a 64 GB ceiling, so
    //! the one claim that needs the `String` — that `boot_token` returns
    //! `key=value` byte for byte with no whitespace and no NUL — is a plain
    //! test over every one-char value and a set of longer ones
    //! (`every_accepted_token_is_key_equals_value`), as the bytes of a line
    //! at the budget are (`a_filter_at_the_budget_crosses_whole_or_not_at_all`,
    //! `guest_env_tokens_at_the_budget_cross_all_or_none`).
    use super::{
        BOOT_LINE_BUDGET, COMMAND_LINE_SIZE, GUEST_LOG_ENV, LIBKRUN_CMDLINE_RESERVE, TokenFault,
        boot_byte, line_len, token_fault, widest_base_len, within_budget,
    };

    /// Bytes in a proved value. Three covers the first-offending-byte rule:
    /// an offender behind up to two legal bytes, behind another offender of
    /// the same or another class, and ahead of either; every position
    /// ranges over all 256 byte values. More bytes only multiply the cost.
    const N: usize = 3;

    /// The alphabet both readers of the boot line agree on, stated here on
    /// its own so the proofs do not lean on `boot_byte`: printable ASCII
    /// `0x21..=0x7E` without `"`.
    fn in_alphabet(b: u8) -> bool {
        (0x21..=0x7e).contains(&b) && b != b'"'
    }

    /// `boot_byte` is the alphabet exactly: for every one of the 256 byte
    /// values it holds iff the byte is printable ASCII `0x21..=0x7E` and not
    /// `"`. No whitespace byte, no NUL and no byte from `0x80` up passes, so
    /// a value it admits has nothing the kernel splits on, nothing it quotes
    /// and nothing libkrun refuses. No loop, so no unwinding bound.
    #[kani::proof]
    fn boot_byte_is_printable_ascii_without_a_quote() {
        let b: u8 = kani::any();
        assert_eq!(boot_byte(b), in_alphabet(b));
        if boot_byte(b) {
            assert!(!b.is_ascii_whitespace(), "whitespace passes");
            assert_ne!(b, 0, "NUL passes");
            assert_ne!(b, b'"', "a quote passes");
            assert!(b.is_ascii_graphic(), "a byte libkrun refuses passes");
        }
    }

    // Unwinding for the token proof: the longest loop is `token_fault`'s
    // `find` over the value's up to `N` bytes (the harness's own `find` is
    // the same length), and a Rust `for` needs one unwinding more than its
    // iterations, so `N + 1` (4 at `N = 3`) is the least that verifies; 5
    // leaves one spare. The attribute takes a literal, so the figure is
    // written out.

    /// `token_fault` is the whole of `boot_token`'s verdict: for a value of
    /// any length up to `N`, each byte any of the 256 values, it is `None`
    /// exactly when the value is non-empty and every byte is in the
    /// alphabet, and otherwise names the class of the first byte outside
    /// it — `Empty` for no bytes, else `Quote`, `Whitespace` or `Outside`
    /// by that byte alone, whatever follows it.
    #[kani::proof]
    #[kani::unwind(5)]
    fn token_fault_names_the_first_byte_outside_the_alphabet() {
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let value = &bytes[..len];
        let first_outside = value.iter().copied().find(|b| !in_alphabet(*b));
        match token_fault(value) {
            None => {
                assert!(!value.is_empty(), "an empty value was accepted");
                assert!(
                    first_outside.is_none(),
                    "a value outside the alphabet was accepted"
                );
            }
            Some(TokenFault::Empty) => assert!(value.is_empty(), "a value with bytes is empty"),
            Some(fault) => {
                let b = first_outside.expect("a value inside the alphabet was refused");
                let want = if b == b'"' {
                    TokenFault::Quote
                } else if b.is_ascii_whitespace() {
                    TokenFault::Whitespace
                } else {
                    TokenFault::Outside
                };
                assert_eq!(fault, want, "the reason is not the first offending byte's");
            }
        }
    }

    // Unwinding for the three budget proofs: their only loops are
    // `line_len`'s fold over an array of one or two token lengths, two
    // iterations at most, so three unwindings — and, in the first, the same
    // fold over `widest_base_len`'s three token lengths, so four there; a
    // loop that ran longer would fail the unwinding assertion out loud rather
    // than unwind without a bound, which is what a harness with no attribute
    // lets CBMC do.

    /// The budget is the kernel's buffer less the NUL and less libkrun's
    /// reserve, so a line within it, with libkrun's suffix appended, fits
    /// `COMMAND_LINE_SIZE`; and for a `RUST_LOG` value of any length `n`
    /// behind a base line of any length up to the widest the port, the
    /// generation and the egress opt-out can make (`widest_base_len`), the
    /// verdict is `Ok` exactly when
    /// `n <= BOOT_LINE_BUDGET - base - len("RUST_LOG=") - 1`, so a filter
    /// is forwarded or skipped on its length alone, and a one-byte filter
    /// always fits: the port, the generation and the opt-out, which are
    /// never skipped, never fill the budget on their own.
    #[kani::proof]
    #[kani::unwind(4)]
    fn the_budget_leaves_libkrun_its_reserve() {
        assert_eq!(
            BOOT_LINE_BUDGET + LIBKRUN_CMDLINE_RESERVE + 1,
            COMMAND_LINE_SIZE
        );
        let base_len: usize = kani::any();
        kani::assume(base_len <= widest_base_len());
        let n: usize = kani::any();
        kani::assume(n <= COMMAND_LINE_SIZE + 16);
        let room = BOOT_LINE_BUDGET - base_len - GUEST_LOG_ENV.len() - 2;
        match within_budget(base_len, [GUEST_LOG_ENV.len() + 1 + n]) {
            Ok(total) => {
                assert!(n <= room, "a filter past the room was forwarded");
                assert!(
                    total + LIBKRUN_CMDLINE_RESERVE + 1 <= COMMAND_LINE_SIZE,
                    "a line within the budget leaves libkrun no room"
                );
            }
            Err(_) => assert!(n > room, "a filter within the room was skipped"),
        }
        assert!(
            matches!(within_budget(base_len, [GUEST_LOG_ENV.len() + 2]), Ok(_)),
            "a one-byte filter does not fit behind the port, the generation and the opt-out"
        );
    }

    /// A filter token is forwarded or skipped whole, on its length alone:
    /// for a base line and a token of any lengths up to the kernel's buffer,
    /// the verdict is `Ok` with the length of base, a space and the whole
    /// token when that is within the budget, and `Err` with that same
    /// length when it is not — no third outcome, and never a length that
    /// counts a part of the token. That the admitted line is base, a space
    /// and the token byte for byte is a plain test on a base line at the
    /// boundary, `a_filter_at_the_budget_crosses_whole_or_not_at_all`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn a_filter_at_the_budget_is_forwarded_or_skipped_whole() {
        let base_len: usize = kani::any();
        kani::assume(base_len <= COMMAND_LINE_SIZE);
        let token_len: usize = kani::any();
        kani::assume(token_len <= COMMAND_LINE_SIZE);
        let want = base_len + 1 + token_len;
        assert_eq!(line_len(base_len, [token_len]), want);
        match within_budget(base_len, [token_len]) {
            Ok(total) => {
                assert_eq!(total, want, "a forwarded line is not base, space, token");
                assert!(total <= BOOT_LINE_BUDGET, "a line over the budget");
            }
            Err(total) => {
                assert_eq!(total, want, "a refusal does not report the line's length");
                assert!(
                    total > BOOT_LINE_BUDGET,
                    "a line within the budget was refused"
                );
            }
        }
    }

    /// The telemetry tokens cross all or none: for a base line and two
    /// tokens of any lengths up to the kernel's buffer, the pair gets one
    /// verdict — `Ok` with the length of base and both tokens, a space
    /// before each, or `Err` with that same length — never a verdict on one
    /// of them, so the caller boots on the whole set or on `base` alone.
    /// The length is the set's, not the order's; and a pair that fits has
    /// each token fitting on its own, so a refusal of the pair is the pair's
    /// length and not a token's. That an admitted line holds every token in
    /// order is a plain test on a base line at the boundary,
    /// `guest_env_tokens_at_the_budget_cross_all_or_none`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn guest_env_tokens_cross_all_or_none() {
        let base_len: usize = kani::any();
        kani::assume(base_len <= COMMAND_LINE_SIZE);
        let first: usize = kani::any();
        kani::assume(first <= COMMAND_LINE_SIZE);
        let second: usize = kani::any();
        kani::assume(second <= COMMAND_LINE_SIZE);
        let want = base_len + 1 + first + 1 + second;
        assert_eq!(line_len(base_len, [first, second]), want);
        assert_eq!(
            line_len(base_len, [second, first]),
            want,
            "the length depends on the order"
        );
        match within_budget(base_len, [first, second]) {
            Ok(total) => {
                assert_eq!(total, want, "a forwarded line is not base then every token");
                assert!(total <= BOOT_LINE_BUDGET, "a line over the budget");
                assert!(
                    matches!(within_budget(base_len, [first]), Ok(_))
                        && matches!(within_budget(base_len, [second]), Ok(_)),
                    "a pair fits but a token of it does not"
                );
            }
            Err(total) => {
                assert_eq!(total, want, "a refusal does not report the line's length");
                assert!(
                    total > BOOT_LINE_BUDGET,
                    "a line within the budget was refused"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_cmdline_without_a_host_filter_is_the_base_boot_line() {
        // The base line exactly: console plus IPv6 disabled, no empty token,
        // no trailing space.
        assert_eq!(
            kernel_cmdline(None, None, None, false),
            "console=hvc0 ipv6.disable=1"
        );
    }

    #[test]
    fn guest_ipv6_disabled_no_v6_route() {
        // Every boot line carries `ipv6.disable=1`, so the guest's IPv6 stack
        // never comes up: no interface configures an IPv6 address and the
        // route table never gains an IPv6 entry, loopback's ::1 included —
        // nothing inside the escape boundary gets a v6 family to ride.
        let lines = [
            kernel_cmdline(None, None, None, false),
            kernel_cmdline(Some("debug"), None, None, false),
        ];
        for line in lines {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            assert!(
                tokens.contains(&"ipv6.disable=1"),
                "expected an `ipv6.disable=1` boot token, got: {line}"
            );
        }
    }

    #[test]
    fn kernel_cmdline_forwards_a_simple_filter() {
        assert_eq!(
            kernel_cmdline(Some("debug"), None, None, false),
            "console=hvc0 ipv6.disable=1 RUST_LOG=debug"
        );
    }

    #[test]
    fn kernel_cmdline_preserves_comma_separated_directives() {
        // The normal form of a real filter; commas are legal in a boot token.
        assert_eq!(
            kernel_cmdline(Some("info,russh=debug,minimald=debug"), None, None, false),
            "console=hvc0 ipv6.disable=1 RUST_LOG=info,russh=debug,minimald=debug"
        );
    }

    #[test]
    fn kernel_cmdline_skips_a_filter_containing_whitespace() {
        // The kernel would split these into separate boot tokens, silently
        // corrupting the line, so the whole value is dropped — the base line
        // still boots, IPv6 disabled.
        assert_eq!(
            kernel_cmdline(Some("info, russh=debug"), None, None, false),
            "console=hvc0 ipv6.disable=1"
        );
        assert_eq!(
            kernel_cmdline(Some("info\trussh=debug"), None, None, false),
            "console=hvc0 ipv6.disable=1"
        );
    }

    #[test]
    fn kernel_cmdline_skips_an_empty_filter() {
        assert_eq!(
            kernel_cmdline(Some(""), None, None, false),
            "console=hvc0 ipv6.disable=1"
        );
    }

    #[test]
    fn kernel_cmdline_skips_an_oversized_filter() {
        let huge = "minimald=trace,".repeat(500);
        assert!(huge.len() > COMMAND_LINE_SIZE);
        assert_eq!(
            kernel_cmdline(Some(&huge), None, None, false),
            "console=hvc0 ipv6.disable=1"
        );
    }

    #[test]
    fn kernel_cmdline_forwards_the_longest_filter_that_fits_the_budget() {
        // The budget is the kernel's buffer less the NUL and less what
        // libkrun appends (F12).
        assert_eq!(
            BOOT_LINE_BUDGET + LIBKRUN_CMDLINE_RESERVE + 1,
            COMMAND_LINE_SIZE
        );
        // `console=hvc0 ipv6.disable=1 RUST_LOG=` (37 bytes today, computed
        // from the constants so the base line may change) precedes the
        // value, so this value yields a line that fills the budget exactly.
        let prefix = format!("{BASE_KERNEL_CMDLINE} {GUEST_LOG_ENV}=").len();
        let longest = "d".repeat(BOOT_LINE_BUDGET - prefix);
        let line = kernel_cmdline(Some(&longest), None, None, false);
        assert_eq!(line.len(), BOOT_LINE_BUDGET);
        assert!(line.ends_with(&longest));

        // One byte more must be skipped, not truncated.
        assert_eq!(
            kernel_cmdline(
                Some(&"d".repeat(BOOT_LINE_BUDGET - prefix + 1)),
                None,
                None,
                false
            ),
            "console=hvc0 ipv6.disable=1"
        );
    }

    /// The same two witnesses behind the widest line the port, the
    /// generation and the egress opt-out can make: the longest filter that
    /// still crosses fills the budget exactly, and one byte more is skipped
    /// while the port, the generation and the opt-out still boot.
    #[test]
    fn kernel_cmdline_forwards_the_longest_filter_behind_the_widest_port_and_generation() {
        let base = kernel_cmdline(None, Some(u16::MAX), Some(u64::MAX), true);
        let prefix = format!("{base} {GUEST_LOG_ENV}=").len();
        let longest = "d".repeat(BOOT_LINE_BUDGET - prefix);
        let line = kernel_cmdline(Some(&longest), Some(u16::MAX), Some(u64::MAX), true);
        assert_eq!(line.len(), BOOT_LINE_BUDGET);
        assert!(line.starts_with(&*base) && line.ends_with(&longest));
        assert_eq!(
            kernel_cmdline(
                Some(&"d".repeat(BOOT_LINE_BUDGET - prefix + 1)),
                Some(u16::MAX),
                Some(u64::MAX),
                true
            ),
            base
        );
    }

    /// `widest_base_len`, the bound the budget proofs put on the line before
    /// the filter, covers every token `kernel_cmdline` adds to the base line:
    /// with each optional token set at its widest and no filter, the line is
    /// no longer than the bound. A token added to `kernel_cmdline` and not to
    /// the bound fails here, rather than leaving the widest real base line
    /// outside what the proofs assume.
    #[test]
    fn widest_base_len_covers_every_base_token() {
        let widest = kernel_cmdline(None, Some(u16::MAX), Some(u64::MAX), true);
        assert!(
            widest.len() <= widest_base_len(),
            "the widest base line is {} bytes, past widest_base_len() = {}: {widest}",
            widest.len(),
            widest_base_len()
        );
    }

    /// Scenario 715g (the lab probe): a build without the budget took
    /// `RUST_LOG` filters of 1600 to 1760 bytes onto the line and libkrun
    /// panicked inside `krun_start_enter`. With the budget, the ends of that
    /// range are decided: 1600 bytes cross, with or without the port and the
    /// generation, and 1760 are skipped; every line handed on leaves libkrun
    /// its reserve.
    #[test]
    fn kernel_cmdline_decides_the_filter_lengths_the_lab_probe_crashed_on() {
        for (port, generation) in [(None, None), (Some(u16::MAX), Some(u64::MAX))] {
            let base = kernel_cmdline(None, port, generation, false);
            let crosses = "d".repeat(1600);
            let line = kernel_cmdline(Some(&crosses), port, generation, false);
            assert!(line.ends_with(&crosses), "a 1600-byte filter was skipped");
            assert!(line.len() + LIBKRUN_CMDLINE_RESERVE < COMMAND_LINE_SIZE);
            assert_eq!(
                kernel_cmdline(Some(&"d".repeat(1760)), port, generation, false),
                base,
                "a 1760-byte filter crossed"
            );
        }
    }

    /// The pure core behind `kernel_cmdline`'s filter step and
    /// `with_guest_env`: a line comes back whole or not at all, and a
    /// refusal reports the length the line would have had, so the warning
    /// can say by how much it passed the budget.
    #[test]
    fn append_tokens_reports_the_length_a_dropped_line_would_have_had() {
        let tokens = vec!["A=1".to_string(), "B=22".to_string()];
        assert_eq!(
            append_tokens("base", &tokens).as_deref(),
            Ok("base A=1 B=22")
        );
        let base = "d".repeat(BOOT_LINE_BUDGET - " A=1 B=22".len());
        assert_eq!(
            append_tokens(&base, &tokens).as_deref(),
            Ok(format!("{base} A=1 B=22").as_str())
        );
        assert_eq!(
            append_tokens(&format!("{base}d"), &tokens),
            Err(BOOT_LINE_BUDGET + 1)
        );
    }

    /// The bytes behind the Kani harness
    /// `a_filter_at_the_budget_is_forwarded_or_skipped_whole`, which states
    /// the verdict on lengths alone: with a real base line two bytes short
    /// of leaving room for the shortest `RUST_LOG` token (1779 bytes at
    /// today's budget), a token `boot_token` built is appended whole when
    /// the line is within the budget and not at all when it is not; the
    /// appended line is `base`, a space and the token, its length the one
    /// `line_len` reckons, and a refusal reports that same length.
    #[test]
    fn a_filter_at_the_budget_crosses_whole_or_not_at_all() {
        // `base + " RUST_LOG=" + v` fits iff `v.len() <= 2`; values run from
        // 1 to 8 bytes, so both outcomes are reached.
        let base = "d".repeat(BOOT_LINE_BUDGET - GUEST_LOG_ENV.len() - 4);
        for n in 1..=8 {
            let token = boot_token(GUEST_LOG_ENV, &"v".repeat(n)).unwrap();
            let want = line_len(base.len(), [token.len()]);
            match append_tokens(&base, std::slice::from_ref(&token)) {
                Ok(line) => {
                    assert!(n <= 2, "a line over the budget crossed ({n})");
                    assert_eq!(line.len(), want);
                    assert_eq!(line, format!("{base} {token}"));
                }
                Err(total) => {
                    assert!(n > 2, "a line within the budget was refused ({n})");
                    assert_eq!(total, want);
                    assert!(total > BOOT_LINE_BUDGET);
                }
            }
        }
    }

    /// The bytes behind the Kani harness `guest_env_tokens_cross_all_or_none`:
    /// with a base line at the boundary and two tokens `boot_token` built,
    /// the line that comes back is within the budget and holds `base`, then
    /// every token in order, one space before each; when the line would
    /// pass the budget nothing comes back but the length it would have had,
    /// so the caller boots on `base` alone and never on a part of the set.
    #[test]
    fn guest_env_tokens_at_the_budget_cross_all_or_none() {
        let keys = ["MINIMAL_TELEMETRY", "MINIMAL_OTEL_FILTER"];
        // Both tokens fit iff their values total at most 8 bytes; each runs
        // from 1 to 8 bytes, so both outcomes are reached.
        let base = "d".repeat(BOOT_LINE_BUDGET - keys[0].len() - keys[1].len() - 4 - 8);
        for a in 1..=8 {
            for b in 1..=8 {
                let tokens = [
                    boot_token(keys[0], &"v".repeat(a)).unwrap(),
                    boot_token(keys[1], &"w".repeat(b)).unwrap(),
                ];
                let want = line_len(base.len(), tokens.iter().map(String::len));
                match append_tokens(&base, &tokens) {
                    Ok(line) => {
                        assert!(a + b <= 8, "a line over the budget crossed ({a}, {b})");
                        assert_eq!(line.len(), want);
                        assert_eq!(line, format!("{base} {} {}", tokens[0], tokens[1]));
                    }
                    Err(total) => {
                        assert!(a + b > 8, "a line within the budget was refused ({a}, {b})");
                        assert_eq!(total, want);
                        assert!(total > BOOT_LINE_BUDGET);
                    }
                }
            }
        }
    }

    /// The alphabet of a boot value is the intersection of what libkrun's
    /// `Cmdline` accepts and what the kernel's tokenizer reads as part of
    /// one token: printable ASCII `0x21..=0x7E` without `"`. Every other
    /// char is refused.
    #[test]
    fn boot_token_accepts_exactly_the_bytes_both_readers_agree_on() {
        for c in (0u8..=0xff).map(char::from) {
            let value = format!("a{c}z");
            let accepted = boot_token("K", &value).is_ok();
            let in_alphabet = ('\u{21}'..='\u{7e}').contains(&c) && c != '"';
            assert_eq!(accepted, in_alphabet, "{c:?} ({:#x})", u32::from(c));
            if accepted {
                assert_eq!(boot_token("K", &value).unwrap(), format!("K={value}"));
            }
        }
        boot_token("K", "").unwrap_err();
        boot_token("K", "\u{1f496}").unwrap_err();
    }

    /// Every value `boot_token` accepts comes back as `key=value` byte for
    /// byte — nothing rewritten, quoted or cut — holding no whitespace and
    /// no NUL, so the kernel reads it as one token and libkrun takes it;
    /// and every refusal is `token_fault`'s verdict on the value's bytes,
    /// with the fixed reason for the first offending byte's class. Over
    /// every one-char value (a char from `0x80` up is two bytes, both
    /// outside ASCII) and a set of longer values that put an offender
    /// behind legal bytes and behind another offender. The alphabet itself
    /// and the first-offending-byte rule are proved on bytes in
    /// `kani_proofs`; this test is where the `String` is checked, cheap here
    /// and the lane's memory sink under CBMC.
    #[test]
    fn every_accepted_token_is_key_equals_value() {
        fn check(value: &str) {
            let fault = token_fault(value.as_bytes());
            match boot_token(GUEST_LOG_ENV, value) {
                Ok(token) => {
                    assert_eq!(fault, None, "{value:?}: accepted with a fault");
                    assert_eq!(token, format!("{GUEST_LOG_ENV}={value}"), "{value:?}");
                    assert_eq!(token.len(), GUEST_LOG_ENV.len() + 1 + value.len());
                    assert!(
                        token.bytes().all(|b| !b.is_ascii_whitespace() && b != 0),
                        "{value:?}: whitespace or NUL in a token"
                    );
                    assert!(
                        value.bytes().all(boot_byte),
                        "{value:?}: a byte outside the alphabet crossed"
                    );
                }
                Err(reason) => {
                    let fault =
                        fault.unwrap_or_else(|| panic!("{value:?}: refused without a fault"));
                    assert_eq!(reason, fault.reason(), "{value:?}");
                    let want = if value.is_empty() {
                        TokenFault::Empty
                    } else {
                        match value.bytes().find(|b| !boot_byte(*b)) {
                            Some(b'"') => TokenFault::Quote,
                            Some(b) if b.is_ascii_whitespace() => TokenFault::Whitespace,
                            Some(_) => TokenFault::Outside,
                            None => panic!("{value:?}: refused inside the alphabet"),
                        }
                    };
                    assert_eq!(fault, want, "{value:?}");
                }
            }
        }
        for c in (0u8..=0xff).map(char::from) {
            check(&c.to_string());
        }
        for value in [
            "",
            "debug",
            "minvmd=trace,hyper=warn",
            "a\"b",
            "a b",
            "ab\u{80}",
            "a\0",
            "\"\t",
            "\t\"",
            "\u{e9}\"",
            "\"\u{e9}",
            "\u{7f}",
            "\u{1f496}",
            "ok then",
            "~!#$%&'()*+,-./:;<=>?@[\\]^_`{|}",
        ] {
            check(value);
        }
        assert_eq!(TokenFault::Empty.reason(), "value is empty");
        assert!(
            TokenFault::Quote
                .reason()
                .starts_with("value contains a double quote")
        );
        assert!(
            TokenFault::Whitespace
                .reason()
                .starts_with("value contains whitespace")
        );
        assert!(
            TokenFault::Outside
                .reason()
                .starts_with("value contains a byte outside printable ASCII")
        );
    }

    /// A port of the kernel's `next_arg` (`lib/cmdline.c`): split on
    /// whitespace outside quotes, toggle quote state on every `"`, strip a
    /// quote pair around a value. Every token the writer accepts comes back
    /// from it unchanged, so the guest reads what minvmd logged.
    #[test]
    fn the_kernel_tokenizer_returns_every_accepted_token_unchanged() {
        fn next_arg(line: &str) -> Vec<String> {
            let mut out = Vec::new();
            let mut cur = String::new();
            let mut in_quote = false;
            for c in line.chars() {
                if c == '"' {
                    in_quote = !in_quote;
                }
                if c.is_ascii_whitespace() && !in_quote {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(c);
                }
            }
            if !cur.is_empty() {
                out.push(cur);
            }
            out.into_iter()
                .map(|t| {
                    let unquoted = t.split_once('=').and_then(|(k, v)| {
                        let inner = v.strip_prefix('"')?.strip_suffix('"')?;
                        Some(format!("{k}={inner}"))
                    });
                    unquoted.unwrap_or(t)
                })
                .collect()
        }

        let tokens: Vec<String> = [
            ("RUST_LOG", "info,russh=debug,minimald=debug"),
            ("MINIMAL_OTEL_FILTER", "warn,minimald[exec{cmd='x'}]=trace"),
            (
                "TRACEPARENT",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            ),
            ("K", "a=b=c\\'~!#$%&()*+,-./:;<>?@[]^_`{|}"),
        ]
        .into_iter()
        .map(|(k, v)| boot_token(k, v).unwrap())
        .collect();
        let line = with_guest_env(Cow::Borrowed(BASE_KERNEL_CMDLINE), &tokens);
        let mut expected: Vec<String> =
            BASE_KERNEL_CMDLINE.split(' ').map(str::to_string).collect();
        expected.extend(tokens.iter().cloned());
        assert_eq!(next_arg(&line), expected);

        // What the alphabet keeps out: a quote would merge the tokens after
        // it into one, and a space would split a value in two.
        assert_eq!(
            next_arg("A=x\" B=1 C=2").len(),
            1,
            "a quote merges every later token"
        );
        assert_eq!(next_arg("A=\"x\""), ["A=x"], "a quote pair is stripped");
        assert_eq!(next_arg("A=x y").len(), 2, "a space splits the value");
    }

    /// F11: the boot line has two readers, libkrun's printable-ASCII
    /// `Cmdline` and the kernel's quote-aware `next_arg`. A value with a byte
    /// neither accepts as part of one token is skipped, never handed on: a
    /// non-ASCII char or a C0 control would panic libkrun inside
    /// `krun_start_enter`, and a `"` would make the kernel merge every later
    /// token into this one or silently unquote it.
    #[test]
    fn kernel_cmdline_skips_a_filter_outside_the_boot_alphabet() {
        for bad in [
            "info\"",
            "\"info\"",
            "x\u{e0}info",
            "info\u{a0}debug",
            "info\u{1b}[0m",
            "info\u{1}",
        ] {
            assert_eq!(
                kernel_cmdline(Some(bad), None, None, false),
                BASE_KERNEL_CMDLINE,
                "{bad:?}"
            );
        }
    }

    /// F12: libkrun appends its own tokens after minvmd's line and panics
    /// when the result passes its 2048-byte capacity, so a line that fits
    /// the kernel's buffer on its own is not enough. The 2000-`d` filter
    /// (a 2037-byte line) is the audit's reproducer.
    #[test]
    fn the_boot_line_leaves_room_for_the_suffix_libkrun_appends() {
        assert_eq!(
            kernel_cmdline(Some(&"d".repeat(2000)), None, None, false),
            BASE_KERNEL_CMDLINE
        );
        let tokens = vec![format!("MINIMAL_OTEL_FILTER={}", "d".repeat(1990))];
        assert_eq!(
            with_guest_env(Cow::Borrowed(BASE_KERNEL_CMDLINE), &tokens),
            BASE_KERNEL_CMDLINE
        );
    }

    #[test]
    fn node_port_assigned_on_host_and_handed_to_daemon() {
        // The port the supervisor handed lands on the boot line as the boot
        // token the guest daemon reads, exactly as handed (the kernel hands
        // unrecognized `KEY=VALUE` tokens to init as env vars). The answerer
        // port never rides: on a VM-backed host the in-VM daemon starts no
        // answerer (NET-138), so a token carrying one would be an admitted
        // port with nothing behind it.
        let handed = "console=hvc0 ipv6.disable=1 MINIMALD_HOSTNAME_PROXY_PORT=7654";
        assert_eq!(kernel_cmdline(None, Some(7654), None, false), handed);
        assert!(
            !handed.contains("MINIMALD_ZONE_ANSWERER_PORT"),
            "the boot line must not carry a zone-answerer port: {handed}"
        );

        // With both a filter and the port, the tokens share the line.
        assert_eq!(
            kernel_cmdline(Some("debug"), Some(7654), None, false),
            "console=hvc0 ipv6.disable=1 MINIMALD_HOSTNAME_PROXY_PORT=7654 RUST_LOG=debug"
        );

        // A filter that would push the whole line past the buffer is skipped
        // while the port still boots: the line keeps the handed port and
        // drops the filter, rather than corrupting a token the guest binds.
        let port_only = kernel_cmdline(None, Some(7654), None, false);
        let oversized = "d".repeat(COMMAND_LINE_SIZE - port_only.len() - GUEST_LOG_ENV.len() - 1);
        assert_eq!(
            kernel_cmdline(Some(&oversized), Some(7654), None, false),
            port_only,
            "an oversized filter is skipped; the handed port still boots"
        );

        // The handoff decode is strict, because the supervisor resolves the
        // port once and anything undecodable here would boot the guest onto a
        // port different from the one the node row registered: the variable
        // absent is the pre-handoff boot (no token), a value decodes, and a
        // value that is not a port is a surfaced error naming the variable
        // and the value.
        assert_eq!(node_proxy_port_from_raw(None).unwrap(), None);
        assert_eq!(node_proxy_port_from_raw(Some("7654")).unwrap(), Some(7654));
        let garbage = node_proxy_port_from_raw(Some("no-port-here"))
            .unwrap_err()
            .to_string();
        assert!(
            garbage.contains(NODE_PROXY_PORT_ENV) && garbage.contains("no-port-here"),
            "an undecodable value names the variable and the value, got: {garbage}"
        );
    }

    #[test]
    fn the_publish_generation_rides_the_boot_line_beside_the_port() {
        // T93: the boot's publish generation travels the same way the port
        // does, so the guest can echo it in every publish report.
        assert_eq!(
            kernel_cmdline(Some("debug"), Some(7654), Some(42), false),
            "console=hvc0 ipv6.disable=1 MINIMALD_HOSTNAME_PROXY_PORT=7654 \
             MINIMALD_PUBLISH_GENERATION=42 RUST_LOG=debug"
        );
        assert_eq!(publish_generation_from_raw(None).unwrap(), None);
        assert_eq!(publish_generation_from_raw(Some("42")).unwrap(), Some(42));
        let garbage = publish_generation_from_raw(Some("not-a-generation"))
            .unwrap_err()
            .to_string();
        assert!(
            garbage.contains(PUBLISH_GENERATION_ENV) && garbage.contains("not-a-generation"),
            "an undecodable value names the variable and the value, got: {garbage}"
        );
    }

    #[test]
    fn the_egress_opt_out_rides_the_boot_line_only_when_set() {
        // NET-077: the operator's opt-out travels the same way the port does,
        // so the guest daemon runs the egress default its host was started
        // with. Unset, the token is absent — the guest runs the default.
        assert_eq!(
            kernel_cmdline(None, None, None, false),
            "console=hvc0 ipv6.disable=1"
        );
        assert_eq!(
            kernel_cmdline(None, None, None, true),
            "console=hvc0 ipv6.disable=1 MINIMALD_EGRESS_DENY_ALL_OPT_OUT=1"
        );
        // Beside the port and generation, the token shares the line.
        assert_eq!(
            kernel_cmdline(Some("debug"), Some(7654), Some(42), true),
            "console=hvc0 ipv6.disable=1 MINIMALD_HOSTNAME_PROXY_PORT=7654 \
             MINIMALD_PUBLISH_GENERATION=42 MINIMALD_EGRESS_DENY_ALL_OPT_OUT=1 RUST_LOG=debug"
        );
    }

    #[test]
    fn guest_env_tokens_follow_the_log_filter() {
        let tokens = vec![
            "MINIMAL_TELEMETRY=1".to_string(),
            "MINIMAL_OTEL_FILTER=info,minimald::net=debug".to_string(),
        ];
        // Relative to the base line, which upstream owns (it gained ipv6.disable=1).
        assert_eq!(
            with_guest_env(kernel_cmdline(Some("info"), None, None, false), &tokens),
            format!(
                "{} MINIMAL_TELEMETRY=1 MINIMAL_OTEL_FILTER=info,minimald::net=debug",
                kernel_cmdline(Some("info"), None, None, false)
            )
        );
    }

    /// (code review, TEL-040) The logged boot line names each telemetry
    /// token by its key and shows none of their values; the kernel's own
    /// parameters are logged as they are.
    #[test]
    fn the_logged_boot_line_shows_telemetry_keys_not_values() {
        let tokens = [
            "MINIMAL_TELEMETRY=1".to_string(),
            "MINIMAL_OTEL_FILTER=warn,minimald=debug".to_string(),
            "MINIMAL_OTEL_TRACES_EXPORTER=none".to_string(),
            "TRACEPARENT=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
        ];
        let base = kernel_cmdline(Some("info"), None, None, false);
        let line = with_guest_env(base.clone(), &tokens);
        let logged = loggable_boot_line(&line, &tokens);
        assert!(logged.starts_with(base.as_ref()), "{logged}");
        for key in [
            "MINIMAL_TELEMETRY=…",
            "MINIMAL_OTEL_FILTER=…",
            "MINIMAL_OTEL_TRACES_EXPORTER=…",
            "TRACEPARENT=…",
        ] {
            assert!(logged.contains(key), "{key} missing from {logged}");
        }
        for token in &tokens {
            assert!(
                !logged.contains(token.as_str()),
                "{token} logged in {logged}"
            );
        }
        for value in ["minimald=debug", "0af7651916cd43dd8448eb211c80319c"] {
            assert!(!logged.contains(value), "{value} logged in {logged}");
        }
        // With no tokens the line is logged unchanged.
        assert_eq!(loggable_boot_line(&base, &[]), base.as_ref());
    }

    /// Plan T15, the part that needs no VM (spec 25 TEL-033): the boot line
    /// the VMM child composes from a host environment holding every
    /// telemetry setting (endpoints with credentials, headers, a
    /// certificate path, resource attributes, a filter, a signal off, the
    /// spool off) adds only allowlisted keys to the base line, carries no
    /// endpoint, header or credential, and names the forward port and the
    /// caller's trace. With telemetry off the line is byte for byte the
    /// line composed with no telemetry environment at all, whatever that
    /// environment holds. `otel_integration`'s VM test checks the same on
    /// a booted guest.
    #[test]
    fn the_boot_line_carries_only_allowlisted_settings_and_off_is_byte_identical() {
        /// TEL-033's allowlist: the switch, the spool, the filter, a
        /// signal turned off, the forward port and the trace context.
        const ALLOWED: &[&str] = &[
            "MINIMAL_TELEMETRY",
            "MINIMAL_OTEL_SPOOL",
            "MINIMAL_OTEL_FILTER",
            "MINIMAL_OTEL_TRACES_EXPORTER",
            "MINIMAL_OTEL_LOGS_EXPORTER",
            "MINIMAL_OTEL_FORWARD",
            "TRACEPARENT",
        ];
        const TP: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let vars: &[(&str, &str)] = &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL", "0"),
            ("MINIMAL_OTEL_FILTER", "info,minimald=debug"),
            ("MINIMAL_OTEL_LOGS_EXPORTER", "none"),
            (
                "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "https://u:s3cr3tPW@collector.example:4318/v1/traces",
            ),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.77.0.1:4318"),
            ("MINIMAL_OTEL_EXPORTER_OTLP_HEADERS", "x-key=s3cr3tKEY1"),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "authorization=Bearer%20s3cr3tTOK",
            ),
            ("OTEL_EXPORTER_OTLP_CERTIFICATE", "/etc/ssl/collector.pem"),
            ("OTEL_RESOURCE_ATTRIBUTES", "team=x"),
            ("OTEL_SERVICE_NAME", "renamed"),
        ];
        let get = |k: &str| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        };
        let base = kernel_cmdline(Some("info"), Some(7654), Some(42), false);

        let tokens = crate::telemetry::guest_env(get, true, Some(7353), Some(TP));
        let on = with_guest_env(base.clone(), &tokens);
        let added = on
            .strip_prefix(base.as_ref())
            .unwrap_or_else(|| panic!("the base line is kept as it was: {on}"));
        let keys: Vec<&str> = added
            .split_whitespace()
            .map(|w| w.split_once('=').map_or(w, |(k, _)| k))
            .collect();
        for key in &keys {
            assert!(ALLOWED.contains(key), "{key} is not allowlisted: {on}");
        }
        for wanted in ["MINIMAL_TELEMETRY", "MINIMAL_OTEL_FORWARD", "TRACEPARENT"] {
            assert!(keys.contains(&wanted), "{wanted} missing: {on}");
        }
        for leak in [
            "ENDPOINT",
            "HEADERS",
            "CERTIFICATE",
            "RESOURCE",
            "SERVICE_NAME",
            "s3cr3t",
            "10.77.0.1",
            "collector.example",
            "x-key",
            "/etc/ssl",
            "team=x",
            "renamed",
        ] {
            assert!(!on.contains(leak), "{leak} reached the boot line: {on}");
        }

        // Off: the same environment, or none, adds not one byte.
        let none = |_: &str| None;
        for off in [
            crate::telemetry::guest_env(get, false, Some(7353), Some(TP)),
            crate::telemetry::guest_env(none, false, Some(7353), Some(TP)),
            crate::telemetry::guest_env(none, false, None, None),
        ] {
            assert_eq!(
                with_guest_env(base.clone(), &off).as_bytes(),
                base.as_bytes(),
                "telemetry off changed the boot line"
            );
        }
    }

    #[test]
    fn no_guest_env_leaves_the_boot_line_byte_identical() {
        assert_eq!(
            with_guest_env(kernel_cmdline(None, None, None, false), &[]),
            kernel_cmdline(None, None, None, false)
        );
    }

    #[test]
    fn guest_env_that_would_overflow_the_boot_line_is_dropped_whole() {
        let big = vec![
            "MINIMAL_TELEMETRY=1".to_string(),
            format!("MINIMAL_OTEL_FILTER=info,{}=debug", "h".repeat(2100)),
        ];
        assert_eq!(
            with_guest_env(kernel_cmdline(None, None, None, false), &big),
            kernel_cmdline(None, None, None, false)
        );

        // At the boundary: tokens that fill the budget exactly cross; one
        // byte more drops them all, at the token boundary, never mid-value.
        let base = kernel_cmdline(None, None, None, false);
        let fill = |len: usize| {
            vec![
                "MINIMAL_TELEMETRY=1".to_string(),
                format!("MINIMAL_OTEL_FILTER={}", "d".repeat(len)),
            ]
        };
        let room =
            BOOT_LINE_BUDGET - base.len() - " MINIMAL_TELEMETRY=1 MINIMAL_OTEL_FILTER=".len();
        assert_eq!(
            with_guest_env(base.clone(), &fill(room)).len(),
            BOOT_LINE_BUDGET
        );
        assert_eq!(with_guest_env(base.clone(), &fill(room + 1)), base);
    }

    #[test]
    fn vm_config_stores_fields() {
        let cfg = VmConfig::new(
            2,
            512,
            PathBuf::from("/boot/Image.gz"),
            PathBuf::from("/var/lib/rootfs.img"),
            PathBuf::from("/var/lib/initramfs.cpio"),
        );
        assert_eq!(cfg.num_vcpus, 2);
        assert_eq!(cfg.ram_mib, 512);
        assert_eq!(cfg.kernel_path, PathBuf::from("/boot/Image.gz"));
        assert_eq!(cfg.rootfs_path, PathBuf::from("/var/lib/rootfs.img"));
        assert_eq!(cfg.initramfs, PathBuf::from("/var/lib/initramfs.cpio"));
    }

    #[test]
    fn network_mode_defaults_to_host_net() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert_eq!(cfg.network_mode, NetworkMode::HostNet);
    }

    #[test]
    fn with_network_mode_overrides_default() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_network_mode(NetworkMode::OwnIp);
        assert_eq!(cfg.network_mode, NetworkMode::OwnIp);
        assert!(cfg.is_own_ip());
    }

    #[test]
    fn host_net_and_no_net_are_not_own_ip() {
        let base = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert!(
            !base
                .clone()
                .with_network_mode(NetworkMode::HostNet)
                .is_own_ip()
        );
        assert!(!base.with_network_mode(NetworkMode::NoNet).is_own_ip());
    }

    #[test]
    fn tap_name_is_deterministic_and_within_ifnamsiz() {
        assert_eq!(VmConfig::tap_name(2), "vmtap2");
        assert_eq!(VmConfig::tap_name(3), "vmtap3");
        assert_ne!(VmConfig::tap_name(2), VmConfig::tap_name(3));
        // Kernel IFNAMSIZ is 16 (15 usable chars); the widest u32 must fit.
        assert!(VmConfig::tap_name(u32::MAX).len() < 16);
    }

    #[test]
    fn vm_egress_defaults_to_none_and_round_trips() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert!(cfg.vm_egress.is_none());
        let cfg = cfg.with_vm_egress(EgressPolicy::default());
        assert!(cfg.vm_egress.is_some());
    }

    #[test]
    fn vm_egress_is_rejected_on_dm2() {
        // R2.5: VM-wide egress is a configuration error on DM2 (no VM boundary).
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy::default());
        let err = cfg.validate_for(DeploymentMode::Dm2).unwrap_err();
        assert!(
            matches!(
                err,
                VmError::Configuration {
                    what: "vm_egress",
                    ..
                }
            ),
            "expected a typed configuration error, got {err:?}"
        );
    }

    #[test]
    fn vm_egress_is_rejected_on_dm5() {
        // R2.5 fail-closed: DM5 does not encode a VM boundary, so a VM-wide
        // egress policy is rejected until the underlying model is resolved.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy::default());
        let err = cfg.validate_for(DeploymentMode::Dm5).unwrap_err();
        assert!(
            matches!(
                err,
                VmError::Configuration {
                    what: "vm_egress",
                    ..
                }
            ),
            "expected a typed configuration error, got {err:?}"
        );
    }

    #[test]
    fn vm_egress_is_accepted_on_vm_deployment_models() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy::default());
        // DM1/DM3/DM4 each have a VM boundary, so vm_egress is valid.
        assert!(cfg.validate_for(DeploymentMode::Dm1).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm3).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm4).is_ok());
    }

    #[test]
    fn vm_egress_with_invalid_cidr_is_rejected_on_vm_deployment_models() {
        // vm_egress is accepted on DM1/DM3/DM4, but an allow_subnets entry that is
        // not a valid CIDR prefix is named at config time, mirroring the per-PTask
        // egress check, rather than failing opaquely under #553's enforcement.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "not-a-cidr".into()]),
            ..EgressPolicy::default()
        });
        for mode in [
            DeploymentMode::Dm1,
            DeploymentMode::Dm3,
            DeploymentMode::Dm4,
        ] {
            let err = cfg.validate_for(mode).unwrap_err();
            assert!(
                matches!(&err, VmError::InvalidEgressSubnet { cidr } if cidr == "not-a-cidr"),
                "expected an invalid-egress-subnet error, got {err:?}"
            );
        }
    }

    #[test]
    fn vm_egress_with_valid_cidrs_is_accepted_on_vm_deployment_models() {
        // Both IPv4 and IPv6 CIDR prefixes pass the syntactic check.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "fd00::/8".into()]),
            ..EgressPolicy::default()
        });
        assert!(cfg.validate_for(DeploymentMode::Dm1).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm3).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm4).is_ok());
    }

    #[test]
    fn vm_egress_with_invalid_cidr_still_rejected_first_by_mode_on_dm2() {
        // On DM2 the mode rejection fires before the CIDR check, so even an
        // invalid-CIDR vm_egress surfaces as the Configuration error, not
        // InvalidEgressSubnet — the mode incompatibility is the dominant fault.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy {
            allow_subnets: Some(vec!["not-a-cidr".into()]),
            ..EgressPolicy::default()
        });
        let err = cfg.validate_for(DeploymentMode::Dm2).unwrap_err();
        assert!(
            matches!(
                err,
                VmError::Configuration {
                    what: "vm_egress",
                    ..
                }
            ),
            "expected a mode configuration error, got {err:?}"
        );
    }

    #[test]
    fn absent_vm_egress_is_valid_on_dm2() {
        // No vm_egress => nothing to reject, even on DM2.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert!(cfg.validate_for(DeploymentMode::Dm2).is_ok());
    }

    #[test]
    fn vm_config_clone() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        let cfg2 = cfg.clone();
        assert_eq!(cfg.num_vcpus, cfg2.num_vcpus);
        assert_eq!(cfg.ram_mib, cfg2.ram_mib);
        assert_eq!(cfg.initramfs, cfg2.initramfs);
    }
}
