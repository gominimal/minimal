//! Data-volume end-to-end tests for Unit 2 (spec R2.1–R2.5).
//!
//! Proof artifacts:
//! 1. `minvmd stop` on a running VM quiesces the volume: afterwards the raw
//!    image's ext4 superblock is marked cleanly unmounted (`EXT4_VALID_FS`
//!    set, `INCOMPAT_RECOVER` clear) — the journal was closed, not abandoned.
//! 2. A volume the guest cannot format/mount produces a loud boot failure —
//!    no `vm-up`, non-zero exit — with fatality decided by whether the image
//!    pre-existed (kept) or was freshly provisioned (removed).
//!
//! Gates match `boot_e2e.rs`: `#[cfg(minvmd_libkrun)]`, `#[ignore]`, and
//! `MINVMD_E2E=1` with `MINVMD_KERNEL_PATH`/`MINVMD_ROOTFS_PATH`/
//! `MINVMD_INITRAMFS` set.

#![cfg(minvmd_libkrun)]

use serial_test::serial;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// ext4 superblock: `s_state` (u16 LE) at byte 1024 + 58. Bit 0x0001
/// (`EXT4_VALID_FS`) is set on clean unmount and cleared while mounted.
const EXT4_S_STATE_OFFSET: u64 = 1024 + 58;
const EXT4_VALID_FS: u16 = 0x0001;

/// ext4 superblock: `s_feature_incompat` (u32 LE) at byte 1024 + 96. Bit
/// 0x0004 (`INCOMPAT_RECOVER`) is set while the journal needs replay and
/// cleared by a clean unmount.
const EXT4_S_FEATURE_INCOMPAT_OFFSET: u64 = 1024 + 96;
const EXT4_INCOMPAT_RECOVER: u32 = 0x0004;

/// ext4 superblock magic (`0xEF53` LE) at byte offset 1080.
const EXT4_MAGIC_OFFSET: u64 = 1080;

fn e2e_enabled(test: &str) -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("{test}: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "{test}: {var} must be set when MINVMD_E2E=1"
        );
    }
    true
}

/// Isolated per-test environment: a fresh state dir (volume image, state file,
/// locks, bridge socket) so tests never touch a real VM. Short `/tmp` paths,
/// matching `boot_e2e::short_state_dir` — the bridge UDS lives inside the
/// state dir and must fit `sun_path`.
struct TestEnv {
    _state: tempfile::TempDir,
    state_home: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let state = tempfile::Builder::new()
            .prefix("mnl")
            .tempdir_in("/tmp")
            .expect("state tempdir");
        Self {
            state_home: state.path().to_path_buf(),
            _state: state,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let bin =
            std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into());
        let mut cmd = Command::new(bin);
        // HOME too, not just XDG_STATE_HOME, as belt-and-braces: any
        // `dirs`-based fallback that ignores XDG on macOS must also land in
        // the tempdir, never the developer's real state dir.
        cmd.args(args)
            .env("HOME", &self.state_home)
            .env("XDG_STATE_HOME", &self.state_home);
        cmd
    }

    fn volume_path(&self) -> PathBuf {
        // `volume::resolve_data_volume_path()` default: the provider dir
        // under `paths::minimal_state_dir()` (XDG_STATE_HOME honoured).
        self.state_home
            .join("minimal/providers/local-0/data-vol.raw")
    }
}

fn read_le_u16(path: &Path, offset: u64) -> u16 {
    let mut f = std::fs::File::open(path).expect("open volume image");
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf).unwrap();
    u16::from_le_bytes(buf)
}

fn read_le_u32(path: &Path, offset: u64) -> u32 {
    let mut f = std::fs::File::open(path).expect("open volume image");
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

/// Poll `minvmd status --json` until it reports `running` (or panic on
/// timeout). `run --detach` returns once the bridge UDS accepts, which can
/// slightly precede the Running state write.
fn wait_until_running(env: &TestEnv, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let out = env
            .command(&["status", "--json"])
            .output()
            .expect("running minvmd status");
        if String::from_utf8_lossy(&out.stdout).contains("running") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "VM did not reach Running within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, rootfs, initramfs"]
fn stop_quiesces_volume_leaving_clean_ext4_journal() {
    if !e2e_enabled("volume_quiesce_e2e") {
        return;
    }
    let env = TestEnv::new();

    // Keep the sparse image small so mkfs and the journal stay quick.
    let status = env
        .command(&["run", "--detach", "--timeout", "120"])
        .env("MINVMD_VOLUME_BYTES", "1073741824") // 1 GiB
        .status()
        .expect("spawning minvmd run --detach");
    assert!(status.success(), "minvmd run --detach failed: {status}");
    wait_until_running(&env, Duration::from_secs(60));

    let volume = env.volume_path();
    assert!(volume.exists(), "volume image must exist after boot");

    // Clean stop: Shutdown RPC (drain + syncfs + umount) before SIGTERM.
    let status = env
        .command(&["stop"])
        .status()
        .expect("running minvmd stop");
    assert!(status.success(), "minvmd stop failed: {status}");

    // The guest formatted the image, so the magic must be present …
    assert_eq!(
        read_le_u16(&volume, EXT4_MAGIC_OFFSET),
        0xEF53,
        "volume image must carry an ext4 superblock"
    );
    // … and a quiesced stop leaves the journal closed: cleanly-unmounted
    // state bit set, no recovery pending.
    let s_state = read_le_u16(&volume, EXT4_S_STATE_OFFSET);
    assert_ne!(
        s_state & EXT4_VALID_FS,
        0,
        "s_state ({s_state:#06x}) must have EXT4_VALID_FS set after a clean stop"
    );
    let incompat = read_le_u32(&volume, EXT4_S_FEATURE_INCOMPAT_OFFSET);
    assert_eq!(
        incompat & EXT4_INCOMPAT_RECOVER,
        0,
        "s_feature_incompat ({incompat:#010x}) must not need journal recovery after a clean stop"
    );
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, rootfs, initramfs"]
fn boot_fails_loudly_on_unformattable_fresh_volume() {
    if !e2e_enabled("volume_quiesce_e2e") {
        return;
    }
    let env = TestEnv::new();

    // 1 MiB is below the guest's 16 MiB mkfs floor: the guest cannot format
    // the fresh volume, so it must emit MOUNT_FAILED instead of READY (R2.4).
    let out = env
        .command(&["boot"])
        .env("MINVMD_VOLUME_BYTES", "1048576")
        .output()
        .expect("running minvmd boot");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !out.status.success(),
        "boot must fail; stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        !stdout.contains("vm-up"),
        "no vm-up may be printed on mount failure (ghost READY); stdout: {stdout}"
    );
    assert!(
        stderr.contains("freshly provisioned"),
        "error must name the fresh-volume case; stderr: {stderr}"
    );
    // The blank image was created this boot and holds no user data: it must
    // be removed so the next boot is not misclassified as \"pre-existing\".
    assert!(
        !env.volume_path().exists(),
        "freshly provisioned image must be removed after MOUNT_FAILED"
    );
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, rootfs, initramfs"]
fn boot_fails_fatally_on_unmountable_preexisting_volume() {
    if !e2e_enabled("volume_quiesce_e2e") {
        return;
    }
    let env = TestEnv::new();

    // Pre-create a corrupt image: the ext4 magic is present (so the guest
    // will NOT reformat — that would destroy user data) but everything else
    // is garbage, so mount and the e2fsck retry both fail.
    let volume = env.volume_path();
    std::fs::create_dir_all(volume.parent().unwrap()).unwrap();
    {
        let mut f = std::fs::File::create(&volume).unwrap();
        f.write_all(&[0xAA; 4096 * 8]).unwrap();
        f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET)).unwrap();
        f.write_all(&[0x53, 0xEF]).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
    }

    let out = env
        .command(&["boot"])
        .output()
        .expect("running minvmd boot");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !out.status.success(),
        "boot must fail; stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        !stdout.contains("vm-up"),
        "no vm-up may be printed on mount failure (ghost READY); stdout: {stdout}"
    );
    assert!(
        stderr.contains("pre-exists"),
        "error must name the pre-existing-image (fatal) case; stderr: {stderr}"
    );
    assert!(
        volume.exists(),
        "a pre-existing image may hold session data and must never be removed"
    );
}
