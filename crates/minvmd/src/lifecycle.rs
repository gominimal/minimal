//! VM lifecycle: ensures krunkit has a running VM before forwarding any traffic.
//!
//! Drives `krunkit` as a managed subprocess via the [`KrunkitRunner`] trait
//! seam. Production uses [`RealRunner`]; tests inject a mock that records
//! calls and returns scripted results.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use sessions::paths::{HostAbsPath, HostRelPath};
use tokio::process::Child;

use crate::config::Config;
use crate::error::UserFacing;

/// VM state as reported by krunkit's REST API (`GET /vm/state`).
///
/// krunkit 1.2.1 returns `{"state": "VirtualMachineState<X>"}` over the
/// `--restful-uri` unix socket (validated: `Running` observed live). The
/// production `get_state` maps `VirtualMachineStateRunning` → [`VmState::Running`],
/// `…Stopped` → [`VmState::Stopped`]; an absent socket → [`VmState::NotRunning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Running,
    Stopped,
    NotRunning,
}

/// Guest vsock port for the control socket `minimald` listens on. krunkit
/// bridges it host→guest in `connect` mode.
const CONTROL_VSOCK_PORT: u16 = 1024;
/// Guest vsock port for the root debug shell.
const DEBUG_VSOCK_PORT: u16 = 1025;

/// Abstraction over krunkit process management.
#[async_trait]
pub trait KrunkitRunner: Send + Sync {
    /// Start `krunkit` with the given arguments.
    async fn spawn(&self, args: &[OsString]) -> anyhow::Result<Child>;
    /// POST `{"state":"Stop"}` to the REST socket.
    async fn stop(&self, rest_sock: &Path) -> anyhow::Result<()>;
    /// GET `/vm/state` on the REST socket.
    async fn get_state(&self, rest_sock: &Path) -> anyhow::Result<VmState>;
    /// Wait for the child to exit with a timeout.
    async fn wait(
        &self,
        child: &mut Child,
        timeout: Duration,
    ) -> anyhow::Result<std::process::ExitStatus>;
}

/// Paths derived from the vm directory for krunkit sockets and disks.
///
/// All paths live on the macOS [`Host`](sessions::paths::Host) filesystem;
/// the "guest" vsock endpoints are host UDS *socket URLs*, not guest paths.
struct VmPaths {
    #[allow(dead_code)]
    vm_dir: HostAbsPath,
    rootfs: HostAbsPath,
    state_disk: HostAbsPath,
    rest_sock: HostAbsPath,
    control_sock: HostAbsPath,
    debug_sock: HostAbsPath,
    log_serial: HostAbsPath,
    pidfile: HostAbsPath,
    /// OVMF EFI variable store. krunkit's libkrun-efi bootloader requires a
    /// writable NVRAM file; `create` makes it on first boot.
    efi_vars: HostAbsPath,
}

impl VmPaths {
    /// Derive the per-VM paths from `vm_dir`.
    ///
    /// `vm_dir` is the canonical VM directory (`$MINIMAL_HOME/vm` or
    /// `~/.minimal/vm`) and is therefore always an absolute, UTF-8 host path;
    /// the conversion is effectively infallible, but a clear error is surfaced
    /// if that invariant is ever violated.
    fn new(vm_dir: &Path) -> anyhow::Result<Self> {
        let utf8 = camino::Utf8Path::from_path(vm_dir)
            .with_context(|| format!("vm dir is not valid UTF-8: {}", vm_dir.display()))?;
        let vm_dir = HostAbsPath::try_new(utf8.to_owned()).context("vm dir must be absolute")?;
        let child = |name: &str| -> HostAbsPath {
            vm_dir.join(&HostRelPath::try_new(name).expect("literal file name is relative"))
        };
        Ok(Self {
            rootfs: child("rootfs.raw"),
            state_disk: child("state.qcow2"),
            rest_sock: child("krunkit.sock"),
            control_sock: child("control.sock"),
            debug_sock: child("root-debug.sock"),
            log_serial: child("serial.log"),
            pidfile: child("krunkit.pid"),
            efi_vars: child("efivars.fd"),
            vm_dir,
        })
    }
}

/// Build the krunkit argument vector.
///
/// Flags match krunkit 1.2.1 (libkrun-efi), validated empirically:
/// - `--memory` (not `--mem`); `--device <type>,…` (not `--disk`/`--vsock`/`--serial`).
/// - `--bootloader efi,…,create`: krunkit only boots via OVMF, which needs a
///   writable EFI variable store. The boot disk is an EFI-bootable image (ESP +
///   ext4 root) built by the VM-image package.
/// - vsock `connect`: host→guest, because `minimald`/the debug shell *listen*
///   inside the guest and minvmd connects inward. (`listen`, the krunkit
///   default, is guest→host and would never create the host socket.)
fn krunkit_args(config: &Config, paths: &VmPaths) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();

    // CPU and memory
    args.push("--cpus".into());
    args.push(config.cpus.to_string().into());
    args.push("--memory".into());
    args.push(config.memory_mib.to_string().into());

    // EFI bootloader with a per-VM variable store (created on first boot).
    args.push("--bootloader".into());
    args.push(format!("efi,variable-store={},create", paths.efi_vars.as_str()).into());

    // virtio-blk: bootable rootfs image (raw) and state disk (qcow2). The
    // kernel mounts its root read-only via the baked-in cmdline, so no
    // block-layer `ro` is needed (krunkit virtio-blk has no such option).
    args.push("--device".into());
    args.push(format!("virtio-blk,path={},format=raw", paths.rootfs.as_str()).into());
    args.push("--device".into());
    args.push(format!("virtio-blk,path={},format=qcow2", paths.state_disk.as_str()).into());

    // virtio-vsock: control (1024) and debug shell (1025), host→guest (`connect`).
    args.push("--device".into());
    args.push(
        format!(
            "virtio-vsock,port={CONTROL_VSOCK_PORT},socketURL={},connect",
            paths.control_sock.as_str()
        )
        .into(),
    );
    args.push("--device".into());
    args.push(
        format!(
            "virtio-vsock,port={DEBUG_VSOCK_PORT},socketURL={},connect",
            paths.debug_sock.as_str()
        )
        .into(),
    );

    // virtio-serial: guest console log.
    args.push("--device".into());
    args.push(format!("virtio-serial,logFilePath={}", paths.log_serial.as_str()).into());

    // REST API over a unix socket.
    args.push("--restful-uri".into());
    args.push(format!("unix://{}", paths.rest_sock.as_str()).into());

    args
}

/// Boot the Linux VM.
pub async fn up(runner: &dyn KrunkitRunner, config: &Config, vm_dir: &Path) -> anyhow::Result<()> {
    // create vm dir with mode 0700
    create_dir_restricted(vm_dir)?;

    let paths = VmPaths::new(vm_dir)?;
    let args = krunkit_args(config, &paths);

    let child = runner.spawn(&args).await.context("spawn krunkit")?;

    // Write pidfile. `id()` is `None` only if the process already exited, which
    // means krunkit died immediately after spawn — surface that rather than
    // silently skipping the pidfile and waiting out the readiness timeout.
    let pid = child
        .id()
        .context("krunkit exited immediately after spawn (no pid)")?;
    tokio::fs::write(paths.pidfile.as_utf8_path().as_std_path(), pid.to_string())
        .await
        .context("write pidfile")?;

    // Poll for REST socket and vsock UDS readiness (default 30s timeout)
    let timeout = Duration::from_secs(30);
    let poll_interval = Duration::from_millis(100);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if paths.rest_sock.as_utf8_path().as_std_path().exists()
            && paths.control_sock.as_utf8_path().as_std_path().exists()
            && paths.debug_sock.as_utf8_path().as_std_path().exists()
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow::Error::from(UserFacing::new(format!(
                "krunkit did not create REST socket and vsock UDS within {}s",
                timeout.as_secs()
            ))));
        }
        tokio::time::sleep(poll_interval).await;
    }

    // set socket permissions to 0600
    set_file_mode(paths.control_sock.as_utf8_path().as_std_path(), 0o600)?;
    set_file_mode(paths.debug_sock.as_utf8_path().as_std_path(), 0o600)?;
    set_file_mode(paths.rest_sock.as_utf8_path().as_std_path(), 0o600)?;

    Ok(())
}

/// Query the VM state.
pub async fn status(runner: &dyn KrunkitRunner, vm_dir: &Path) -> anyhow::Result<VmState> {
    let paths = VmPaths::new(vm_dir)?;
    if !paths.rest_sock.as_utf8_path().as_std_path().exists() {
        return Ok(VmState::NotRunning);
    }
    runner
        .get_state(paths.rest_sock.as_utf8_path().as_std_path())
        .await
}

/// Stop the VM.
pub async fn down(runner: &dyn KrunkitRunner, vm_dir: &Path) -> anyhow::Result<()> {
    let paths = VmPaths::new(vm_dir)?;

    // If the REST socket is absent the VM is already stopped.
    if !paths.rest_sock.as_utf8_path().as_std_path().exists() {
        return Ok(());
    }

    runner
        .stop(paths.rest_sock.as_utf8_path().as_std_path())
        .await
        .context("POST stop to krunkit")?;

    // Wait for pidfile to disappear (10s)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if !paths.pidfile.as_utf8_path().as_std_path().exists() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Pidfile still present: SIGTERM the process and reap.
    if let Ok(pid_str) = tokio::fs::read_to_string(paths.pidfile.as_utf8_path().as_std_path()).await
    {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
            match nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM) {
                Ok(()) => reap_pid(nix_pid),
                // ESRCH: the process is already gone, nothing to reap.
                Err(nix::errno::Errno::ESRCH) => {}
                Err(e) => eprintln!("warn: failed to SIGTERM krunkit pid {pid}: {e}"),
            }
        }
        if let Err(e) = tokio::fs::remove_file(paths.pidfile.as_utf8_path().as_std_path()).await {
            eprintln!("warn: failed to remove pidfile {}: {e}", paths.pidfile);
        }
    }

    Ok(())
}

/// Reap a child after SIGTERM so it does not linger as a zombie.
///
/// Polls `waitpid` with `WNOHANG` for a bounded window. `ECHILD` means the
/// pid is not a child of this process (e.g. an orphaned krunkit from a prior
/// run) — there is nothing for us to reap, so it is treated as done.
fn reap_pid(pid: nix::unistd::Pid) {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            // Reaped, or unreapable (not our child / already gone): stop.
            _ => break,
        }
    }
}

/// Create a directory with mode 0700 if it does not exist.
///
/// Uses `DirBuilder::mode` so the directory is created at 0700 atomically,
/// rather than created at the umask-derived mode and chmod-ed afterward — that
/// would leave a brief window at looser permissions (umask not relied
/// upon). `recursive(true)` creates any missing parents, applying the same
/// 0700 mode to each directory it creates.
fn create_dir_restricted(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("create dir {}", path.display()))?;
    }
    Ok(())
}

/// Set a file/directory's permissions to the given mode.
fn set_file_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {:o} {}", mode, path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{serial_test::serial, with_isolated_home};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// Records of calls made to the mock runner.
    #[derive(Debug, Clone)]
    enum MockCall {
        Spawn(Vec<OsString>),
        Stop(PathBuf),
        GetState(PathBuf),
    }

    /// A mock [`KrunkitRunner`] that records calls and returns scripted
    /// results without spawning a real process.
    struct MockRunner {
        calls: Arc<Mutex<Vec<MockCall>>>,
        state_sequence: Mutex<Vec<VmState>>,
        /// Paths to create when `spawn` is called, simulating krunkit creating
        /// its sockets.
        create_on_spawn: Mutex<Vec<PathBuf>>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                state_sequence: Mutex::new(Vec::new()),
                create_on_spawn: Mutex::new(Vec::new()),
            }
        }

        fn with_states(mut self, states: Vec<VmState>) -> Self {
            self.state_sequence = Mutex::new(states);
            self
        }

        fn with_socket_creation(mut self, paths: Vec<PathBuf>) -> Self {
            self.create_on_spawn = Mutex::new(paths);
            self
        }

        fn calls(&self) -> Vec<MockCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl KrunkitRunner for MockRunner {
        async fn spawn(&self, args: &[OsString]) -> anyhow::Result<Child> {
            self.calls
                .lock()
                .unwrap()
                .push(MockCall::Spawn(args.to_vec()));

            // Create socket files to simulate krunkit readiness.
            for path in self.create_on_spawn.lock().unwrap().iter() {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(path, b"").unwrap();
            }

            // Return a dummy child as a stand-in krunkit process so `up` has a
            // real pid to write. `kill_on_drop` so it is reaped when the Child
            // drops at test end — otherwise the orphaned `sleep` inherits the
            // test's stdout fd and a `cargo test | tail` pipe never sees EOF.
            let child = tokio::process::Command::new("sleep")
                .arg("3600")
                .kill_on_drop(true)
                .spawn()
                .context("spawn dummy child")?;
            Ok(child)
        }

        async fn stop(&self, rest_sock: &Path) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(MockCall::Stop(rest_sock.to_path_buf()));
            Ok(())
        }

        async fn get_state(&self, rest_sock: &Path) -> anyhow::Result<VmState> {
            self.calls
                .lock()
                .unwrap()
                .push(MockCall::GetState(rest_sock.to_path_buf()));
            let mut seq = self.state_sequence.lock().unwrap();
            if seq.is_empty() {
                Ok(VmState::NotRunning)
            } else {
                Ok(seq.remove(0))
            }
        }

        async fn wait(
            &self,
            child: &mut Child,
            _timeout: Duration,
        ) -> anyhow::Result<std::process::ExitStatus> {
            child.kill().await.ok();
            child.wait().await.context("wait for child")
        }
    }

    #[test]
    #[serial]
    fn up_spawns_with_correct_krunkit_args() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");

            let config = Config {
                cpus: 4,
                memory_mib: 8192,
                state_size_gib: 20,
            };

            let rest_sock = vm_dir.join("krunkit.sock");
            let control_sock = vm_dir.join("control.sock");
            let debug_sock = vm_dir.join("root-debug.sock");

            let runner = MockRunner::new().with_socket_creation(vec![
                rest_sock.clone(),
                control_sock.clone(),
                debug_sock,
            ]);

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    up(&runner, &config, &vm_dir)
                        .await
                        .expect("up should succeed");
                });

            let calls = runner.calls();
            assert!(!calls.is_empty(), "runner should have been called");

            // First call must be a Spawn
            let spawn_args = match &calls[0] {
                MockCall::Spawn(args) => args.clone(),
                other => panic!("expected Spawn, got {other:?}"),
            };

            // Verify krunkit argument sequence
            let args_str: Vec<String> = spawn_args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();

            // All krunkit devices are `--device <type>,…`; collect the values.
            let device_args: Vec<&String> = args_str
                .iter()
                .enumerate()
                .filter(|(_, a)| a.as_str() == "--device")
                .map(|(i, _)| &args_str[i + 1])
                .collect();

            // Two virtio-blk disks: rootfs (raw) then state (qcow2).
            let blk: Vec<&&String> = device_args
                .iter()
                .filter(|d| d.starts_with("virtio-blk,"))
                .collect();
            assert_eq!(blk.len(), 2, "expected 2 virtio-blk devices");
            assert!(
                blk[0].contains("rootfs.raw") && blk[0].contains("format=raw"),
                "first disk should be rootfs.raw,format=raw; got {}",
                blk[0]
            );
            assert!(
                blk[1].contains("state.qcow2") && blk[1].contains("format=qcow2"),
                "second disk should be state.qcow2,format=qcow2; got {}",
                blk[1]
            );

            // Two virtio-vsock devices: control (1024) and debug (1025), `connect`.
            let vsock: Vec<&&String> = device_args
                .iter()
                .filter(|d| d.starts_with("virtio-vsock,"))
                .collect();
            assert_eq!(vsock.len(), 2, "expected 2 virtio-vsock devices");
            assert!(
                vsock[0].contains("port=1024")
                    && vsock[0].contains("control.sock")
                    && vsock[0].ends_with(",connect"),
                "first vsock should be control.sock port 1024 connect; got {}",
                vsock[0]
            );
            assert!(
                vsock[1].contains("port=1025")
                    && vsock[1].contains("root-debug.sock")
                    && vsock[1].ends_with(",connect"),
                "second vsock should be root-debug.sock port 1025 connect; got {}",
                vsock[1]
            );

            // One virtio-serial log device.
            let serial: Vec<&&String> = device_args
                .iter()
                .filter(|d| d.starts_with("virtio-serial,"))
                .collect();
            assert_eq!(serial.len(), 1, "expected 1 virtio-serial device");
            assert!(
                serial[0].contains("logFilePath=") && serial[0].contains("serial.log"),
                "serial device should log to serial.log; got {}",
                serial[0]
            );

            // EFI bootloader with a variable store.
            let boot_idx = args_str.iter().position(|a| a == "--bootloader").unwrap();
            assert!(
                args_str[boot_idx + 1].starts_with("efi,")
                    && args_str[boot_idx + 1].contains("variable-store=")
                    && args_str[boot_idx + 1].contains("create"),
                "bootloader should be efi with a created variable-store; got {}",
                args_str[boot_idx + 1]
            );

            // Must contain --restful-uri over a unix socket.
            let rest_idx = args_str.iter().position(|a| a == "--restful-uri").unwrap();
            assert!(
                args_str[rest_idx + 1].starts_with("unix://")
                    && args_str[rest_idx + 1].contains("krunkit.sock"),
                "--restful-uri value should be unix:// krunkit.sock; got {}",
                args_str[rest_idx + 1]
            );

            // CPU and memory
            let cpus_idx = args_str.iter().position(|a| a == "--cpus").unwrap();
            assert_eq!(args_str[cpus_idx + 1], "4");
            let mem_idx = args_str.iter().position(|a| a == "--memory").unwrap();
            assert_eq!(args_str[mem_idx + 1], "8192");
        });
    }

    #[test]
    #[serial]
    fn status_returns_state_from_runner() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");
            std::fs::create_dir_all(&vm_dir).unwrap();

            // Create the REST socket so status calls get_state.
            let rest_sock = vm_dir.join("krunkit.sock");
            std::fs::write(&rest_sock, b"").unwrap();

            let runner = MockRunner::new().with_states(vec![VmState::Running]);

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let state = status(&runner, &vm_dir).await.expect("status");
                    assert_eq!(state, VmState::Running);
                });

            let calls = runner.calls();
            assert!(
                matches!(&calls[0], MockCall::GetState(p) if p == &rest_sock),
                "status should call get_state on the rest socket"
            );
        });
    }

    #[test]
    #[serial]
    fn status_returns_not_running_when_no_socket() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");
            // Do NOT create the rest socket.

            let runner = MockRunner::new();

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let state = status(&runner, &vm_dir).await.expect("status");
                    assert_eq!(state, VmState::NotRunning);
                });

            // Runner should not have been called at all.
            assert!(
                runner.calls().is_empty(),
                "no runner calls when socket absent"
            );
        });
    }

    #[test]
    #[serial]
    fn down_calls_stop_and_removes_pidfile() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");
            std::fs::create_dir_all(&vm_dir).unwrap();
            let rest_sock = vm_dir.join("krunkit.sock");
            std::fs::write(&rest_sock, b"").unwrap();
            // Create a pidfile that should be cleaned up.
            let pidfile = vm_dir.join("krunkit.pid");
            std::fs::write(&pidfile, "99999").unwrap();

            let runner = MockRunner::new();

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    // Remove pidfile in a spawned task to simulate the process exiting.
                    let pf = pidfile.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        let _ = tokio::fs::remove_file(&pf).await;
                    });

                    down(&runner, &vm_dir).await.expect("down should succeed");
                });

            let calls = runner.calls();
            assert!(
                matches!(&calls[0], MockCall::Stop(p) if p == &rest_sock),
                "down should call stop on the rest socket"
            );
        });
    }

    #[test]
    #[serial]
    fn up_creates_vm_dir_with_restricted_permissions() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");
            assert!(!vm_dir.exists());

            let config = Config::default();

            let rest_sock = vm_dir.join("krunkit.sock");
            let control_sock = vm_dir.join("control.sock");
            let debug_sock = vm_dir.join("root-debug.sock");

            let runner =
                MockRunner::new().with_socket_creation(vec![rest_sock, control_sock, debug_sock]);

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    up(&runner, &config, &vm_dir).await.expect("up");
                });

            // vm_dir should have mode 0700
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&vm_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "vm dir should be 0700, got {mode:o}");
        });
    }
}
