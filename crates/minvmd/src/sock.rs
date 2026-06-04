//! Host UDS path resolution and socket-directory management for the
//! minimald bridge (R3.2).
//!
//! Path resolution: `$XDG_RUNTIME_DIR/minimal/minimald.sock`; fallback
//! `~/.minimal/local/minimald.sock` when `XDG_RUNTIME_DIR` is unset or empty.

use std::io;
use std::path::PathBuf;

/// vsock port where the in-guest minimald (or v0.1 stub) listens.
///
/// The host UDS registered via `krun_add_vsock_port2(listen=true)` bridges
/// each accepted host connection to the guest process on this port. This
/// lets the `minimal` CLI reach in-guest `minimald` over a host UDS without
/// knowing a VM exists.
///
/// The guest-side stub (`/sbin/minvmd-stub-init`) runs `socat
/// VSOCK-LISTEN:2222,fork EXEC:cat` so it listens on this port. See
/// `scripts/build-rootfs.sh` (`vsock_port_bridge=2222`).
///
/// TSI ~62-concurrent-connection cap: libkrun's TSI layer multiplexes guest
/// vsock connections over a single host transport; the practical ceiling is
/// ~62 concurrent connections on this port before new ones queue.
pub const VSOCK_BRIDGE_PORT: u32 = 2222;

/// Resolve the host UDS path for the minimald bridge (R3.2).
///
/// Returns `$XDG_RUNTIME_DIR/minimal/minimald.sock` when `XDG_RUNTIME_DIR`
/// is set and non-empty; otherwise `~/.minimal/local/minimald.sock`.
///
/// Returns an error when `XDG_RUNTIME_DIR` is absent/empty and the home
/// directory cannot be determined (e.g. `HOME` unset and no passwd entry).
pub fn resolve_uds_path() -> io::Result<PathBuf> {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            return Ok(PathBuf::from(runtime).join("minimal/minimald.sock"));
        }
    }
    dirs::home_dir()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME directory is not set; cannot resolve minimald socket path",
            )
        })
        .map(|home| home.join(".minimal/local/minimald.sock"))
}

/// Create the parent directory of `socket_path` with mode 0700, if absent.
///
/// Uses `DirBuilder::recursive(true)` so intermediate directories are created
/// as needed. A pre-existing directory is left untouched.
pub fn prepare_socket_dir(socket_path: &std::path::Path) -> io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    Ok(())
}

/// Verify that the socket file at `socket_path` has owner-only permissions
/// (0600).
///
/// Returns `io::ErrorKind::PermissionDenied` if the permission bits differ.
pub fn verify_socket_permissions(socket_path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(socket_path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket at {} has mode {:03o}; expected 0600",
                socket_path.display(),
                mode,
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Serialize tests that mutate XDG_RUNTIME_DIR / HOME so they don't race.
    static UDS_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_uds_path_uses_xdg_runtime_dir() {
        let _g = UDS_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000") };
        let path = resolve_uds_path().unwrap();
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        assert_eq!(
            path,
            PathBuf::from("/run/user/1000/minimal/minimald.sock"),
        );
    }

    #[test]
    fn resolve_uds_path_falls_back_to_home() {
        let _g = UDS_ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        unsafe { std::env::set_var("HOME", "/home/user") };
        let path = resolve_uds_path().unwrap();
        unsafe { std::env::remove_var("HOME") };
        assert_eq!(
            path,
            PathBuf::from("/home/user/.minimal/local/minimald.sock"),
        );
    }

    #[test]
    fn resolve_uds_path_ignores_empty_xdg_runtime_dir() {
        let _g = UDS_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "") };
        unsafe { std::env::set_var("HOME", "/home/user") };
        let path = resolve_uds_path().unwrap();
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        unsafe { std::env::remove_var("HOME") };
        assert_eq!(
            path,
            PathBuf::from("/home/user/.minimal/local/minimald.sock"),
        );
    }

    #[test]
    fn prepare_socket_dir_creates_with_mode_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("subdir/minimald.sock");
        prepare_socket_dir(&socket_path).unwrap();
        let meta = std::fs::metadata(tmp.path().join("subdir")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected dir mode 0700, got {mode:03o}");
    }

    #[test]
    fn verify_socket_permissions_passes_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.sock");
        std::fs::File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        verify_socket_permissions(&path).unwrap();
    }

    #[test]
    fn verify_socket_permissions_rejects_wrong_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.sock");
        std::fs::File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = verify_socket_permissions(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
