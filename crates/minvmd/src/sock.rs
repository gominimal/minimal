//! Host UDS path resolution and socket-directory management for the
//! minimald bridge (R3.2).
//!
//! The bridge socket lives beside the minvmd state files in the
//! provider-instance dir: `<minimal_state_dir>/providers/local-0/ssh.sock` —
//! the same name native minimald binds, so clients see one endpoint
//! regardless of backend.

use std::io;
use std::path::PathBuf;

/// vsock port where the in-guest minimald (or v0.1 stub) listens.
///
/// The host UDS registered via `krun_add_vsock_port2(listen=true)` bridges
/// each accepted host connection to the guest process on this port. This
/// lets the `minimal` CLI reach in-guest `minimald` over a host UDS without
/// knowing a VM exists.
///
/// The guest-side stub (`/sbin/microvm-init`) runs `socat
/// VSOCK-LISTEN:2222,fork EXEC:cat` so it listens on this port. See the
/// `minvmd-rootfs` package (`.minimal/packages/minvmd-rootfs/build.sh`,
/// `vsock_port_bridge=2222`).
///
/// TSI ~62-concurrent-connection cap: libkrun's TSI layer multiplexes guest
/// vsock connections over a single host transport; the practical ceiling is
/// ~62 concurrent connections on this port before new ones queue.
pub const VSOCK_BRIDGE_PORT: u32 = 2222;

/// Resolve the host UDS path for the minimald bridge (R3.2):
/// `<provider dir>/ssh.sock`.
pub fn resolve_uds_path() -> io::Result<PathBuf> {
    Ok(crate::state::provider_dir().join(paths::SSH_SOCK_FILE))
}

/// Usable bytes in `sockaddr_un.sun_path` (excluding the NUL terminator).
#[cfg(target_os = "macos")]
const SUN_PATH_MAX: usize = 103;
#[cfg(not(target_os = "macos"))]
const SUN_PATH_MAX: usize = 107;

/// Fail fast when `path` exceeds the platform unix-socket path limit.
/// libkrun aborts the process (panic in a nounwind FFI frame) on
/// `ENAMETOOLONG` instead of returning an error, so check before handing
/// socket paths to it.
pub fn check_uds_path_len(path: &std::path::Path) -> io::Result<()> {
    let len = path.as_os_str().as_encoded_bytes().len();
    if len > SUN_PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "socket path {} is {len} bytes, over the {SUN_PATH_MAX}-byte unix socket \
                 limit; use a shorter state dir (--minimal-state-dir / XDG_STATE_HOME)",
                path.display(),
            ),
        ));
    }
    Ok(())
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

/// Remove a stale socket left by a previous run.
///
/// `krun_add_vsock_port2(listen=true)` binds the host UDS and fails with
/// `EEXIST` if the path already exists — common on a persistent runner where
/// the socket file outlives the process. Remove a pre-existing *socket* at
/// `socket_path`; refuse to touch any other file type so an unrelated path is
/// never clobbered. A missing path is a no-op.
pub fn remove_stale_socket(socket_path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt as _;
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(socket_path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to remove",
                socket_path.display(),
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

/// Tighten the bridge socket at `socket_path` to owner-only (0600).
///
/// libkrun creates the listening socket with default permissions (typically
/// 0755), so the parent enforces 0600 once the socket exists — only the owner
/// should be able to connect to the daemon. (The containing dir is already
/// 0700, so this is defense in depth.)
pub fn enforce_socket_permissions(socket_path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Serialize tests that mutate XDG_STATE_HOME so they don't race.
    static UDS_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_uds_path_lives_in_provider_dir() {
        let _g = UDS_ENV_LOCK.lock().unwrap();
        let prev = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", "/state") };
        let path = resolve_uds_path().unwrap();
        match prev {
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
        assert_eq!(
            path,
            PathBuf::from("/state/minimal/providers/local-0/ssh.sock"),
        );
    }

    #[test]
    fn check_uds_path_len_accepts_short_and_rejects_long() {
        check_uds_path_len(std::path::Path::new("/tmp/x/ssh.sock")).unwrap();

        let long = format!("/tmp/{}/ssh.sock", "x".repeat(SUN_PATH_MAX));
        let err = check_uds_path_len(std::path::Path::new(&long)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("unix socket limit"), "{err}");
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

    #[test]
    fn enforce_socket_permissions_tightens_to_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.sock");
        std::fs::File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        enforce_socket_permissions(&path).unwrap();
        verify_socket_permissions(&path).unwrap();
    }

    #[test]
    fn remove_stale_socket_missing_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        remove_stale_socket(&tmp.path().join("absent.sock")).unwrap();
    }

    #[test]
    fn remove_stale_socket_unlinks_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("live.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(path.exists());
        remove_stale_socket(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn remove_stale_socket_refuses_non_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("regular");
        std::fs::File::create(&path).unwrap();
        let err = remove_stale_socket(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(path.exists(), "non-socket must be left in place");
    }
}
