//! Host UDS path resolution and socket-directory management for the
//! minimald bridge (R3.2).
//!
//! The bridge socket lives beside the minvmd state files in the minvmd
//! provider-instance dir:
//! `<minimal_state_dir>/providers/local-minvmd0/ssh.sock`. It mirrors the
//! `ssh.sock` name native minimald binds under its own `local-minimald<N>`
//! dir; the client selects the dir matching the requested backend.

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

/// The user the VMM child runs as (BEP-047), and its primary group. The
/// provider dir and the sockets the VMM child opens carry this group.
pub const VMM_USER: &str = "minimal-vmm";
/// The user gvproxy runs as, and its primary group.
pub const GVPROXY_USER: &str = "minimal-gvproxy";

/// The name of the provider dir's subdirectory that the VM user owns.
pub const VMM_DIR: &str = "vmm";

/// The gid of `group`, when this host has the group.
pub fn group_gid(group: &str) -> Option<u32> {
    let name = std::ffi::CString::new(group).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: `grp` and `buf` outlive the call, and `result` is written by it.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some(grp.gr_gid)
}

/// The uid of `user`, when this host has the user.
pub fn user_uid(user: &str) -> Option<u32> {
    let name = std::ffi::CString::new(user).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: `pwd` and `buf` outlive the call, and `result` is written by it.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some(pwd.pw_uid)
}

/// The gid of `group` when this process holds it, as its effective group
/// or a supplementary one. Only then can it give a file that group (a
/// membership added after this login starts is not held yet).
pub fn held_group_gid(group: &str) -> Option<u32> {
    let gid = group_gid(group)?;
    // SAFETY: getegid has no preconditions and cannot fail.
    if unsafe { libc::getegid() } == gid {
        return Some(gid);
    }
    // SAFETY: a zero-length call only counts the groups.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return None;
    }
    let mut groups = vec![0 as libc::gid_t; n as usize];
    // SAFETY: `groups` has room for `n` entries.
    let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    (n > 0 && groups[..n as usize].contains(&gid)).then_some(gid)
}

/// The mode and the group one socket gets: a row of the split-user
/// design's ownership table (`docs/design/2026-10-25-split-user-vmm-provider-dir.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAccess {
    /// The permission bits.
    pub mode: u32,
    /// The group that must own the socket, when the mode admits a group.
    pub group: Option<&'static str>,
}

impl SocketAccess {
    /// Only the owner connects.
    pub const OWNER_ONLY: SocketAccess = SocketAccess {
        mode: 0o600,
        group: None,
    };
    /// The owner and the VM user connect, through the `minimal-vmm` group.
    pub const VMM_GROUP: SocketAccess = SocketAccess {
        mode: 0o660,
        group: Some(VMM_USER),
    };
    /// The owner and gvproxy's user connect, through the `minimal-gvproxy`
    /// group.
    pub const GVPROXY_GROUP: SocketAccess = SocketAccess {
        mode: 0o660,
        group: Some(GVPROXY_USER),
    };
}

/// The design's mode and group for the socket at `socket_path`, by its
/// file name: the sockets the VMM child opens are 0660 with group
/// `minimal-vmm`, `gvproxy-bep.sock` is 0660 with group `minimal-gvproxy`,
/// and every other socket (`control.sock`, `timekeep.sock`, the switch
/// socket) is 0600.
pub fn socket_access(socket_path: &std::path::Path) -> SocketAccess {
    let name = socket_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    match name {
        paths::SSH_SOCK_FILE
        | crate::control::GUEST_CONTROL_SOCK_FILE
        | crate::guest_telemetry::GUEST_TELEMETRY_SOCK_FILE
        | "gvproxy-gate.sock" => SocketAccess::VMM_GROUP,
        "gvproxy-bep.sock" => SocketAccess::GVPROXY_GROUP,
        marker if marker.starts_with("minvmd-marker-") && marker.ends_with(".sock") => {
            SocketAccess::VMM_GROUP
        }
        _ => SocketAccess::OWNER_ONLY,
    }
}

/// The mode and the gid `access` resolves to on this host. `held` gives
/// the gid of a group this process holds. A group the process does not
/// hold (no `min finalize-install` yet, or a membership that starts at the
/// next login) resolves to 0600 with no group, so no other user connects.
fn resolve_access(access: SocketAccess, held: impl Fn(&str) -> Option<u32>) -> (u32, Option<u32>) {
    match access.group.and_then(held) {
        Some(gid) => (access.mode, Some(gid)),
        None => (0o600, None),
    }
}

/// Create the parent directory of `socket_path`, if absent.
///
/// Uses `DirBuilder::recursive(true)` so intermediate directories are created
/// as needed. A new directory gets mode 0700, or 0710 with group
/// `minimal-vmm` when this process holds that group, so the VM user can
/// search it. A pre-existing directory is left untouched. The VM user's own
/// `vmm/` is never created here, because only root can create it: it is
/// verified ([`verify_vmm_dir`]).
pub fn prepare_socket_dir(socket_path: &std::path::Path) -> io::Result<()> {
    prepare_socket_dir_with(socket_path, held_group_gid(VMM_USER), || {
        verify_vmm_dir(socket_path.parent().unwrap_or(socket_path))
    })
}

fn prepare_socket_dir_with(
    socket_path: &std::path::Path,
    vmm_gid: Option<u32>,
    verify_vmm: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let Some(parent) = socket_path.parent() else {
        return Ok(());
    };
    if parent.file_name().is_some_and(|n| n == VMM_DIR) {
        return verify_vmm();
    }
    if parent.exists() {
        return Ok(());
    }
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    if let Some(gid) = vmm_gid {
        std::os::unix::fs::chown(parent, None, Some(gid))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o710))?;
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

/// Verify that the socket file at `socket_path` has the mode and the group
/// [`socket_access`] gives it: 0600, or 0660 with its group when this
/// process holds that group.
///
/// Returns `io::ErrorKind::PermissionDenied` if the mode or the group differ.
pub fn verify_socket_permissions(socket_path: &std::path::Path) -> io::Result<()> {
    verify_socket_access(socket_path, socket_access(socket_path), held_group_gid)
}

/// [`verify_socket_permissions`] with the access and the group lookup given.
pub fn verify_socket_access(
    socket_path: &std::path::Path,
    access: SocketAccess,
    held: impl Fn(&str) -> Option<u32>,
) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (want_mode, want_gid) = resolve_access(access, held);
    let meta = std::fs::metadata(socket_path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != want_mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket at {} has mode {:03o}; expected {want_mode:04o}",
                socket_path.display(),
                mode,
            ),
        ));
    }
    if let Some(gid) = want_gid
        && meta.gid() != gid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket at {} has group {}; expected group {} ({gid})",
                socket_path.display(),
                meta.gid(),
                access.group.unwrap_or_default(),
            ),
        ));
    }
    Ok(())
}

/// Set the mode and the group [`socket_access`] gives the socket at
/// `socket_path`, with `chown` and `chmod` on the path after the bind.
///
/// libkrun creates the listening socket with default permissions (typically
/// 0755), so the owner sets the mode once the socket exists. A socket that
/// another user opens gets 0660 with that user's group. Every other socket
/// gets 0600, so only the owner connects.
pub fn enforce_socket_permissions(socket_path: &std::path::Path) -> io::Result<()> {
    enforce_socket_access(socket_path, socket_access(socket_path), held_group_gid)
}

/// [`enforce_socket_permissions`] with the access and the group lookup
/// given.
pub fn enforce_socket_access(
    socket_path: &std::path::Path,
    access: SocketAccess,
    held: impl Fn(&str) -> Option<u32>,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let (mode, gid) = resolve_access(access, held);
    if let Some(gid) = gid {
        std::os::unix::fs::chown(socket_path, None, Some(gid))?;
    }
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(mode))
}

/// Whether a provider dir with this group and mode is one the VM host
/// daemon puts its sockets in: 0700, or 0710 with group `minimal-vmm`
/// (`vmm_gid`), so the VM user can search it and do nothing else.
fn provider_dir_mode_ok(gid: u32, mode: u32, vmm_gid: Option<u32>) -> bool {
    mode == 0o700 || (mode == 0o710 && vmm_gid == Some(gid))
}

/// Verify that `dir` is owned by the calling process's uid and has mode
/// 0700, or 0710 with group `minimal-vmm`. Return `PermissionDenied`
/// otherwise, naming the directory and its actual owner and mode.
pub fn verify_provider_dir_ownership(dir: &std::path::Path) -> io::Result<()> {
    verify_provider_dir_ownership_with(dir, group_gid(VMM_USER))
}

fn verify_provider_dir_ownership_with(
    dir: &std::path::Path,
    vmm_gid: Option<u32>,
) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let meta = std::fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{} is not a directory", dir.display()),
        ));
    }

    // SAFETY: geteuid has no preconditions and cannot fail.
    let my_uid = unsafe { libc::geteuid() };
    if meta.uid() != my_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the Minimal state directory {} is owned by uid {}, but this user is uid \
                 {my_uid}; the VM host daemon will not put its sockets there. Change the \
                 directory's owner to this user with `chown`",
                dir.display(),
                meta.uid(),
            ),
        ));
    }

    let mode = meta.permissions().mode() & 0o7777;
    if !provider_dir_mode_ok(meta.gid(), mode, vmm_gid) {
        let allowed = if vmm_gid.is_some() {
            format!("0700, or 0710 with group {VMM_USER}")
        } else {
            "0700".to_string()
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the Minimal state directory {} has mode {mode:04o}, but it must be {allowed}; \
                 run `chmod 700` on it",
                dir.display(),
            ),
        ));
    }

    Ok(())
}

/// Tighten `dir` when it is a directory the calling uid owns with a mode
/// [`verify_provider_dir_ownership`] refuses: to 0710 when its group is
/// `minimal-vmm`, else to 0700.
///
/// The provider dir is first created by `StateDir::new`, which creates it
/// under the process umask (typically 0755), before any socket is bound;
/// [`prepare_socket_dir`] leaves a pre-existing dir untouched. Refusing
/// such a dir outright would refuse every existing install. Only the
/// owner (or root) can change a dir's mode, so tightening our own dir is
/// safe; a dir owned by another uid is left as is for the verification to
/// refuse.
pub fn restrict_owned_dir(dir: &std::path::Path) -> io::Result<()> {
    restrict_owned_dir_with(dir, group_gid(VMM_USER))
}

fn restrict_owned_dir_with(dir: &std::path::Path, vmm_gid: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let meta = std::fs::metadata(dir)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let my_uid = unsafe { libc::geteuid() };
    let mode = meta.permissions().mode() & 0o7777;
    if meta.is_dir() && meta.uid() == my_uid && !provider_dir_mode_ok(meta.gid(), mode, vmm_gid) {
        let target = if vmm_gid == Some(meta.gid()) {
            0o710
        } else {
            0o700
        };
        tracing::info!(
            dir = %dir.display(),
            mode = format_args!("{mode:04o}"),
            target = format_args!("{target:04o}"),
            "tightening the provider directory"
        );
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(target))?;
    }
    Ok(())
}

/// Verify the VM user's `vmm/` dir: a directory, not a symlink, owned by
/// `minimal-vmm` with group `minimal-vmm` and mode 0750. Only root creates
/// it, in `min finalize-install`, so the error names that command.
pub fn verify_vmm_dir(dir: &std::path::Path) -> io::Result<()> {
    verify_vmm_dir_with(dir, user_uid(VMM_USER), group_gid(VMM_USER))
}

fn verify_vmm_dir_with(
    dir: &std::path::Path,
    vmm_uid: Option<u32>,
    vmm_gid: Option<u32>,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let refuse = |what: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} {what}. It must be a directory owned by {VMM_USER} with group {VMM_USER} \
                 and mode 0750. Run `min finalize-install` to set it up.",
                dir.display(),
            ),
        )
    };
    let (Some(uid), Some(gid)) = (vmm_uid, vmm_gid) else {
        return Err(refuse(format!(
            "cannot be checked: this machine has no {VMM_USER} user"
        )));
    };
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(refuse("is not there".to_string()));
        }
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_dir() {
        return Err(refuse("is not a directory".to_string()));
    }
    let mode = meta.mode() & 0o7777;
    if meta.uid() != uid || meta.gid() != gid || mode != 0o750 {
        return Err(refuse(format!(
            "has owner uid {}, group gid {} and mode {mode:04o}",
            meta.uid(),
            meta.gid(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::DirBuilderExt;
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
            PathBuf::from("/state/minimal/providers/local-minvmd0/ssh.sock"),
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

    #[test]
    fn verify_provider_dir_ownership_passes_owned_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("provider");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        verify_provider_dir_ownership(&dir).unwrap();
    }

    #[test]
    fn verify_provider_dir_ownership_rejects_wrong_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("provider");
        std::fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
        let err = verify_provider_dir_ownership(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("0755"), "{err}");
        assert!(err.to_string().contains("but it must be 0700"), "{err}");
    }

    #[test]
    fn verify_provider_dir_ownership_rejects_non_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("regular");
        std::fs::File::create(&path).unwrap();
        let err = verify_provider_dir_ownership(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
    }

    #[test]
    fn restrict_owned_dir_tightens_an_owned_0755_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("provider");
        std::fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
        restrict_owned_dir(&dir).unwrap();
        verify_provider_dir_ownership(&dir).unwrap();
    }

    /// BEP-047: the provider dir is 0700, or 0710 with group `minimal-vmm`;
    /// `vmm/` is verified, never created; each socket gets the mode and the
    /// group of the design's table, and 0600 while the group is not held.
    #[test]
    fn split_user_provider_dir_modes_are_enforced() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // The test stands in this process's own group for `minimal-vmm`:
        // it is the one group a test can give its own entries.
        let my_gid = unsafe { libc::getegid() };
        let my_uid = unsafe { libc::geteuid() };
        let tmp = tempfile::tempdir().unwrap();
        let mode_of = |p: &std::path::Path| std::fs::metadata(p).unwrap().mode() & 0o7777;

        // A new provider dir: 0710 with the group when it is held, else 0700.
        let grouped = tmp.path().join("grouped/ssh.sock");
        prepare_socket_dir_with(&grouped, Some(my_gid), || unreachable!()).unwrap();
        let dir = grouped.parent().unwrap();
        assert_eq!(mode_of(dir), 0o710);
        assert_eq!(std::fs::metadata(dir).unwrap().gid(), my_gid);
        verify_provider_dir_ownership_with(dir, Some(my_gid)).unwrap();
        let err = verify_provider_dir_ownership_with(dir, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let plain = tmp.path().join("plain/ssh.sock");
        prepare_socket_dir_with(&plain, None, || unreachable!()).unwrap();
        assert_eq!(mode_of(plain.parent().unwrap()), 0o700);

        // `vmm/` is root's to create: the call verifies it and creates nothing.
        let in_vmm = tmp.path().join("provider").join(VMM_DIR).join("ssh.sock");
        let mut verified = false;
        prepare_socket_dir_with(&in_vmm, Some(my_gid), || {
            verified = true;
            Ok(())
        })
        .unwrap();
        assert!(verified);
        assert!(!in_vmm.parent().unwrap().exists());

        // A group-writable or other-readable provider dir is refused, and an
        // owned one is tightened to 0710 when its group is `minimal-vmm`.
        for mode in [0o750, 0o770, 0o711, 0o755] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(verify_provider_dir_ownership_with(dir, Some(my_gid)).is_err());
            restrict_owned_dir_with(dir, Some(my_gid)).unwrap();
            assert_eq!(mode_of(dir), 0o710, "from {mode:04o}");
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        restrict_owned_dir_with(dir, None).unwrap();
        assert_eq!(mode_of(dir), 0o700);

        // `vmm/`: owned by the VM user with its group and mode 0750.
        let vmm = tmp.path().join("p2").join(VMM_DIR);
        let missing = verify_vmm_dir_with(&vmm, Some(my_uid), Some(my_gid)).unwrap_err();
        assert!(
            missing.to_string().contains("min finalize-install"),
            "{missing}"
        );
        std::fs::create_dir_all(&vmm).unwrap();
        std::fs::set_permissions(&vmm, std::fs::Permissions::from_mode(0o750)).unwrap();
        verify_vmm_dir_with(&vmm, Some(my_uid), Some(my_gid)).unwrap();
        assert!(verify_vmm_dir_with(&vmm, Some(my_uid + 1), Some(my_gid)).is_err());
        assert!(verify_vmm_dir_with(&vmm, None, None).is_err());
        std::fs::set_permissions(&vmm, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(verify_vmm_dir_with(&vmm, Some(my_uid), Some(my_gid)).is_err());
        let link = tmp.path().join("p3").join(VMM_DIR);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&vmm, &link).unwrap();
        std::fs::set_permissions(&vmm, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = verify_vmm_dir_with(&link, Some(my_uid), Some(my_gid)).unwrap_err();
        assert!(err.to_string().contains("is not a directory"), "{err}");

        // The table: the sockets the VMM child opens are 0660 with group
        // `minimal-vmm`, the proxy socket 0660 with group `minimal-gvproxy`,
        // and the rest 0600.
        let p = |name: &str| PathBuf::from("/provider").join(name);
        assert_eq!(
            socket_access(&p(paths::SSH_SOCK_FILE)),
            SocketAccess::VMM_GROUP
        );
        assert_eq!(
            socket_access(&p(crate::control::GUEST_CONTROL_SOCK_FILE)),
            SocketAccess::VMM_GROUP
        );
        assert_eq!(
            socket_access(&p(crate::guest_telemetry::GUEST_TELEMETRY_SOCK_FILE)),
            SocketAccess::VMM_GROUP
        );
        assert_eq!(
            socket_access(std::path::Path::new("/tmp/minvmd-marker-1-0000abcd.sock")),
            SocketAccess::VMM_GROUP
        );
        assert_eq!(
            socket_access(&p("gvproxy-gate.sock")),
            SocketAccess::VMM_GROUP
        );
        assert_eq!(
            socket_access(&p("gvproxy-bep.sock")),
            SocketAccess::GVPROXY_GROUP
        );
        for owner_only in [
            crate::control::CONTROL_SOCK_FILE,
            "timekeep.sock",
            "gvproxy-switch.sock",
        ] {
            assert_eq!(
                socket_access(&p(owner_only)),
                SocketAccess::OWNER_ONLY,
                "{owner_only}"
            );
        }

        // The mode and the group are set on the path after the bind.
        let sock = tmp.path().join("door.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        enforce_socket_access(&sock, SocketAccess::VMM_GROUP, |_| Some(my_gid)).unwrap();
        assert_eq!(mode_of(&sock), 0o660);
        assert_eq!(std::fs::metadata(&sock).unwrap().gid(), my_gid);
        verify_socket_access(&sock, SocketAccess::VMM_GROUP, |_| Some(my_gid)).unwrap();
        assert!(verify_socket_access(&sock, SocketAccess::VMM_GROUP, |_| None).is_err());
        assert!(verify_socket_access(&sock, SocketAccess::OWNER_ONLY, |_| None).is_err());
        // Until the group is held, the socket stays owner-only.
        enforce_socket_access(&sock, SocketAccess::VMM_GROUP, |_| None).unwrap();
        assert_eq!(mode_of(&sock), 0o600);
        verify_socket_access(&sock, SocketAccess::VMM_GROUP, |_| None).unwrap();
    }

    /// The split-user design (T57) names each socket and file in the list
    /// below with an owner, a mode and the users that open it. The list
    /// covers the provider dir, its `vmm/` subdirectory, the gvproxy dir,
    /// gvproxy config dir and gate dir that `minimal-gvproxy` uses outside
    /// the provider dir, and the supervisor channel to the EGW process. The
    /// list is written by hand. A new socket that nobody adds to it does not
    /// fail this test. A rename fails it only for a name that the list takes
    /// from the code.
    #[test]
    fn split_user_provider_dir_design_names_every_socket_owner_of_fixed_list() {
        let _g = UDS_ENV_LOCK.lock().unwrap();
        let doc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/design/2026-10-25-split-user-vmm-provider-dir.md");
        let doc = std::fs::read_to_string(&doc_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", doc_path.display()));

        let file_name = |p: PathBuf| {
            p.file_name()
                .and_then(|n| n.to_str())
                .expect("socket path has a file name")
                .to_string()
        };
        let switch_sock = file_name(crate::net::resolve_switch_sock().unwrap());
        let gvproxy_yaml = file_name(
            crate::net::GvproxyConfig::new(
                PathBuf::from("gvproxy"),
                PathBuf::from("/provider").join(&switch_sock),
            )
            .config_path()
            .to_path_buf(),
        );
        // The entries in the provider dir and in its `vmm/` subdirectory,
        // the entries the VMM child or `prepare_socket_dir` creates, and
        // the sockets the VMM child opens, each with the user that must
        // create it. A name comes from the code where this
        // module can reach a constant or a resolver for it, so a rename of
        // that name fails this test. `boot.log`, `data-vol.raw` and
        // `gvproxy-bep.sock` are literals, because no reachable item names
        // them. The entries `minimal-vmm` creates sit in `vmm/`, because
        // `minimal-vmm` cannot write the provider dir. gvproxy runs as a
        // third user, `minimal-gvproxy`, so it shares no writable state
        // with `bep serve` and only the egress gate reaches it. Its switch
        // socket sits in the gvproxy dir, and `gvproxy.yaml` in the gvproxy
        // config dir, both outside the provider dir. The egress gate and
        // `switch::bep_host` run in an EGW process as `minimal-gvproxy`
        // (Gatehouse 6.10 line 831). So the EGW process creates the gate
        // socket in the gate dir, and dials `gvproxy-bep.sock` in the
        // gvproxy config dir, which `minimal-vmm` cannot search. The
        // supervisor hands the EGW process its table and token on a
        // `socketpair` with no path, which the supervisor creates.
        let vmm = |name: String| format!("vmm/{name}");
        let gvproxy_dir = |name: &str| format!("<gvproxy dir>/{name}");
        let gvproxy_config_dir = |name: &str| format!("<gvproxy config dir>/{name}");
        let gate_dir = |name: &str| format!("<gate dir>/{name}");
        let required = [
            ("<provider dir>/".to_string(), LOGIN),
            ("<provider dir>/vmm/".to_string(), ROOT),
            (vmm(paths::SSH_SOCK_FILE.to_string()), VMM),
            (
                vmm(file_name(crate::timekeep::resolve_timekeep_sock().unwrap())),
                VMM,
            ),
            (vmm("boot.log".to_string()), VMM),
            (vmm("data-vol.raw".to_string()), VMM),
            (gvproxy_dir(""), ROOT),
            (gvproxy_dir(&switch_sock), GVPROXY),
            (gvproxy_config_dir(""), ROOT),
            (gvproxy_config_dir(&gvproxy_yaml), LOGIN),
            (gate_dir(""), ROOT),
            (
                gate_dir(&file_name(crate::net::resolve_gate_sock().unwrap())),
                GVPROXY,
            ),
            (crate::control::GUEST_CONTROL_SOCK_FILE.to_string(), LOGIN),
            (
                crate::guest_telemetry::GUEST_TELEMETRY_SOCK_FILE.to_string(),
                LOGIN,
            ),
            ("/tmp/minvmd-marker-<pid>-<nonce>.sock".to_string(), LOGIN),
            // `cmd/run.rs` names the proxy socket beside the switch socket
            // with this literal. No constant carries it. It moves to the
            // gvproxy config dir, where the EGW process can reach it and
            // the VM user cannot.
            (gvproxy_config_dir("gvproxy-bep.sock"), LOGIN),
            (crate::control::CONTROL_SOCK_FILE.to_string(), LOGIN),
            (
                "EGW channel (descriptor 0 of the EGW process)".to_string(),
                LOGIN,
            ),
        ];

        check_table(&doc, "Ownership model", &required);
        // The fallback changes only the gvproxy rows. There gvproxy runs
        // as `minimal-vmm`, so its switch socket sits in `vmm/`. The gate
        // socket and `gvproxy-bep.sock` are named beside the switch socket
        // today, so the fallback names them in the provider dir, where
        // `<login>` still creates them.
        check_table(
            &doc,
            "Fallback: only gvproxy runs as `minimal-vmm`",
            &[
                ("<provider dir>/".to_string(), LOGIN),
                ("<provider dir>/vmm/".to_string(), ROOT),
                (gvproxy_yaml, LOGIN),
                (vmm(switch_sock), VMM),
                (file_name(crate::net::resolve_gate_sock().unwrap()), LOGIN),
                ("gvproxy-bep.sock".to_string(), LOGIN),
            ],
        );
    }

    const LOGIN: &str = "<login>";
    const VMM: &str = "minimal-vmm";
    const ROOT: &str = "root";
    const GVPROXY: &str = "minimal-gvproxy";

    /// The users named at the start of each comma-separated entry of `cell`,
    /// ignoring commas inside parentheses. `None` when an entry does not
    /// start with one of the four users the design knows.
    fn users_in(cell: &str) -> Option<Vec<&'static str>> {
        let mut entries = Vec::new();
        let (mut depth, mut start) = (0usize, 0usize);
        for (i, c) in cell.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    entries.push(&cell[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        entries.push(&cell[start..]);
        entries
            .into_iter()
            .map(|entry| {
                let token = entry.split_whitespace().next()?;
                [LOGIN, VMM, ROOT, GVPROXY]
                    .into_iter()
                    .find(|u| *u == token)
            })
            .collect()
    }

    /// Checks that the table in the `## <heading>` section of `doc` has a
    /// row for each name in `required`. Each row names the expected
    /// creating user first, a four-digit octal mode that gives its owner
    /// some access, and only known users as opening users. A mode with no
    /// group and no other bits admits only its owner, so such a row must
    /// name no opening user except the owner. The owner is the user after
    /// `owner` in the mode cell, or else the creating user. The check does
    /// not prove that a group mode names the right group for each opener.
    fn check_table(doc: &str, heading: &str, required: &[(String, &str)]) {
        let section = doc
            .split("\n## ")
            .find(|s| s.starts_with(&format!("{heading}\n")))
            .unwrap_or_else(|| panic!("the design has a `## {heading}` section"));
        let rows: Vec<Vec<String>> = section
            .lines()
            .filter(|l| l.starts_with('|') && !l.starts_with("|---"))
            .map(|l| {
                l.trim_matches('|')
                    .split('|')
                    .map(|c| c.replace('`', "").trim().to_string())
                    .collect()
            })
            .filter(|cells: &Vec<String>| cells.first().is_some_and(|c| c != "Path"))
            .collect();

        for (name, creator) in required {
            let row = rows
                .iter()
                .find(|cells| &cells[0] == name)
                .unwrap_or_else(|| panic!("the {heading} table has no row for {name}"));
            assert_eq!(row.len(), 4, "row for {name} has four columns: {row:?}");
            let creators = users_in(&row[1])
                .unwrap_or_else(|| panic!("row for {name} names a known creating user: {row:?}"));
            assert_eq!(
                creators.first(),
                Some(creator),
                "row for {name} is created by {creator}: {row:?}",
            );
            let mode = row[2].split([' ', ',']).next().unwrap_or("");
            assert!(
                mode.len() == 4 && mode.chars().all(|c| ('0'..='7').contains(&c)),
                "row for {name} names a four-digit octal mode, got {:?}",
                row[2],
            );
            assert_ne!(
                &mode[1..2],
                "0",
                "row for {name} gives its owner some access, got {:?}",
                row[2],
            );
            let openers = users_in(&row[3]).unwrap_or_else(|| {
                panic!("row for {name} names only known opening users: {row:?}")
            });
            assert!(!openers.is_empty(), "row for {name} names an opening user");
            // A 0600 entry that lists another opener contradicts itself.
            let owner = row[2]
                .split(',')
                .find_map(|part| part.trim().strip_prefix("owner "))
                .map(|rest| {
                    users_in(rest.trim())
                        .and_then(|users| users.first().copied())
                        .unwrap_or_else(|| panic!("row for {name} names a known owner: {row:?}"))
                })
                .unwrap_or(*creator);
            if &mode[2..] == "00" {
                assert!(
                    openers.iter().all(|u| *u == owner),
                    "row for {name} has mode {mode}, so only {owner} can open it: {row:?}",
                );
            }
        }
    }
}
