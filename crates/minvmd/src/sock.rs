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

/// Verify that `dir` is owned by the calling process's uid and has mode
/// 0700. Return `PermissionDenied` otherwise, naming the directory and its
/// actual owner and mode.
pub fn verify_provider_dir_ownership(dir: &std::path::Path) -> io::Result<()> {
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

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the Minimal state directory {} has mode {mode:04o}, but it must be 0700; run \
                 `chmod 700` on it",
                dir.display(),
            ),
        ));
    }

    Ok(())
}

/// Tighten `dir` to 0700 when it is a directory the calling uid owns with
/// any other mode, so [`verify_provider_dir_ownership`] then holds.
///
/// The provider dir is first created by `StateDir::new`, which creates it
/// under the process umask (typically 0755), before any socket is bound;
/// [`prepare_socket_dir`] leaves a pre-existing dir untouched. Refusing
/// such a dir outright would refuse every existing install. Only the
/// owner (or root) can change a dir's mode, so tightening our own dir is
/// safe; a dir owned by another uid is left as is for the verification to
/// refuse.
pub fn restrict_owned_dir(dir: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let meta = std::fs::metadata(dir)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let my_uid = unsafe { libc::geteuid() };
    let mode = meta.permissions().mode() & 0o777;
    if meta.is_dir() && meta.uid() == my_uid && mode != 0o700 {
        tracing::info!(
            dir = %dir.display(),
            mode = format_args!("{mode:04o}"),
            "tightening the provider directory to 0700"
        );
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
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
