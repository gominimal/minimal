//! The mirror door (MIR-023): the vsock port the guest daemon reads the
//! laptop's mirror through.
//!
//! The supervisor (`cmd/run`) reads the `[mirror]` table of the client
//! configuration file (MIR-022), starts the mirror daemon if it is not
//! running, and hands the VMM child the mirror's door socket in
//! [`MIRROR_DOOR_SOCK_ENV`]; the child registers the door's vsock port
//! ([`mirror_client::DOOR_PORT`]) against that socket and writes the door
//! token on the guest's boot line (`vm::kernel_cmdline`), so every
//! connection the guest opens on the port reaches the mirror. A mirror that
//! is disabled or does not start leaves the VM without the door, and the
//! guest then fetches from the origins directly (MIR-024).

use std::path::{Path, PathBuf};

use mirror_client::{MirrorConfig, MirrorDirs};

/// The environment variable the supervisor hands the VMM child the mirror's
/// door socket in, by the transport the marker socket and the other doors
/// ride: the child is a separate process. Absent when the mirror is
/// disabled or did not start, and the child then registers no door.
pub const MIRROR_DOOR_SOCK_ENV: &str = "MINVMD_MIRROR_DOOR_SOCK";

/// The client configuration file the VM host daemon reads the `[mirror]`
/// table from: the file `min dirs` prints (O3).
// Only the supervisor calls this, and the supervisor needs libkrun.
#[cfg_attr(
    not(minvmd_libkrun),
    expect(dead_code, reason = "used only by the libkrun build")
)]
pub(crate) fn client_config_path() -> PathBuf {
    paths::minimal_config_dir()
        .as_utf8_path()
        .as_std_path()
        .join("config.toml")
}

/// Whether the client configuration at `config_path` enables the mirror
/// (MIR-022). A missing file, or one without the table, enables it; a file
/// that cannot be read or parsed is warned and counts as disabled, so the
/// VM boots without the door and `min` reports the file's fault on its
/// next project command.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
pub(crate) fn mirror_enabled(config_path: &Path) -> bool {
    match MirrorConfig::read_table(config_path) {
        Ok(table) => table.enabled,
        Err(error) => {
            tracing::warn!(
                %error,
                "cannot read the [mirror] table of the client configuration; the VM boots \
                 without the mirror door"
            );
            false
        }
    }
}

/// The door socket the VMM child bridges the guest's door to: the running
/// mirror's, started on demand (MIR-023), under the state base the
/// `--minimal-state-dir` override names when there is one. `None` when the
/// configuration at `config_path` disables the mirror, or when the mirror
/// did not start, which is warned with its cause: the VM boots without the
/// door either way.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
pub(crate) fn open_mirror_door(config_path: &Path, state_base: Option<&Path>) -> Option<PathBuf> {
    if !mirror_enabled(config_path) {
        tracing::info!(
            "the client configuration disables the mirror; the VM boots without its door"
        );
        return None;
    }
    let dirs = MirrorDirs::resolve(state_base);
    match mirror_client::ensure_running(&dirs) {
        Ok(state) => Some(state.door_socket),
        Err(error) => {
            tracing::warn!(
                %error,
                "the mirror did not start; the VM boots without its door and the guest fetches \
                 from the origins directly"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MIR-022: the VM host daemon reads the `[mirror]` table of the client
    /// configuration file. `enabled = false` closes the door before any
    /// daemon is looked for or started, a missing file leaves it enabled,
    /// and a file that does not parse closes it.
    #[test]
    fn vm_host_daemon_reads_mirror_table_from_client_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[loadouts]\ndefault_loadouts = []\n[mirror]\nenabled = false\n",
        )
        .unwrap();
        assert!(!mirror_enabled(&config_path));
        let state_base = tmp.path().join("state");
        assert_eq!(open_mirror_door(&config_path, Some(&state_base)), None);
        assert!(
            !MirrorDirs::resolve(Some(&state_base)).state.exists(),
            "a disabled mirror is neither looked for nor started"
        );

        assert!(mirror_enabled(&tmp.path().join("absent.toml")));

        std::fs::write(&config_path, "[mirror]\nenabled = \"maybe\"\n").unwrap();
        assert!(!mirror_enabled(&config_path));
    }
}
