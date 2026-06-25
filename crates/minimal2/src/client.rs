//! SSH client transport for talking to minimald over the UDS bridge.
//!
//! Provides a `russh`-based client that connects to `minimald` over the UNIX
//! domain socket, authenticates (passwordless), and invokes oneshot RPCs
//! defined in the `minimald-rpc` wire contract.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use minimald_rpc::{MINIMAL_SESSION_ID_ENV, OneshotSshRpc, STREAM_WORKSPACE_FILES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Max retries when connecting to the daemon UDS.
const CONNECT_RETRIES: u32 = 20;
/// Delay between connection retries.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// russh client handler that accepts any ephemeral host key.
///
/// The daemon generates a fresh host key on every boot. Since we connect over
/// a local UDS (not the network), TOFU trust is acceptable here.
struct MinimalClientHandler;

impl russh::client::Handler for MinimalClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// An authenticated SSH session to minimald.
pub struct Client {
    handle: russh::client::Handle<MinimalClientHandler>,
}

impl Client {
    /// Connect to minimald over the UDS at `sock_path`, authenticate, and
    /// return a ready [`Client`].
    ///
    /// Retries the UDS connect for up to ~2 seconds to absorb the post-boot
    /// race on macOS where the libkrun bridge UDS appears slightly after the
    /// `vm-up` line.
    pub async fn connect(sock_path: &Path) -> Result<Self, String> {
        let stream = {
            let mut conn = None;
            let mut last_err = None;
            for _ in 0..CONNECT_RETRIES {
                match tokio::net::UnixStream::connect(sock_path).await {
                    Ok(s) => {
                        conn = Some(s);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                    }
                }
            }
            conn.ok_or_else(|| {
                format!(
                    "connect to daemon at {}: {}",
                    sock_path.display(),
                    last_err.unwrap()
                )
            })?
        };

        let config = Arc::new(russh::client::Config::default());
        let mut handle = russh::client::connect_stream(config, stream, MinimalClientHandler)
            .await
            .map_err(|e| format!("ssh connect: {e}"))?;

        let auth = handle
            .authenticate_none("minimal-cli")
            .await
            .map_err(|e| format!("authenticate: {e}"))?;

        if !auth.success() {
            return Err("authentication rejected by daemon".into());
        }

        Ok(Client { handle })
    }

    /// Issue a oneshot RPC: open a channel, request the subsystem, write the
    /// serialized request, half-close, and decode the response.
    ///
    /// The type parameter `R` picks the RPC from the wire contract; `request`
    /// is serialized to JSON and the response is deserialized from JSON.
    pub async fn oneshot_rpc<R: OneshotSshRpc>(
        &mut self,
        request: R::Request<'_>,
    ) -> Result<R::Response, String>
    where
        <R as OneshotSshRpc>::Response: serde::de::DeserializeOwned,
    {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open channel for {}: {e}", R::NAME))?;

        channel
            .request_subsystem(false, R::NAME)
            .await
            .map_err(|e| format!("request subsystem {}: {e}", R::NAME))?;

        let body = serde_json::to_vec(&request).map_err(|e| format!("serialize request: {e}"))?;

        let mut rpc = channel.into_stream();
        rpc.write_all(&body)
            .await
            .map_err(|e| format!("write request: {e}"))?;
        rpc.shutdown()
            .await
            .map_err(|e| format!("shutdown write half: {e}"))?;

        let mut resp_buf = Vec::with_capacity(256);
        rpc.read_to_end(&mut resp_buf)
            .await
            .map_err(|e| format!("read response: {e}"))?;

        serde_json::from_slice(&resp_buf)
            .map_err(|e| format!("decode response for {}: {e}", R::NAME))
    }

    /// Stream the project directory into the session's workspace
    /// (copy-on-activate). Builds an ignore-aware `tar.zst` of `project_dir`
    /// and uploads it over the `WorkspaceFilesTarZst` subsystem; the daemon
    /// unpacks it into the session worktree. Reports server-side unpack errors
    /// (relayed on the channel's stderr stream) as `Err`.
    pub async fn upload_workspace(
        &mut self,
        session_id: &str,
        project_dir: &Path,
    ) -> Result<(), String> {
        let payload = build_workspace_tar_zst(project_dir).await?;

        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open workspace channel: {e}"))?;

        // The server reads the session id from the channel env, captured at
        // subsystem-request time — so set_env must precede request_subsystem.
        channel
            .set_env(true, MINIMAL_SESSION_ID_ENV, session_id)
            .await
            .map_err(|e| format!("set_env {MINIMAL_SESSION_ID_ENV}: {e}"))?;
        channel
            .request_subsystem(true, STREAM_WORKSPACE_FILES)
            .await
            .map_err(|e| format!("request subsystem {STREAM_WORKSPACE_FILES}: {e}"))?;

        channel
            .data(&payload[..])
            .await
            .map_err(|e| format!("stream workspace tarball: {e}"))?;
        channel
            .eof()
            .await
            .map_err(|e| format!("half-close workspace channel: {e}"))?;

        // Drain until the server closes the channel; it relays any unpack
        // failure on extended-data stream 1 (stderr).
        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                stderr.extend_from_slice(&data);
            }
        }
        if !stderr.is_empty() {
            return Err(String::from_utf8_lossy(&stderr).trim().to_owned());
        }
        Ok(())
    }
}

/// Build an ignore-aware zstd-compressed tar of `project_dir`, with entry paths
/// relative to the project root. Honours `.gitignore`, `.ignore`, and a custom
/// `.minimalignore` (via the `ignore` crate's gitignore semantics) even outside
/// a git repo. Dotfiles are kept, but `.git` is always skipped. Symlinks are
/// not followed. File modes are preserved.
async fn build_workspace_tar_zst(project_dir: &Path) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::PermissionsExt;

    // Collect the file set synchronously (the `ignore` walk is sync), then
    // stream contents asynchronously below.
    let mut files = Vec::new();
    let walker = ignore::WalkBuilder::new(project_dir)
        // Keep dotfiles (.github, .env, .gitignore, …) — they're part of the
        // project — but never the VCS dir itself.
        .hidden(false)
        .filter_entry(|e| e.file_name() != ".git")
        // Apply ignore files even when project_dir is not a git working tree.
        .require_git(false)
        .add_custom_ignore_filename(".minimalignore")
        .build();
    for entry in walker {
        let entry = entry.map_err(|e| format!("walk project: {e}"))?;
        if entry.file_type().is_some_and(|t| t.is_file()) {
            files.push(entry.into_path());
        }
    }

    let mut builder = async_tar::Builder::new(Vec::new());
    for path in &files {
        let rel = path
            .strip_prefix(project_dir)
            .map_err(|e| format!("relativize {}: {e}", path.display()))?;
        let meta = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        let contents = tokio::fs::read(path)
            .await
            .map_err(|e| format!("read {}: {e}", path.display()))?;

        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(meta.permissions().mode() & 0o777);
        builder
            .append_data(&mut header, rel, &contents[..])
            .await
            .map_err(|e| format!("tar append {}: {e}", rel.display()))?;
    }

    let tar_bytes = builder
        .into_inner()
        .await
        .map_err(|e| format!("finalize tar: {e}"))?;

    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder
        .write_all(&tar_bytes)
        .await
        .map_err(|e| format!("zstd compress: {e}"))?;
    encoder
        .shutdown()
        .await
        .map_err(|e| format!("zstd finalize: {e}"))?;
    Ok(encoder.into_inner())
}

/// Resolve the daemon socket path.
///
/// On Linux: `$XDG_STATE_HOME/minimal/providers/local-0/ssh.sock` (matching
/// `minimald`'s `listen_on()`).
///
/// On macOS: delegates to `minvmd::sock::resolve_uds_path()` (the bridge
/// socket created by the minvmd host daemon).
///
/// If `--minimal-dir` is set, use `<minimal_dir>/providers/local-0/ssh.sock`
/// on Linux, or `<minimal_dir>/minimald.sock` on macOS.
pub fn resolve_socket_path(
    minimal_dir_override: Option<&std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    if let Some(dir) = minimal_dir_override {
        #[cfg(target_os = "linux")]
        return Ok(dir.join("providers/local-0/ssh.sock"));
        #[cfg(target_os = "macos")]
        return Ok(dir.join("minimald.sock"));
    }
    #[cfg(target_os = "linux")]
    {
        let state = dirs::state_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".local/state")))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "cannot determine state directory; set --minimal-dir",
                )
            })?;
        Ok(state.join("minimal/providers/local-0/ssh.sock"))
    }
    #[cfg(target_os = "macos")]
    minvmd::sock::resolve_uds_path()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::build_workspace_tar_zst;

    /// Decompress + read the tar produced by `build_workspace_tar_zst` and
    /// return its entry paths.
    fn entry_paths(tar_zst: &[u8]) -> BTreeSet<String> {
        let tar_bytes = zstd::stream::decode_all(tar_zst).expect("zstd decode");
        let mut archive = tar::Archive::new(&tar_bytes[..]);
        archive
            .entries()
            .expect("entries")
            .map(|e| {
                e.expect("entry")
                    .path()
                    .expect("path")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    fn write(root: &std::path::Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[tokio::test]
    async fn workspace_tar_honours_ignore_files_keeps_dotfiles_skips_git() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Kept: project files and non-git dotfiles.
        write(root, "minimal.toml", "name = \"p\"\n");
        write(root, "src/main.rs", "fn main() {}\n");
        write(root, ".github/workflows/ci.yml", "on: push\n");

        // .gitignore excludes build output; .minimalignore excludes a secret.
        write(root, ".gitignore", "ignored.txt\n/target\n");
        write(root, ".minimalignore", "secret.txt\n");
        write(root, "ignored.txt", "nope");
        write(root, "secret.txt", "nope");
        write(root, "target/junk.o", "nope");

        // The VCS dir is always skipped even though dotfiles are kept.
        write(root, ".git/config", "[core]\n");

        let paths = entry_paths(&build_workspace_tar_zst(root).await.unwrap());

        assert!(paths.contains("minimal.toml"), "got {paths:?}");
        assert!(paths.contains("src/main.rs"), "got {paths:?}");
        assert!(
            paths.contains(".github/workflows/ci.yml"),
            "dotfiles kept; got {paths:?}"
        );
        // .gitignore and .minimalignore themselves ship (they're project files).
        assert!(paths.contains(".gitignore"), "got {paths:?}");

        assert!(!paths.contains("ignored.txt"), ".gitignore; got {paths:?}");
        assert!(
            !paths.contains("secret.txt"),
            ".minimalignore; got {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with("target/")),
            "target/ gitignored; got {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with(".git/")),
            ".git skipped; got {paths:?}"
        );
    }
}
