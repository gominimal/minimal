//! Bidirectional UDS bridge: host socket <-> in-VM minimald socket.

use crate::uds;
use anyhow::{Context as _, Result};
use std::path::Path;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Byte-pump between the host control socket and the in-VM minimald socket.
///
/// Listens on `host_sock` and, for each accepted connection, connects to
/// `vsock_sock` and copies bytes bidirectionally. Runs until
/// `token` is cancelled, then drains all in-flight relay tasks before
/// returning.
///
/// The pump is *opaque*: minvmd never parses the minimald SSH RPC frames that
/// ride over these streams — that is terminated by minimald inside the guest.
pub async fn serve(host_sock: &Path, vsock_sock: &Path, token: CancellationToken) -> Result<()> {
    // create parent dir with mode 0700
    if let Some(parent) = host_sock.parent()
        && !parent.as_os_str().is_empty()
    {
        create_dir_restricted(parent)?;
    }

    // bind host socket
    let listener = uds::listen(host_sock).await.context("bind host socket")?;

    // set the host socket to mode 0600 after bind. We use a path-based
    // chmod rather than fchmod because fchmod on a Unix-domain socket fd
    // returns EINVAL on macOS (Darwin) — the only platform this broker runs on
    // in production. The socket lives inside the 0700 parent created above, so
    // no other user can traverse to it during the brief post-bind window.
    set_file_mode(host_sock, 0o600)?;

    // Accept loop with cancellation. Spawned relay tasks are
    // tracked in a JoinSet and carry a clone of the token so cancellation
    // drops both streams; serve drains them before returning.
    let mut pumps: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            result = listener.accept() => {
                let (mut client, _) = result.context("accept on host socket")?;
                let vsock_path = vsock_sock.to_path_buf();
                let task_token = token.clone();
                pumps.spawn(async move {
                    // connect to in-VM minimald
                    match uds::connect(&vsock_path).await {
                        Ok(mut server) => {
                            // opaque bidirectional byte pump. Cancellation
                            // drops both streams, terminating the pump cleanly.
                            tokio::select! {
                                _ = task_token.cancelled() => {}
                                _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                            }
                        }
                        Err(e) => {
                            tracing::warn!("broker: vsock connect failed: {e}");
                        }
                    }
                });
            }
        }
    }

    // drain in-flight pumps so serve does not return while bytes are
    // still being relayed.
    while pumps.join_next().await.is_some() {}
    Ok(())
}

fn create_dir_restricted(path: &Path) -> Result<()> {
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

fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    #[tokio::test]
    async fn byte_pump_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let host_path = dir.path().join("host.sock");
        let vsock_path = dir.path().join("vsock.sock");

        // Bind the "vsock" server (mimics minimald inside the VM).
        let vsock_server = UnixListener::bind(&vsock_path).unwrap();

        let token = CancellationToken::new();
        let cancel = token.clone();
        let hp = host_path.clone();
        let vp = vsock_path.clone();

        tokio::spawn(async move {
            serve(&hp, &vp, cancel).await.unwrap();
        });

        // Connect as the "minimal" client once the broker has bound, retrying
        // until the host socket is ready rather than sleeping a fixed amount.
        let mut client = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match UnixStream::connect(&host_path).await {
                    Ok(stream) => break stream,
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(err) => panic!("failed to connect to broker: {err}"),
                }
            }
        })
        .await
        .expect("broker did not bind in time");

        // Accept on the vsock side (mimics minimald accepting).
        let (mut vm_side, _) = vsock_server.accept().await.unwrap();

        // client → VM
        client.write_all(b"hello from minimal").await.unwrap();
        let mut buf = vec![0u8; 18];
        vm_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from minimal");

        // VM → client
        vm_side.write_all(b"hello from minimald").await.unwrap();
        let mut buf2 = vec![0u8; 19];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello from minimald");

        token.cancel();
    }
}
