//! Connect to the guest root debug shell via vsock.

use crate::error::UserFacing;
use crate::uds;
use anyhow::{Context as _, Result};
use sessions::paths::HostAbsPath;
use std::path::Path;
use tokio::io::{self, AsyncRead, AsyncWrite};

/// Default path to the root debug shell socket on the host.
///
/// Anchored at the user's home directory (`~/.minimal/vm/root-debug.sock`),
/// which is always absolute.
pub fn debug_shell_socket_path() -> Result<HostAbsPath> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let path = home.join(".minimal/vm/root-debug.sock");
    let utf8 = camino::Utf8PathBuf::from_path_buf(path).map_err(|p| {
        anyhow::anyhow!(
            "debug shell socket path is not valid UTF-8: {}",
            p.display()
        )
    })?;
    HostAbsPath::try_new(utf8).context("debug shell socket path must be absolute")
}

/// Connect to the root debug shell and forward stdin/stdout bidirectionally.
pub async fn connect_debug_shell(socket_path: &Path) -> Result<()> {
    // a missing socket is the only user-facing condition. Check existence
    // up front so the connect call below can propagate every *other* failure
    // (e.g. permission denied) with `?` rather than masking it as "not found".
    if !socket_path.exists() {
        return Err(anyhow::Error::from(UserFacing::new(format!(
            "debug shell socket not found: {}",
            socket_path.display()
        ))));
    }

    let stream = uds::connect(socket_path).await?;

    // Bridge the host terminal (stdin/stdout) to the socket. join() pairs the
    // read-only stdin with the write-only stdout into one duplex.
    let local = io::join(io::stdin(), io::stdout());
    bridge(local, stream).await
}

/// Forward bytes both ways between a local duplex and the debug-shell socket.
///
/// `local` carries the host terminal (stdin -> socket, socket -> stdout).
///
/// Drives the two directions independently and returns as soon as *either*
/// completes. `copy_bidirectional` is unsuitable here: it returns only after
/// *both* directions reach EOF, so a guest disconnect (socket -> stdout hits
/// EOF) while the local stdin stays open would leave the stdin -> socket copy
/// waiting forever and the subcommand would hang. Returning on the first
/// direction to finish makes "exit on socket disconnect" hold (-> exit 0).
async fn bridge<L, S>(local: L, stream: S) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_rd, mut local_wr) = io::split(local);
    let (mut sock_rd, mut sock_wr) = io::split(stream);

    tokio::select! {
        // Guest disconnect: socket -> stdout hits EOF; return so we exit 0.
        r = io::copy(&mut sock_rd, &mut local_wr) => { r?; }
        // Local stdin closed (e.g. EOF / Ctrl-D): stdin -> socket finishes.
        r = io::copy(&mut local_rd, &mut sock_wr) => { r?; }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// proof artifact: bind an in-process `UnixListener`, invoke the
    /// debug-shell connect path (`bridge` over a real `uds::connect` stream),
    /// send a byte sequence through the local side, and assert it arrives at
    /// the listener; then close the listener and assert `bridge` returns
    /// `Ok(())`.
    #[tokio::test]
    async fn test_debug_shell_connect() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let socket_path = temp_dir.path().join("test.sock");

        let listener = UnixListener::bind(&socket_path)?;

        // Server side: accept, read the bytes the bridge forwards from the
        // local "stdin", assert them, then drop the connection (EOF) so the
        // bridge's socket->stdout copy completes and the function returns Ok.
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf)
                .await
                .expect("read forwarded bytes");
            assert_eq!(&buf, b"hello", "bridge should forward stdin to the socket");
            // Dropping `conn` here closes the socket, signalling disconnect.
        });

        // Connect to the listener via the production transport path.
        let stream = uds::connect(&socket_path).await?;

        // Drive `bridge` with an in-memory duplex standing in for the terminal:
        // `local_test` is the test's handle to the local side; `local_bridge`
        // is what the bridge treats as stdin/stdout.
        let (mut local_test, local_bridge) = io::duplex(1024);
        let bridge_task = tokio::spawn(async move { bridge(local_bridge, stream).await });

        // Write the byte sequence into the local side; the bridge forwards it
        // to the socket, where the server asserts it. Shutdown signals EOF on
        // the stdin->socket direction.
        local_test.write_all(b"hello").await?;
        local_test.flush().await?;
        local_test.shutdown().await?;

        server.await?;
        // on disconnect the bridge returns Ok(()).
        bridge_task.await??;
        Ok(())
    }

    /// (disconnect-only): the guest socket closes while the local stdin
    /// side stays open; `bridge` must still return promptly so the subcommand
    /// exits 0. This is the case `copy_bidirectional` would hang on.
    #[tokio::test]
    async fn bridge_returns_when_socket_disconnects_with_local_open() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let socket_path = temp_dir.path().join("disc.sock");
        let listener = UnixListener::bind(&socket_path)?;

        // Server accepts then immediately drops the connection (disconnect).
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            drop(conn);
        });

        let stream = uds::connect(&socket_path).await?;

        // `_local_test` is deliberately kept alive (never shut down) so the
        // local stdin->socket direction never hits EOF; only the socket
        // disconnect can make `bridge` return.
        let (_local_test, local_bridge) = io::duplex(1024);
        let bridge_task = tokio::spawn(async move { bridge(local_bridge, stream).await });

        server.await?;
        // Bound the wait so a regression (hang) fails fast instead of stalling
        // the suite.
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge_task)
            .await
            .expect("bridge should return promptly on socket disconnect")?;
        res?;
        Ok(())
    }
}
