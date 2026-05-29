//! Minimal Unix-domain-socket connect/listen helpers.
//!
//! minvmd carries these two trivial wrappers itself rather than pulling in a
//! shared UDS crate: the broker only needs a connect and a listen.
//!
//! The broker byte-pumps these streams *opaquely*: it does not parse the
//! minimald SSH RPC frames riding over them. That layering is preserved.

use std::io;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};

/// Connect to the Unix-domain socket at `path`.
pub async fn connect(path: &Path) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}

/// Bind a listener on the Unix-domain socket at `path`, removing any stale
/// socket file first.
pub async fn listen(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    UnixListener::bind(path)
}
