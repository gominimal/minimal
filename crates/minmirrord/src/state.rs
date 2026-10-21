//! The daemon's lifecycle on disk: the alive lock one running daemon holds,
//! and the lifecycle file every client reads (MIR-070).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

use mirror_client::{Lifecycle, MirrorDirs, MirrorState};

/// The alive lock: held for the daemon's life, released by the kernel when
/// the process is gone, so a stale lifecycle file never claims a daemon.
pub struct AliveLock {
    _file: File,
}

impl AliveLock {
    /// Takes the lock, or `None` when another daemon holds it.
    pub fn try_acquire(path: &Path) -> io::Result<Option<Self>> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        // SAFETY: flock takes an open descriptor we own and two flags; it
        // reads no memory of ours.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(Self { _file: file }));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            Err(err)
        }
    }
}

/// Writes the lifecycle file for this process.
pub fn write(dirs: &MirrorDirs, lifecycle: Lifecycle) -> io::Result<()> {
    mirror_client::write_state(
        dirs,
        &MirrorState {
            lifecycle,
            pid: std::process::id(),
            host_socket: dirs.host_socket(),
            door_socket: dirs.door_socket(),
            store: dirs.store.clone(),
            written_at: mirror_client::now_secs(),
        },
    )
}
