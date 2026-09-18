//! PTY + file-descriptor plumbing for [`super`]'s host.
//!
//! Owns the `WinSize`/`Pty` pair and the raw-`fd` helpers (`dup_fd`,
//! `get_winsize`/`set_winsize`, `set_nonblocking`/`set_cloexec`) they and
//! the host rely on.

use super::*;

/// The dimensions of a terminal.
///
/// This is the libc-facing view of a terminal size, mirroring `libc::winsize`.
/// The SSH layer's [`RequestedPty`] carries the same dimensions (plus `term`
/// and terminal modes) as `u32`s; convert via [`From`] when opening a PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl From<&RequestedPty> for WinSize {
    /// Extracts the terminal dimensions, clamping SSH's `u32` to
    /// `u16` and replacing any zero dimension with a 24×80 default
    /// (avoids a vt100 panic on unprobed clients).
    fn from(pty: &RequestedPty) -> Self {
        let (cols, rows) = pty.char_sizes;
        let (xpixel, ypixel) = pty.pixel_sizes;
        let rows = rows.min(u16::MAX as u32) as u16;
        let cols = cols.min(u16::MAX as u32) as u16;
        Self {
            rows: if rows == 0 { 24 } else { rows },
            cols: if cols == 0 { 80 } else { cols },
            xpixel: xpixel.min(u16::MAX as u32) as u16,
            ypixel: ypixel.min(u16::MAX as u32) as u16,
        }
    }
}

/// A pseudo-terminal pair (master + slave).
#[derive(Debug)]
pub struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
    /// Filesystem path of the slave side (`/dev/pts/N`), captured at
    /// open.
    ///
    /// Exists so a caller that needs the terminal *later* — a lifecycle
    /// hook wanting a real tty for `[ -t 1 ]` and `tput` — can open a
    /// short-lived descriptor and close it again, instead of retaining
    /// a spare slave fd for the session's lifetime. Retaining one is
    /// precisely the leak the `set_cloexec` comment below warns about:
    /// while any slave fd stays open the master never sees EOF, so the
    /// host never observes the shell exiting and the session is never
    /// reaped.
    slave_path: std::path::PathBuf,
}

impl Pty {
    /// Creates a new PTY pair via `openpty(3)` with the given initial size.
    pub fn open(size: WinSize) -> io::Result<Self> {
        let mut master: RawFd = -1;
        let mut slave: RawFd = -1;

        let ws = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.xpixel,
            ws_ypixel: size.ypixel,
        };

        // SAFETY: We pass valid pointers for the output fds and winsize, and
        // NULL for the optional name/termios parameters.
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &ws,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `openpty` returned successfully, so both fds are valid and
        // open. We take ownership immediately.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };

        // `openpty` returns fds without close-on-exec. Set it so these fds
        // don't leak into unrelated child processes that happen to `fork`
        // concurrently: a leaked slave fd would keep this master from ever
        // seeing EOF when our own child exits, stalling teardown. The child we
        // intend to wire up still gets its stdio via `dup2`, which is unaffected
        // by the source fd's close-on-exec flag.
        set_cloexec(master.as_raw_fd())?;
        set_cloexec(slave.as_raw_fd())?;

        // `ptsname_r`, not `ptsname`: the latter returns a pointer to a
        // static buffer, which is not safe to call from a daemon that
        // opens PTYs from more than one task.
        let slave_path = {
            let mut buf = [0 as libc::c_char; 128];
            // SAFETY: `master` is a live PTY master fd; `buf` is a valid
            // writable array of the length passed alongside it.
            let ret = unsafe { libc::ptsname_r(master.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
            if ret != 0 {
                return Err(io::Error::from_raw_os_error(ret));
            }
            // SAFETY: on success `ptsname_r` wrote a NUL-terminated
            // string into `buf`.
            let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
            std::path::PathBuf::from(
                std::str::from_utf8(cstr.to_bytes())
                    .map_err(|_| io::Error::other("pty slave path is not valid UTF-8"))?,
            )
        };

        Ok(Self {
            master,
            slave,
            slave_path,
        })
    }

    /// Path of the slave side, for opening a short-lived terminal
    /// descriptor after the pair has been wired to a process. See
    /// [`Pty::slave_path`](Self::slave_path) on the struct for why this
    /// is a path rather than a retained descriptor.
    pub fn slave_path(&self) -> &std::path::Path {
        &self.slave_path
    }

    /// Returns the raw file descriptor for the master side.
    pub fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// Returns the raw file descriptor for the slave side.
    pub fn slave_fd(&self) -> RawFd {
        self.slave.as_raw_fd()
    }

    /// Returns a duplicate file descriptor for the slave side.
    pub fn dup_slave_fd(&self) -> io::Result<OwnedFd> {
        dup_fd(&self.slave)
    }

    /// Consumes the PTY pair, returning the owned master and slave fds.
    pub fn into_fds(self) -> (OwnedFd, OwnedFd) {
        (self.master, self.slave)
    }

    /// Gets the current terminal size of the slave side.
    pub fn get_size(&self) -> io::Result<WinSize> {
        get_winsize(self.master.as_raw_fd())
    }

    /// Sets the terminal size of the slave side.
    pub fn set_size(&self, size: WinSize) -> io::Result<()> {
        set_winsize(self.master.as_raw_fd(), size)
    }
}

/// Duplicate `fd` into a new close-on-exec `OwnedFd` via
/// `F_DUPFD_CLOEXEC`, so a concurrent `fork` can't inherit and hold
/// the pty open past our child's exit.
pub(crate) fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` succeeded, so `raw` is a valid, open fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Reads the terminal window size for the given fd.
pub(crate) fn get_winsize(fd: RawFd) -> io::Result<WinSize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `ws` is a valid, zeroed `winsize` struct and `fd` is an open fd.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WinSize {
        rows: ws.ws_row,
        cols: ws.ws_col,
        xpixel: ws.ws_xpixel,
        ypixel: ws.ws_ypixel,
    })
}

/// Sets the terminal window size for the given fd.
pub(crate) fn set_winsize(fd: RawFd, size: WinSize) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.xpixel,
        ws_ypixel: size.ypixel,
    };
    // SAFETY: `ws` is a valid `winsize` struct and `fd` is an open fd.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Puts a file descriptor into non-blocking mode.
pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is a valid open file descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Marks a file descriptor close-on-exec (`FD_CLOEXEC`).
pub(crate) fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is a valid open file descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
