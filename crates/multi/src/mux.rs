//! PTY (pseudo-terminal) pair creation, management, and multiplexing.
//!
//! The [`Mux`] struct orchestrates running a program inside a PTY, wiring the
//! master end of the PTY to a [`vt100_ctt::Parser`] so callers can inspect the
//! virtual terminal screen at any time.

use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

/// The dimensions of a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

/// A pseudo-terminal pair (master + slave).
#[derive(Debug)]
pub struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
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

        Ok(Self { master, slave })
    }

    /// Returns the raw file descriptor for the master side.
    pub fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// Returns the raw file descriptor for the slave side.
    pub fn slave_fd(&self) -> RawFd {
        self.slave.as_raw_fd()
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

/// Duplicates an `OwnedFd` into a new, independent `OwnedFd` via `dup(2)`.
pub fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::dup(fd.as_raw_fd()) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` succeeded, so `raw` is a valid, open fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Reads the terminal window size for the given fd.
fn get_winsize(fd: RawFd) -> io::Result<WinSize> {
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
pub fn set_winsize(fd: RawFd, size: WinSize) -> io::Result<()> {
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

// ---------------------------------------------------------------------------
// Mux: PTY-backed program runner with vt100 screen tracking
// ---------------------------------------------------------------------------

/// Orchestrates running a program with its stdio connected to a PTY, feeding
/// all output through a [`vt100_ctt::Parser`] so the virtual terminal screen
/// can be inspected at any time.
///
/// The child process is launched via [`hakoniwa::Command`] (sandboxed execution).
/// The master side of the PTY is registered with the tokio reactor via
/// [`AsyncFd`], so read/write operations are async and cooperate with the
/// runtime instead of blocking.
pub struct Mux {
    /// The master side of the PTY, wrapped for async I/O via tokio's reactor.
    master: AsyncFd<std::fs::File>,

    /// VT100 terminal parser/screen that tracks what the child has drawn.
    parser: vt100_ctt::Parser,

    /// The running child process.
    child: hakoniwa::Child,
}

impl Mux {
    /// Spawns a program inside a new PTY.
    ///
    /// The PTY slave fd is wired to the command's stdin, stdout, and stderr so
    /// the child believes it is attached to a real terminal. The master end is
    /// retained for reading output and writing input.
    ///
    /// `size` sets the initial terminal dimensions.
    ///
    /// Must be called from within a tokio runtime context (the master fd is
    /// registered with the reactor).
    pub fn spawn(mut command: hakoniwa::Command, size: WinSize) -> io::Result<Self> {
        let pty = Pty::open(size)?;
        let (master, slave) = pty.into_fds();

        // Wire the slave fd to all three stdio streams of the child.
        // Each call to `.stdin()` etc. consumes an `OwnedFd`, so we dup for
        // the second and third.
        let slave_for_stdout = dup_fd(&slave)?;
        let slave_for_stderr = dup_fd(&slave)?;
        command.stdin(hakoniwa::Stdio::from(slave));
        command.stdout(hakoniwa::Stdio::from(slave_for_stdout));
        command.stderr(hakoniwa::Stdio::from(slave_for_stderr));

        let child = command.spawn().map_err(io::Error::other)?;

        // Put the master fd into non-blocking mode so it works with AsyncFd.
        set_nonblocking(master.as_raw_fd())?;

        let file = unsafe { std::fs::File::from_raw_fd(master.into_raw_fd()) };
        let master = AsyncFd::new(file)?;
        let parser = vt100_ctt::Parser::new(size.rows, size.cols, 0);

        Ok(Self {
            master,
            parser,
            child,
        })
    }

    /// Waits for output from the child, reads one chunk, and feeds it to the
    /// VT100 parser.
    ///
    /// Returns the number of bytes processed, or `Ok(0)` on EOF (the child
    /// closed the PTY).
    pub async fn process(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = self.master.readable().await?;
            match guard.try_io(|fd| fd.get_ref().read(&mut buf)) {
                Ok(Ok(0)) => return Ok(0),
                Ok(Ok(n)) => {
                    self.parser.process(&buf[..n]);
                    return Ok(n);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    /// Drains all immediately-available output without waiting for more,
    /// processing it through the VT100 parser.
    ///
    /// Returns the total number of bytes processed.
    pub fn process_available(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 4096];
        let mut total = 0;
        loop {
            match self.master.get_ref().read(&mut buf) {
                Ok(0) => return Ok(total),
                Ok(n) => {
                    self.parser.process(&buf[..n]);
                    total += n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(total),
                Err(e) => return Err(e),
            }
        }
    }

    /// Returns a reference to the current virtual terminal screen.
    pub fn screen(&self) -> &vt100_ctt::Screen {
        self.parser.screen()
    }

    /// Writes input bytes to the child process via the PTY master.
    ///
    /// Awaits writability on the master fd before writing.
    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.master.writable().await?;
            match guard.try_io(|fd| fd.get_ref().write(data)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Resizes the PTY to the given dimensions and updates the parser's
    /// screen size to match.
    pub fn resize(&mut self, size: WinSize) -> io::Result<()> {
        let fd = self.master.as_raw_fd();
        set_winsize(fd, size)?;
        self.parser.screen_mut().set_size(size.rows, size.cols);
        Ok(())
    }

    /// Checks whether the child has exited without blocking.
    ///
    /// Returns `Ok(Some(status))` if the child has exited, `Ok(None)` if it
    /// is still running.
    pub fn try_wait(&mut self) -> io::Result<Option<hakoniwa::ExitStatus>> {
        self.child.try_wait().map_err(io::Error::other)
    }

    /// Waits for the child process to exit, yielding to the tokio runtime
    /// between polls.
    ///
    /// Any remaining output is **not** automatically processed — call
    /// [`process_available`](Self::process_available) after this returns if
    /// you need the final screen state.
    pub async fn wait(&mut self) -> io::Result<hakoniwa::ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            tokio::task::yield_now().await;
        }
    }

    /// Sends `SIGKILL` to the child process.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill().map_err(io::Error::other)
    }

    /// Returns the OS process ID of the child.
    pub fn child_id(&self) -> u32 {
        self.child.id()
    }
}

/// Puts a file descriptor into non-blocking mode.
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_SIZE: WinSize = WinSize {
        rows: 24,
        cols: 80,
        xpixel: 0,
        ypixel: 0,
    };

    #[test]
    fn open_and_get_fds() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
        assert!(pty.master_fd() >= 0);
        assert!(pty.slave_fd() >= 0);
        assert_ne!(pty.master_fd(), pty.slave_fd());
    }

    #[test]
    fn open_sets_initial_size() {
        let size = WinSize {
            rows: 40,
            cols: 120,
            xpixel: 0,
            ypixel: 0,
        };
        let pty = Pty::open(size).expect("failed to open pty");

        let got = pty.get_size().expect("failed to get size");
        assert_eq!(got.rows, 40);
        assert_eq!(got.cols, 120);
    }

    #[test]
    fn dup_fd_produces_independent_fd() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
        let (master, _slave) = pty.into_fds();
        let duped = dup_fd(&master).expect("failed to dup fd");
        assert!(duped.as_raw_fd() >= 0);
        assert_ne!(master.as_raw_fd(), duped.as_raw_fd());
    }

    #[test]
    fn set_and_get_size() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");

        let size = WinSize {
            rows: 50,
            cols: 200,
            xpixel: 0,
            ypixel: 0,
        };
        pty.set_size(size).expect("failed to set size");

        let got = pty.get_size().expect("failed to get size");
        assert_eq!(got.rows, 50);
        assert_eq!(got.cols, 200);
    }
}
