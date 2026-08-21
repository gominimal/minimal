//! The terminal a bundle's producer was invoked on: whether each standard
//! stream is a tty, and what that terminal says about itself.
//!
//! Sessions are interactive by design, so "the TUI is garbled", "lines wrap
//! wrong", "resize does nothing" (#950) are all claims about a terminal no
//! bundle described. Two facts answer most of them. Whether the streams are
//! ttys separates "ran under a pipe, a script, or CI" from a real terminal —
//! the precondition `min attach` and the interactive prompts gate on, so a
//! refused attach or a prompt nobody saw is explained by this field alone.
//! The window size explains the rendering: a zero or stale `TIOCGWINSZ` is
//! the classic wrong-wrapping cause, and a size the user's window plainly is
//! not says the resize never reached the pty.
//!
//! The caveat the capture cannot escape is that it describes the terminal the
//! *bundle* ran on, which is the terminal that rendered wrong only when the
//! user reports from the same window. Recording it beside the other host
//! facts is what makes that judgeable instead of unasked.

use std::ffi::CStr;
use std::os::fd::RawFd;

use serde::Serialize;

/// The three standard streams' terminal facts. Best-effort like every probe:
/// what cannot be read is `None`, never an error.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct TerminalInfo {
    pub stdin: StreamInfo,
    pub stdout: StreamInfo,
    pub stderr: StreamInfo,
}

/// One stream's terminal facts. `device` and `size` are `None` whenever the
/// stream is not a tty: there is nothing to ask a pipe.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct StreamInfo {
    pub tty: bool,
    /// The tty device behind the stream (`/dev/ttys004`, `/dev/pts/3`), which
    /// tells a console apart from a pty — and tells two streams pointing at
    /// different terminals apart from the usual case where all three share
    /// one.
    pub device: Option<String>,
    pub size: Option<WinSize>,
}

/// A terminal's `TIOCGWINSZ` dimensions, reported exactly as the kernel gives
/// them. Zeroes are kept rather than folded into `None`: "the terminal claims
/// it has no rows" is the finding, not a failed read.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

/// Gathers [`TerminalInfo`] for stdin, stdout, and stderr.
pub fn terminal_info() -> TerminalInfo {
    TerminalInfo {
        stdin: stream_info(libc::STDIN_FILENO),
        stdout: stream_info(libc::STDOUT_FILENO),
        stderr: stream_info(libc::STDERR_FILENO),
    }
}

/// Probes one descriptor. A closed or non-tty fd answers `tty: false` and
/// nothing else — the probe never fails.
fn stream_info(fd: RawFd) -> StreamInfo {
    // SAFETY: isatty only inspects the descriptor; an invalid one is EBADF.
    let tty = unsafe { libc::isatty(fd) } == 1;
    StreamInfo {
        tty,
        device: tty.then(|| device_name(fd)).flatten(),
        size: tty.then(|| win_size(fd)).flatten(),
    }
}

/// The tty device path behind `fd`, `None` when it cannot be resolved.
fn device_name(fd: RawFd) -> Option<String> {
    // SAFETY: ttyname returns a pointer into a static buffer valid until the
    // next ttyname call on this thread; it is copied into an owned String
    // before this thread can make another.
    let name = unsafe { libc::ttyname(fd) };
    if name.is_null() {
        return None;
    }
    // SAFETY: a non-null ttyname result is a NUL-terminated C string.
    unsafe { CStr::from_ptr(name) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// The window size `fd`'s terminal reports, `None` when the ioctl fails.
fn win_size(fd: RawFd) -> Option<WinSize> {
    // SAFETY: an all-zero winsize is a valid value to hand the ioctl, which
    // overwrites it wholesale; the fields are only read when it succeeded.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `ws` is a valid winsize and TIOCGWINSZ writes exactly one.
    (unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0).then_some(WinSize {
        rows: ws.ws_row,
        cols: ws.ws_col,
        xpixel: ws.ws_xpixel,
        ypixel: ws.ws_ypixel,
    })
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    use super::*;

    /// A pty pair sized `rows`x`cols`, so the probe can be pointed at a real
    /// terminal instead of whatever the test runner left on fd 0.
    fn open_pty(rows: u16, cols: u16) -> (OwnedFd, OwnedFd) {
        let (mut master, mut slave): (RawFd, RawFd) = (-1, -1);
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: valid out-pointers for both fds and the initial size, NULL
        // for the optional name/termios parameters.
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &ws,
            )
        };
        assert_eq!(ret, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: openpty succeeded, so both fds are open and owned by nobody.
        unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
    }

    #[test]
    fn a_tty_reports_its_device_and_the_size_it_was_opened_with() {
        let (_master, slave) = open_pty(24, 80);
        let info = stream_info(slave.as_raw_fd());

        assert!(info.tty);
        let size = info.size.expect("a pty answers TIOCGWINSZ");
        assert_eq!((size.rows, size.cols), (24, 80));
        assert!(
            info.device.is_some_and(|d| d.starts_with("/dev/")),
            "a pty slave names its device"
        );
    }

    #[test]
    fn a_pipe_is_not_a_tty_and_has_nothing_to_report() {
        let (reader, _writer) = std::io::pipe().expect("pipe");
        let info = stream_info(reader.as_raw_fd());

        assert!(!info.tty);
        assert!(info.device.is_none() && info.size.is_none());
    }

    #[test]
    fn every_standard_stream_is_described() {
        let json = serde_json_lenient::to_value(terminal_info()).unwrap();
        for stream in ["stdin", "stdout", "stderr"] {
            assert!(json[stream]["tty"].is_boolean(), "{stream} unprobed");
        }
    }
}
