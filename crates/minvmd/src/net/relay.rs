//! Linux tap provisioning and the async TAP↔gvproxy-socket relay (R1.5, R1.7).
//!
//! Ported from `minimald`'s `net::switch`: the gvproxy v0.8.9 switch attachment
//! is **not** an SCM_RIGHTS fd-pass (see
//! `docs/spikes/2026-06-21-gvproxy-attachment.md`). Instead `minvmd`:
//!
//! 1. opens a tap device in the host namespace ([`open_tap`]),
//! 2. moves the tap interface into the PTask's network namespace and configures
//!    its MAC/IP/route there (done by the caller via `ip`, per the spike's
//!    static-lease recipe), and
//! 3. runs an async relay ([`attach_to_switch`]) that bridges the host-side tap
//!    fd to gvproxy's control socket: a bare `POST /connect` HTTP upgrade, after
//!    which raw Ethernet frames flow in both directions framed with a 2-byte
//!    little-endian length prefix (the HyperKit protocol).
//!
//! This module is Linux-only: `/dev/net/tun` and `TUNSETIFF` are Linux APIs.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

use super::DEFAULT_MTU;

/// `ioctl` request number for `TUNSETIFF` (set the tap/tun interface a fd backs).
///
/// Typed as [`libc::Ioctl`], the per-target alias for `ioctl`'s request
/// argument — `c_ulong` on glibc, `c_int` on musl — so the constant resolves to
/// the width `libc::ioctl` expects on each target. The value `0x4004_54ca` fits
/// in an `i32`, so the musl narrowing is lossless.
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
/// `IFF_TAP`: the device is an Ethernet (layer-2) tap, not a layer-3 tun.
const IFF_TAP: libc::c_short = 0x0002;
/// `IFF_NO_PI`: do not prepend the 4-byte packet-info header to frames.
const IFF_NO_PI: libc::c_short = 0x1000;
/// `IFNAMSIZ`: kernel interface-name buffer length.
const IFNAMSIZ: usize = 16;

/// The HTTP request that upgrades a control-socket connection into a raw frame
/// stream. gvproxy hijacks the connection and writes no response.
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// `struct ifreq` reduced to the two fields `TUNSETIFF` reads, padded to the
/// kernel's `sizeof(struct ifreq)` (40 bytes on every LP64 Linux target) so the
/// kernel's `copy_from_user` never reads past the allocation.
#[repr(C)]
struct TunSetIfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Largest Ethernet frame the relay must buffer: MTU + 14-byte header + 4-byte
/// 802.1Q VLAN tag.
const fn max_frame() -> usize {
    DEFAULT_MTU as usize + 14 + 4
}

/// Opens a tap device named `name` in the calling process's network namespace.
///
/// The returned fd owns the tap: the interface exists as long as the fd is open.
/// The caller is expected to move the interface into the PTask's netns
/// (`ip link set <name> netns <pid>`) and configure its MAC/IP/route there
/// before relaying, while keeping this fd on the host side for the relay.
///
/// # Errors
///
/// Returns the underlying I/O error if `/dev/net/tun` cannot be opened or the
/// `TUNSETIFF` ioctl fails (commonly `EPERM` without `CAP_NET_ADMIN`).
pub fn open_tap(name: &str) -> io::Result<OwnedFd> {
    if name.len() >= IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tap name {name:?} is too long (max {} chars)", IFNAMSIZ - 1),
        ));
    }

    // SAFETY: open() with a valid NUL-terminated path and flags returns a new
    // fd or -1; we check for -1 below and take ownership of the fd otherwise.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // From here, `tap` owns the fd and closes it on drop / early return.
    // SAFETY: `fd` is a fresh, valid, owned fd just returned by open().
    let tap = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req = TunSetIfReq {
        name: [0; IFNAMSIZ],
        flags: IFF_TAP | IFF_NO_PI,
        _pad: [0; 22],
    };
    for (dst, src) in req.name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }

    // SAFETY: `fd` is open; `&mut req` points to a correctly-sized `ifreq`
    // (40 bytes) the kernel reads and writes for TUNSETIFF.
    let rc = unsafe {
        libc::ioctl(
            fd,
            TUNSETIFF,
            std::ptr::from_mut(&mut req).cast::<libc::c_void>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(tap)
}

/// Sets `O_NONBLOCK` on `fd` so the tap device can be epoll-driven via
/// [`AsyncFd`]. `std::fs::File` has no `set_nonblocking`, so this goes through
/// `fcntl` directly.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL on a valid, open fd reads/writes its status flags;
    // neither has any effect beyond that and cannot break memory safety.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A running switch relay. Dropping it aborts both relay directions, which
/// closes the gvproxy connection and detaches the PTask from the switch.
#[derive(Debug)]
#[must_use = "dropping the relay immediately detaches the PTask from the switch"]
pub struct SwitchRelay {
    tap_to_switch: JoinHandle<io::Result<()>>,
    switch_to_tap: JoinHandle<io::Result<()>>,
}

impl Drop for SwitchRelay {
    fn drop(&mut self) {
        self.tap_to_switch.abort();
        self.switch_to_tap.abort();
    }
}

/// Attaches `tap_fd` to the gvproxy switch listening on `api_sock` and starts
/// relaying frames between them.
///
/// Spawns two background tasks — tap→switch and switch→tap — and returns a
/// [`SwitchRelay`] handle whose lifetime keeps the attachment alive.
///
/// # Errors
///
/// Returns an error if the control socket cannot be connected, the connect
/// request cannot be written, or the tap fd cannot be put into non-blocking mode
/// for epoll-driven I/O.
pub async fn attach_to_switch(tap_fd: OwnedFd, api_sock: &Path) -> io::Result<SwitchRelay> {
    let mut sock = UnixStream::connect(api_sock).await?;
    sock.write_all(CONNECT_REQUEST).await?;

    // A tap character device does not support pread/pwrite, so `tokio::fs::File`
    // (which routes through the blocking pool via positional I/O) cannot drive
    // it. Use plain read/write in non-blocking mode with `AsyncFd` for epoll
    // readiness instead.
    // SAFETY: `tap_fd.into_raw_fd()` yields a valid, open, owned fd; `File` takes
    // exclusive ownership and closes it on drop.
    let tap_file = unsafe { std::fs::File::from_raw_fd(tap_fd.into_raw_fd()) };
    set_nonblocking(tap_file.as_raw_fd())?;
    let tap = Arc::new(AsyncFd::new(tap_file)?);

    let (sock_rx, sock_tx) = sock.into_split();
    let tap_to_switch = tokio::spawn(relay_tap_to_switch(Arc::clone(&tap), sock_tx));
    let switch_to_tap = tokio::spawn(relay_switch_to_tap(sock_rx, tap));
    Ok(SwitchRelay {
        tap_to_switch,
        switch_to_tap,
    })
}

/// tap → switch: read a raw Ethernet frame, prepend its 2-byte LE length, write
/// the framed packet to the control socket.
async fn relay_tap_to_switch<W>(tap: Arc<AsyncFd<std::fs::File>>, mut sock: W) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    // One byte larger than max_frame() so a full-size 1518-byte VLAN-tagged frame
    // gives n < buf.len() and is not mistaken for a truncated one.
    let mut buf = vec![0u8; max_frame() + 1];
    loop {
        let n = loop {
            let mut guard = tap.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };
        if n == 0 {
            return Ok(());
        }
        // A tap read is frame-atomic, but a frame larger than the buffer is
        // silently truncated to `buf.len()` by the kernel. Forwarding it would
        // emit corrupt bytes under a correct-looking length prefix, so drop it
        // and make the truncation observable instead of silently corrupting.
        if n == buf.len() {
            tracing::warn!(
                n,
                "tap frame filled the buffer; dropping possibly-truncated jumbo frame"
            );
            continue;
        }
        // One combined write keeps the length prefix and frame atomic even if
        // the socket closes between writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&buf[..n]);
        sock.write_all(&framed).await?;
    }
}

/// switch → tap: read a 2-byte LE length, then that many bytes of Ethernet
/// frame, write the frame to the tap device.
async fn relay_switch_to_tap<R>(mut sock: R, tap: Arc<AsyncFd<std::fs::File>>) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    let mut frame = vec![0u8; max_frame()];
    loop {
        match sock.read_exact(&mut len_buf).await {
            Ok(_) => {}
            // A clean close of the switch side ends the relay without error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u16::from_le_bytes(len_buf) as usize;
        if n == 0 {
            tracing::warn!("switch sent zero-length frame claim; skipping");
            continue;
        }
        // Trust nothing the control socket claims about length: a frame larger
        // than the MTU-derived maximum would overrun the tap and points at a
        // malformed or hostile peer, so reject it rather than size an allocation
        // to it.
        if n > frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switch frame length {n} exceeds max {}", frame.len()),
            ));
        }
        sock.read_exact(&mut frame[..n]).await?;
        loop {
            let mut guard = tap.writable().await?;
            // One non-blocking write per try_io call: write_all could issue
            // several syscalls and, on a partial write then EAGAIN, restart the
            // whole frame from byte 0 — re-emitting the already-written prefix. A
            // tap write is frame-atomic, so a single write delivers the whole
            // frame; a short count would mean a malformed write we surface.
            match guard.try_io(|inner| inner.get_ref().write(&frame[..n])) {
                Ok(result) => {
                    let written = result?;
                    if written != n {
                        tracing::warn!(written, n, "short tap write; frame may be truncated");
                    }
                    break;
                }
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_is_little_endian_length() {
        // The HyperKit framing the relay emits: a 2-byte LE length prefix.
        assert_eq!((1u16).to_le_bytes(), [0x01, 0x00]);
        assert_eq!((1514u16).to_le_bytes(), [0xea, 0x05]);
        assert_eq!(u16::from_le_bytes([0xea, 0x05]) as usize, 1514);
    }

    #[test]
    fn max_frame_covers_mtu_header_and_vlan_tag() {
        assert_eq!(max_frame(), 1500 + 14 + 4);
    }

    #[test]
    fn open_tap_rejects_an_overlong_name() {
        let err = open_tap("this-name-is-way-too-long").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
