//! Host↔guest plumbing for the per-PTask gvproxy vsock shuttle (issue #572).
//!
//! On DM1/DM3/DM4 (a libkrun VM) gvproxy runs on the **host**, supervised by
//! `minvmd`, and listens on a host UNIX socket (the `-listen` switch socket; see
//! [`crate::net::GvproxyConfig`]). An own-IP PTask lives inside the guest, where
//! its tap device is provisioned in the PTask's netns. The guest cannot connect
//! to the host UNIX socket directly, so each PTask runs a small **shuttle** that
//! relays its tap's raw Ethernet frames over an AF_VSOCK connection to the host
//! gvproxy. The shuttle is *not* a second TCP/IP stack — it is a pure L2 frame
//! relay (the same HyperKit-framed protocol the DM2 native relay uses), so there
//! is still exactly one gVisor stack in the path (the host gvproxy).
//!
//! libkrun provides the host↔guest vsock bridge. `minvmd` registers
//! [`VSOCK_GVPROXY_SHUTTLE_PORT`] via
//! `krun_add_vsock_port2(port, switch_sock, listen = false)`: with `listen =
//! false` the guest *initiates* the connection (AF_VSOCK CID 2 / the host, the
//! given port) and libkrun dials the host UNIX socket that gvproxy is listening
//! on, splicing the two. This is the mirror image of the READY-marker port
//! ([`crate::cmd::VSOCK_MARKER_PORT`]), which also uses `listen = false` for a
//! guest-initiated connection.
//!
//! ```text
//!  guest                              libkrun                 host
//!  ┌──────────────┐  AF_VSOCK CID 2   ┌─────────┐  UNIX sock  ┌─────────┐
//!  │ PTask tap fd │◀── shuttle ──────▶│ vsock   │◀───────────▶│ gvproxy │
//!  │ (in netns)   │   raw L2 frames   │ bridge  │  switch sock│ (NAT)   │
//!  └──────────────┘                   └─────────┘             └─────────┘
//! ```

use std::io;
use std::path::PathBuf;

/// vsock port the per-PTask guest shuttle connects to (AF_VSOCK CID 2 = host)
/// to reach the host gvproxy switch (issue #572).
///
/// Distinct from [`crate::cmd::VSOCK_MARKER_PORT`] (7350, READY marker) and
/// [`crate::sock::VSOCK_BRIDGE_PORT`] (2222, minimald SSH bridge). libkrun
/// bridges this port to the host gvproxy `-listen` UNIX socket via
/// `krun_add_vsock_port2(.., listen = false)`.
pub const VSOCK_GVPROXY_SHUTTLE_PORT: u32 = 1024;

/// Resolve the host UNIX socket path the gvproxy switch listens on.
///
/// Placed alongside the minimald bridge socket (same parent dir, already created
/// with mode 0700 by [`crate::sock::prepare_socket_dir`]). libkrun's vsock
/// bridge dials this path when the guest shuttle connects to
/// [`VSOCK_GVPROXY_SHUTTLE_PORT`].
///
/// # Errors
///
/// Propagates [`crate::sock::resolve_uds_path`]'s error when neither
/// `XDG_RUNTIME_DIR` nor a home directory can be determined.
pub fn resolve_switch_sock() -> io::Result<PathBuf> {
    let uds = crate::sock::resolve_uds_path()?;
    Ok(uds
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("gvproxy-switch.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuttle_port_is_distinct_from_other_vsock_ports() {
        assert_ne!(VSOCK_GVPROXY_SHUTTLE_PORT, crate::cmd::VSOCK_MARKER_PORT);
        assert_ne!(VSOCK_GVPROXY_SHUTTLE_PORT, crate::sock::VSOCK_BRIDGE_PORT);
    }

    #[test]
    fn switch_sock_sits_beside_the_bridge_socket() {
        // Pin XDG_RUNTIME_DIR so the path is deterministic; the switch socket
        // shares the minimald bridge's parent dir.
        // SAFETY: single-threaded test; restored before returning.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000") };
        let sock = resolve_switch_sock().unwrap();
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        assert_eq!(
            sock,
            PathBuf::from("/run/user/1000/minimal/gvproxy-switch.sock")
        );
    }
}
