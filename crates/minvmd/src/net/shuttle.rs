//! Host↔guest plumbing for the per-PTask gvproxy vsock shuttle.
//!
//! On DM1/DM3/DM4 (a libkrun VM) gvproxy runs on the **host**, supervised by
//! `minvmd`, and listens on a host UNIX socket (the `-listen` switch socket; see
//! [`crate::net::GvproxyConfig`]). An own-IP PTask lives inside the guest, where
//! its tap device is provisioned in the PTask's netns. The guest cannot connect
//! to the host UNIX socket directly, so each PTask runs a small **shuttle** that
//! relays its tap's raw Ethernet frames over an AF_VSOCK connection to the host.
//! The shuttle is *not* a second TCP/IP stack — it is a pure L2 frame relay (the
//! same HyperKit-framed protocol the DM2 native relay uses), so there is still
//! exactly one gVisor stack in the path (the host gvproxy).
//!
//! libkrun provides the host↔guest vsock bridge. `minvmd` registers
//! [`VSOCK_GVPROXY_SHUTTLE_PORT`] via `krun_add_vsock_port2(port, gate_sock,
//! listen = false)`: with `listen = false` the guest *initiates* the connection
//! (AF_VSOCK CID 2 / the host, the given port) and libkrun dials the host UNIX
//! socket named at registration, splicing the two. Since NET-081 that socket is
//! the **egress gate's** ([`crate::net::egress_gate`]), not the switch's own: the
//! gate decides every frame against the host-side table of published namespaces
//! ([`crate::box_registry`]) before relaying the admitted ones on to gvproxy, so
//! the per-box, source-addressed egress rules are applied outside the VM, where
//! nothing inside it can change them. The port is registered before the switch
//! runtime reports ready ([`crate::net::HostGvproxy`]), so a guest that boots
//! meets a listening gate, never an open switch.
//!
//! ```text
//!  guest                              libkrun                            host
//!  ┌──────────────┐  AF_VSOCK CID 2   ┌─────────┐  UNIX sock ┌─────────────┐  ┌─────────┐
//!  │ PTask tap fd │◀── shuttle ──────▶│ vsock   │◀──────────▶│ egress gate │─▶│ gvproxy │
//!  │ (in netns)   │   raw L2 frames   │ bridge  │  gate sock  │  (NET-081)  │  │ (NAT)   │
//!  └──────────────┘                   └─────────┘             └─────────────┘  └─────────┘
//! ```

use std::io;
use std::path::PathBuf;

/// vsock port the per-PTask guest shuttle connects to (AF_VSOCK CID 2 = host)
/// to reach the host-side egress gate in front of the gvproxy switch.
///
/// Distinct from [`crate::cmd::VSOCK_MARKER_PORT`] (7350, READY marker) and
/// [`crate::sock::VSOCK_BRIDGE_PORT`] (2222, minimald SSH bridge). libkrun
/// bridges this port to the gate's UNIX socket via
/// `krun_add_vsock_port2(.., listen = false)`. Shared with `minimald` via the
/// `switch` crate so the guest and host agree on the port.
pub use switch::VSOCK_GVPROXY_SHUTTLE_PORT;

/// Resolve the host UNIX socket path the gvproxy switch listens on.
///
/// Placed alongside the minimald bridge socket (same parent dir, already created
/// with mode 0700 by [`crate::sock::prepare_socket_dir`]). The gate
/// ([`crate::net::egress_gate`]) dials this path once per guest connection,
/// relaying on what its verdict admits.
///
/// # Errors
///
/// Propagates [`crate::sock::resolve_uds_path`]'s error.
pub fn resolve_switch_sock() -> io::Result<PathBuf> {
    Ok(switch_sock_beside(&crate::sock::resolve_uds_path()?))
}

/// Resolve the host UNIX socket path the egress gate (NET-081) listens on: the
/// socket libkrun's vsock bridge dials for the guest shuttle, beside the switch
/// socket [`resolve_switch_sock`] names.
///
/// The same parent dir as the bridge socket (mode 0700 from
/// [`crate::sock::prepare_socket_dir`], length-checked by
/// [`crate::sock::check_uds_path_len`] alongside the switch socket), and a name
/// distinct from every other socket the daemon owns — the composition
/// `gate_sock_beside(switch_sock_beside(uds))` keeps invariant.
///
/// # Errors
///
/// Propagates [`crate::sock::resolve_uds_path`]'s error.
pub fn resolve_gate_sock() -> io::Result<PathBuf> {
    Ok(gate_sock_beside(&crate::sock::resolve_uds_path()?))
}

/// The gvproxy switch socket path beside a given minimald bridge UDS (same
/// parent dir). Pure — derived only from `uds`, no env — so it is unit-testable
/// without mutating process-global state.
fn switch_sock_beside(uds: &std::path::Path) -> PathBuf {
    uds.parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("gvproxy-switch.sock")
}

/// The egress gate's socket path beside a given minimald bridge UDS (same
/// parent dir) — the socket [`crate::vm`] points the shuttle's vsock port at.
/// Pure — derived only from `uds`, no env — so it is unit-testable without
/// mutating process-global state, and pure on the switch socket too, so the
/// runtime can derive it from the switch socket it already holds
/// ([`crate::net::HostGvproxy`]).
pub(crate) fn gate_sock_beside(uds: &std::path::Path) -> PathBuf {
    uds.parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("gvproxy-gate.sock")
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
        // Pure helper, asserted directly — no env mutation, so this
        // can't race other tests that read the env (std::env is process-global).
        let uds = std::path::Path::new("/run/user/1000/minimal/bridge.sock");
        assert_eq!(
            switch_sock_beside(uds),
            PathBuf::from("/run/user/1000/minimal/gvproxy-switch.sock")
        );
    }

    #[test]
    fn gate_sock_sits_beside_the_bridge_socket() {
        let uds = std::path::Path::new("/run/user/1000/minimal/bridge.sock");
        assert_eq!(
            gate_sock_beside(uds),
            PathBuf::from("/run/user/1000/minimal/gvproxy-gate.sock")
        );
    }

    #[test]
    fn gate_sock_from_the_switch_sock_is_the_gate_sock() {
        // The runtime derives the gate socket from the switch socket it
        // already holds; that composition must land on the same path
        // resolving it from the bridge socket does.
        let uds = std::path::Path::new("/run/user/1000/minimal/bridge.sock");
        assert_eq!(
            gate_sock_beside(&switch_sock_beside(uds)),
            gate_sock_beside(uds),
            "deriving the gate socket from the switch socket keeps it beside the bridge"
        );
    }
}
