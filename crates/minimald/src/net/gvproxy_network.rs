//! The own-IP switch attach: one mechanism, one rollback owner.
//!
//! Every own-IP PTask gets its tap the same way on every deployment model — the
//! sandbox layer builds it *inside* the PTask's own user+network namespace
//! (rootless, via hakoniwa's RustSlirp) and hands the descriptor out through
//! `Child.rustslirp_tapfd`. This module takes that descriptor, relays its frames
//! to the already-running gvproxy switch, applies static ingress (R2.3) and
//! registers the PTask's `*.min.internal` name (R3.1).
//!
//! That is what 03-spec-networking R1.5 describes: "create a network namespace,
//! provision a virtual tap interface inside it, and pass the tap file descriptor
//! to the running gvproxy". The deployment model chooses only the transport that
//! carries the descriptor — a unix socket on DM2, vsock on DM1/3/4 — and both
//! transports feed the same frame relay, so the frames are identical.
//!
//! The gvproxy **process** is still owned by the daemon-scoped [`SwitchClient`]
//! (DM2) or the `minvmd` host supervisor (DM1/3/4); this only wires an
//! already-running switch into a sandbox's namespace (spec R1.4/R1.5).

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::Arc;

use sandbox2::NetGuard;
use tokio::sync::Mutex;

use crate::net::SwitchClient;
use crate::net::policy::{ControlChannel, ExposedMapping};
use crate::net::switch::SwitchRelay;

/// The own-IP attachment guard. Returned by [`complete_own_ip_attach`] and torn
/// down explicitly via [`NetGuard::teardown`] at the end of the sandbox's life.
///
/// Teardown removes this PTask's ingress forwards then detaches it from the
/// switch (decrementing the switch refcount, which stops gvproxy once the last
/// `OwnIp` PTask leaves). It is **explicit** — driven on a live runtime by the
/// owner — rather than a `Drop` schedule, so it cannot be lost to a stopped
/// runtime. Dropping the held [`SwitchRelay`] aborts the frame relay either way.
pub(crate) struct OwnIpGuard {
    /// Held for its `Drop`, which aborts the relay tasks; never read.
    _relay: SwitchRelay,
    /// The shared switch, locked on teardown to detach this PTask.
    switch: Arc<Mutex<SwitchClient>>,
    /// gvproxy's control channel (local socket on DM2, host vsock on DM1/3/4),
    /// used on teardown to remove this PTask's ingress forwards before detaching.
    control: ControlChannel,
    /// The static ingress forwards exposed for this PTask (R2.3), removed on
    /// teardown. Empty when no ingress was configured.
    exposed: Vec<ExposedMapping>,
}

impl NetGuard for OwnIpGuard {
    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            // Remove ingress forwards (R2.3 teardown) before detaching: detach
            // may stop gvproxy once the last PTask leaves, so the unexpose must
            // reach a still-running switch first.
            if !self.exposed.is_empty() {
                crate::net::policy::remove_ingress(&self.control, &self.exposed).await;
            }
            if let Err(e) = self.switch.lock().await.detach().await {
                tracing::warn!(error = %e, "detaching OwnIp PTask from switch on session end");
            }
            // `_relay` drops here, aborting the relay tasks.
        })
    }
}

/// Completes an own-IP attach on any deployment model: relay the in-namespace
/// tap fd — created rootless by hakoniwa's RustSlirp inside the PTask's own
/// user+network namespace, and handed out via `Child.rustslirp_tapfd` — to the
/// running gvproxy over `control`, then apply any static ingress.
///
/// `control` is the only thing the deployment model decides:
/// [`ControlChannel::Unix`] reaches the gvproxy the daemon spawned (DM2),
/// [`ControlChannel::Vsock`] reaches the one `minvmd` owns on the host
/// (DM1/3/4). Both end in the same frame relay, so the wire format is the same;
/// see [`crate::net::switch::attach_to_switch`] and
/// [`crate::net::switch::attach_to_switch_vsock`].
///
/// The lease was already allocated and gvproxy already ensured-running by the
/// pre-spawn `SwitchClient::attach()` — the IP has to be known before spawn,
/// because the sandbox layer assigns it to the tap as it builds it — so this
/// only does the post-spawn relay + ingress. Rollback of that pre-spawn attach
/// belongs to the session host's launch guard, which also covers a cancelled
/// launch, so a failure here just propagates; detaching would double-decrement
/// gvproxy's attach count.
pub(crate) async fn complete_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    tap_fd: OwnedFd,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    session_name: &str,
    ingress: Option<&sessions::IngressPolicy>,
) -> io::Result<OwnIpGuard> {
    let gate = crate::net::switch::IngressGate::for_session(lease_ip.to_string(), ingress);
    let relay = match &control {
        ControlChannel::Unix(sock) => {
            crate::net::switch::attach_to_switch(tap_fd, sock, Some(gate)).await?
        }
        ControlChannel::Vsock { cid, port } => {
            crate::net::switch::attach_to_switch_vsock(tap_fd, *cid, *port, Some(gate)).await?
        }
    };
    finish_own_ip_attach(switch, relay, control, lease_ip, session_name, ingress).await
}

/// Tail of the own-IP attach: apply static ingress forwards (R2.3) over
/// `control`, then build the [`OwnIpGuard`]. On an ingress failure the relay is
/// dropped (closing the switch-side connection); the attach-count rollback is
/// left to the session host's launch guard, so the refcount is never
/// double-decremented.
async fn finish_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    relay: SwitchRelay,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    session_name: &str,
    ingress: Option<&sessions::IngressPolicy>,
) -> io::Result<OwnIpGuard> {
    let exposed = match ingress {
        Some(ingress) if !ingress.port_mappings.is_empty() => {
            match crate::net::policy::apply_ingress(&control, lease_ip, ingress).await {
                Ok(exposed) => exposed,
                Err(e) => {
                    drop(relay);
                    return Err(e);
                }
            }
        }
        _ => Vec::new(),
    };

    // Register this PTask's `<name>.<host-id>.min.internal` → its current lease so
    // peer sessions can resolve it (finding #3 / UC6). Done for *every* own-IP
    // PTask, even with no ingress: resolvable names are how peers find each other,
    // and the ingress gate independently governs reachability. Best-effort — a DNS
    // hiccup must not fail an otherwise-working attach.
    if let Err(e) = crate::net::policy::register_dns_name(
        &control,
        crate::net::dns::DEFAULT_HOST_ID,
        session_name,
        lease_ip,
    )
    .await
    {
        tracing::warn!(error = %e, session = session_name, "registering *.min.internal name on gvproxy");
    }

    Ok(OwnIpGuard {
        _relay: relay,
        switch: Arc::clone(switch),
        control,
        exposed,
    })
}
