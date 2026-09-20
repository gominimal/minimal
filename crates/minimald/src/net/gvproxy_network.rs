//! The own-IP switch attach: takes a PTask's tap descriptor, relays its frames
//! to the already-running gvproxy switch, applies static ingress (R2.3) and
//! registers the PTask's `*.min.internal` name (R3.1).
//!
//! Who made the tap is `net::provider`'s business; this module sees only the
//! descriptor and the transport that carries its frames — a unix socket on
//! DM2, vsock on DM1/3/4 — and both feed the same frame relay.
//!
//! The gvproxy **process** is owned by the daemon-scoped [`SwitchClient`] (DM2)
//! or the `minvmd` host supervisor (DM1/3/4); this only wires an
//! already-running switch into a sandbox's namespace (spec R1.4/R1.5).

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::Arc;

use sandbox2::NetGuard;
use tokio::sync::Mutex;

use crate::net::policy::{BoxZone, ControlChannel, ExposedMapping};
use crate::net::switch::SwitchRelay;
use crate::net::{SwitchClient, SwitchSubnet};

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
    /// The switch's in-guest box zone, and this box's name in it: withdrawn on
    /// teardown so a sibling's verdict and the zone dump name live boxes only
    /// (NET-072, NET-073).
    box_zone: Arc<BoxZone>,
    session_name: String,
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
            // Withdrawn before the detach: from here the box answers nothing,
            // so nothing must resolve its name to a lease it no longer holds.
            self.box_zone.withdraw(&self.session_name);
            if let Err(e) = self.switch.lock().await.detach().await {
                tracing::warn!(error = %e, "detaching OwnIp PTask from switch on session end");
            }
            // `_relay` drops here, aborting the relay tasks.
        })
    }
}

/// Completes an own-IP attach on any deployment model: relay `tap_fd` to the
/// running gvproxy over `control` under the box's `egress` gate, then apply
/// any static ingress.
///
/// [`ControlChannel::Unix`] reaches the gvproxy the daemon spawned (DM2),
/// [`ControlChannel::Vsock`] the one `minvmd` owns on the host (DM1/3/4).
///
/// The lease was already allocated and gvproxy already ensured-running by the
/// provider's plan, so this only does the post-spawn relay + ingress. A failure
/// here just propagates: the release of that lease stays with the launch
/// (`sandbox2::PlannedLaunch`), and detaching as well would double-decrement
/// gvproxy's attach count.
pub(crate) async fn complete_own_ip_attach(attach: OwnIpAttach<'_>) -> io::Result<OwnIpGuard> {
    let OwnIpAttach {
        switch,
        tap_fd,
        control,
        lease_ip,
        subnet,
        session_name,
        ingress,
        egress,
    } = attach;
    let gate = crate::net::switch::IngressGate::for_session(lease_ip.to_string(), ingress, subnet)
        .with_egress(egress);
    let relay = match &control {
        ControlChannel::Unix(sock) => {
            crate::net::switch::attach_to_switch(tap_fd, sock, Some(gate)).await?
        }
        ControlChannel::Vsock { cid, port } => {
            crate::net::switch::attach_to_switch_vsock(tap_fd, *cid, *port, Some(gate)).await?
        }
    };
    finish_own_ip_attach(FinishAttach {
        switch,
        relay,
        control,
        lease_ip,
        subnet,
        session_name,
        ingress,
    })
    .await
}

/// What [`complete_own_ip_attach`] needs, as one argument: the tap to relay,
/// the control channel to relay it over, and the addressing and policy (both
/// directions) of the PTask it belongs to.
pub(crate) struct OwnIpAttach<'a> {
    pub(crate) switch: &'a Arc<Mutex<SwitchClient>>,
    pub(crate) tap_fd: OwnedFd,
    pub(crate) control: ControlChannel,
    pub(crate) lease_ip: Ipv4Addr,
    pub(crate) subnet: SwitchSubnet,
    pub(crate) session_name: &'a str,
    pub(crate) ingress: Option<&'a sessions::IngressPolicy>,
    pub(crate) egress: Arc<crate::net::switch::EgressGate>,
}

/// What [`finish_own_ip_attach`] needs, as one argument: the just-started relay
/// plus the addressing and policy of the PTask it belongs to.
struct FinishAttach<'a> {
    switch: &'a Arc<Mutex<SwitchClient>>,
    relay: SwitchRelay,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    subnet: SwitchSubnet,
    session_name: &'a str,
    ingress: Option<&'a sessions::IngressPolicy>,
}

/// Tail of the own-IP attach: apply static ingress forwards (R2.3) over
/// `control`, then build the [`OwnIpGuard`]. On an ingress failure the relay is
/// dropped (closing the switch-side connection); the attach-count rollback is
/// left to the launch, so the refcount is never double-decremented.
async fn finish_own_ip_attach(attach: FinishAttach<'_>) -> io::Result<OwnIpGuard> {
    let FinishAttach {
        switch,
        relay,
        control,
        lease_ip,
        subnet,
        session_name,
        ingress,
    } = attach;
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

    // Register this PTask's `<name>.min.internal` → its current lease so
    // peer sessions can resolve it (finding #3 / UC6). Done for *every* own-IP
    // PTask, even with no ingress: resolvable names are how peers find each other,
    // and the ingress gate independently governs reachability. Best-effort — a DNS
    // hiccup must not fail an otherwise-working attach.
    if let Err(e) = crate::net::policy::register_dns_name(&control, session_name, lease_ip).await {
        tracing::warn!(error = %e, session = session_name, "registering *.min.internal name on gvproxy");
    }

    // The daemon's own record of that registration, with the ports this box's
    // ingress declares: what a sibling's egress leg reads to name the box behind
    // an address and the verdict its rules give a port (NET-072, NET-073), and
    // what the zone dump shows as the in-guest zone. Recorded whether or not the
    // post above reached gvproxy, because the box is on the switch either way —
    // a name that failed to register resolves nowhere, which the warning says.
    let box_zone = switch.lock().await.box_zone();
    box_zone.register(session_name, lease_ip, ingress);

    // And `host.min.internal` → the switch's host-gateway address, so this box
    // resolves the host it runs on (NET-003). Posted on every attach rather than
    // once per process: the switch stops with its last PTask and takes its zones
    // with it, and the record never varies. Best-effort for the same reason as
    // the name above.
    if let Err(e) = crate::net::policy::register_host_name(&control, subnet).await {
        tracing::warn!(
            error = %e,
            name = crate::net::policy::HOST_HOSTNAME,
            "registering the host's name on gvproxy"
        );
    }

    Ok(OwnIpGuard {
        _relay: relay,
        switch: Arc::clone(switch),
        control,
        exposed,
        box_zone,
        session_name: session_name.to_string(),
    })
}
