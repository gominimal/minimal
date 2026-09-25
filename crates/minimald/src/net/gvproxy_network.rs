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

use std::collections::BTreeMap;
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

/// Completes an own-IP attach on any deployment model: relay `tap_fd` to the
/// running gvproxy over `control`, then apply any static ingress.
///
/// [`ControlChannel::Unix`] reaches the gvproxy the daemon spawned (DM2),
/// [`ControlChannel::Vsock`] the one `minvmd` owns on the host (DM1/3/4).
///
/// The lease was already allocated and gvproxy already ensured-running by the
/// provider's plan, so this only does the post-spawn relay + ingress. A failure
/// here just propagates: the release of that lease stays with the launch
/// (`sandbox2::PlannedLaunch`), and detaching as well would double-decrement
/// gvproxy's attach count.
pub(crate) async fn complete_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    tap_fd: OwnedFd,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    session_name: &str,
    ingress: Option<&sessions::IngressPolicy>,
    own_address: Option<&crate::net::provider::OwnAddressReporter>,
) -> io::Result<OwnIpGuard> {
    let gate = crate::net::switch::IngressGate::for_session(lease_ip.to_string(), ingress);
    // The relay's deprecation notice (NET-004) derives the old literal from
    // the subnet of the switch it attaches to, so a custom-subnet switch is
    // watched at its own host alias.
    let subnet = switch.lock().await.subnet();
    let relay = match &control {
        ControlChannel::Unix(sock) => {
            crate::net::switch::attach_to_switch(tap_fd, sock, Some(gate), subnet).await?
        }
        ControlChannel::Vsock { cid, port } => {
            crate::net::switch::attach_to_switch_vsock(tap_fd, *cid, *port, Some(gate), subnet)
                .await?
        }
    };
    finish_own_ip_attach(
        switch,
        relay,
        control,
        lease_ip,
        session_name,
        ingress,
        own_address,
    )
    .await
}

/// Tail of the own-IP attach: apply static ingress forwards (R2.3) over
/// `control`, then build the [`OwnIpGuard`]. On an ingress failure the relay is
/// dropped (closing the switch-side connection); the attach-count rollback is
/// left to the launch, so the refcount is never double-decremented.
async fn finish_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    relay: SwitchRelay,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    session_name: &str,
    ingress: Option<&sessions::IngressPolicy>,
    own_address: Option<&crate::net::provider::OwnAddressReporter>,
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

    // Register this PTask's two-label name — with the deprecated three-label
    // form beside it (NET-002) — pointing at its current lease, so peer
    // sessions can resolve it (finding #3 / UC6). Done for *every* own-IP
    // PTask, even with no ingress: resolvable names are how peers find each other,
    // and the ingress gate independently governs reachability. The host label
    // is this daemon instance's own id — carried by the switch, same as the
    // proxy's registry — so a second daemon on the host registers beside the
    // first's names instead of over them (NET-027). Best-effort — a DNS
    // hiccup must not fail an otherwise-working attach.
    let host_id = switch.lock().await.host_id().to_owned();
    if let Err(e) =
        crate::net::policy::register_dns_name(&control, &host_id, session_name, lease_ip).await
    {
        tracing::warn!(error = %e, session = session_name, "registering *.min.internal name on gvproxy");
    }

    // Report the lease to the proxy's routing table, so the box's
    // `<name>.min.internal` routes from here on (NET-001). Done after the
    // forwards: the route must not lead to a box the switch cannot yet reach.
    // A launch without a reporter — a task, which owns no proxy route of its
    // own — skips this.
    if let Some(own_address) = own_address {
        let ports = ingress.map_or_else(BTreeMap::new, |ingress| {
            ingress
                .port_mappings
                .iter()
                .map(|mapping| (mapping.external_port, mapping.internal_port))
                .collect()
        });
        own_address.report(session_name, lease_ip, ports);
    }

    Ok(OwnIpGuard {
        _relay: relay,
        switch: Arc::clone(switch),
        control,
        exposed,
    })
}
