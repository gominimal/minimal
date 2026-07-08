//! `GvproxyNetwork`: the own-IP [`sandbox2::Network`] implementation.
//!
//! This moves the per-PTask switch wiring (lease, tap open, move-into-netns,
//! frame relay, static ingress) out of the minimald session host and behind the
//! `sandbox2` [`Network`] abstraction, so every sandbox consumer — interactive
//! sessions and autospawned `min run` tasks alike — gets own-IP networking the
//! same way (#581 review).
//!
//! The gvproxy **process** is still owned by the daemon-scoped [`SwitchClient`]
//! (DM2) or the `minvmd` host supervisor (DM1/3/4); this only wires an
//! already-running switch into a sandbox's freshly-unshared network namespace
//! (spec R1.4/R1.5). `sandbox2` decides the netns isolation and surfaces the
//! launched process's PID; this code does the `minimald`-side attach against it.

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use sandbox2::{AttachFuture, NetGuard, Network, NetworkError};
use sessions::SessionId;
use tokio::sync::Mutex;

use crate::net::SwitchClient;
use crate::net::dns::HostnameRegistry;
use crate::net::policy::{ControlChannel, ExposedMapping};
use crate::net::switch::SwitchRelay;

/// An own-IP network: attaches a sandbox's network namespace to the per-host
/// gvproxy switch and applies its static ingress forwards (R1.5/R2.3).
pub(crate) struct GvproxyNetwork {
    /// The shared per-host switch (the daemon-scoped process owner / refcounter).
    switch: Arc<Mutex<SwitchClient>>,
    /// Static ingress port mappings to apply once attached; `None`/empty for none.
    ingress: Option<sessions::IngressPolicy>,
    /// The daemon's shared PTask hostname registry: the live switch lease is
    /// published here at attach and reverted at teardown (G-N9).
    hostnames: Arc<RwLock<HostnameRegistry>>,
    /// The session whose lease this attach publishes.
    session_id: SessionId,
}

impl GvproxyNetwork {
    pub(crate) fn new(
        switch: Arc<Mutex<SwitchClient>>,
        ingress: Option<sessions::IngressPolicy>,
        hostnames: Arc<RwLock<HostnameRegistry>>,
        session_id: SessionId,
    ) -> Self {
        Self {
            switch,
            ingress,
            hostnames,
            session_id,
        }
    }
}

impl std::fmt::Debug for GvproxyNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GvproxyNetwork")
            .field("has_ingress", &self.ingress.is_some())
            .finish_non_exhaustive()
    }
}

impl Network for GvproxyNetwork {
    fn isolate_netns(&self) -> bool {
        true
    }

    fn attach(&self, netns_pid: u32) -> AttachFuture<'_> {
        Box::pin(async move {
            let guard = attach_own_ip(
                &self.switch,
                netns_pid,
                self.ingress.as_ref(),
                Arc::clone(&self.hostnames),
                self.session_id,
            )
            .await
            .map_err(NetworkError::new)?;
            Ok(Box::new(guard) as Box<dyn NetGuard>)
        })
    }
}

/// The own-IP attachment guard. Returned by [`GvproxyNetwork::attach`] and torn
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
    /// This PTask's switch lease. The guard is the authoritative owner of the
    /// ephemeral lease (G-N9); it is logged at teardown for correlation.
    lease: Ipv4Addr,
    /// The shared hostname registry into which this PTask's lease was published
    /// (VM path only); reverted to the loopback placeholder on teardown.
    hostnames: Arc<RwLock<HostnameRegistry>>,
    /// The session key under which the lease was published/reverted.
    session_id: SessionId,
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
            // Revert the published lease BEFORE the switch detach, so no in-VM
            // consumer can resolve the hostname to a tearing-down lease. Only the
            // VM path (`Vsock`) publishes a lease; DM2 (`Unix`) keeps the
            // loopback placeholder untouched (its shared-netns forwarder still
            // serves host-direct access). A revert with nothing published is a
            // harmless no-op.
            if let ControlChannel::Vsock { .. } = &self.control {
                tracing::debug!(
                    session_id = %self.session_id,
                    lease = %self.lease,
                    "reverting OwnIp PTask lease on teardown"
                );
                self.hostnames
                    .write()
                    .expect("hostname registry lock poisoned")
                    .clear_own_ip_lease(self.session_id);
            }
            if let Err(e) = self.switch.lock().await.detach().await {
                tracing::warn!(error = %e, "detaching OwnIp PTask from switch on session end");
            }
            // `_relay` drops here, aborting the relay tasks.
        })
    }
}

/// Attaches an `OwnIp` PTask to the host-owned gvproxy switch over the vsock
/// shuttle — the **DM1/3/4 (`HostShuttle`) path**, used inside a libkrun VM where
/// minimald is root: allocate a lease and bump the attach count, open a host-side
/// tap, move it into the PTask's network namespace with `ip`/`nsenter` and
/// configure its switch address there, then relay its frames to the host gvproxy
/// and apply any static ingress.
///
/// The native DM2 (`LocalSpawn`) path does **not** go through here: it is rootless
/// (hakoniwa's RustSlirp builds the tap in-namespace) and is driven from the
/// session host via [`complete_local_own_ip_attach`].
async fn attach_own_ip(
    switch: &Arc<Mutex<SwitchClient>>,
    netns_pid: u32,
    ingress: Option<&sessions::IngressPolicy>,
    hostnames: Arc<RwLock<HostnameRegistry>>,
    session_id: SessionId,
) -> io::Result<OwnIpGuard> {
    use crate::net::SwitchTransport;
    use crate::net::switch::{attach_to_switch_vsock, move_tap_into_netns, open_tap};

    // Allocate a lease and bump the attach count, snapshotting the subnet and
    // transport under one lock; the slow tap/relay work runs unlocked so
    // concurrent attaches don't serialize on the namespace plumbing.
    let (lease, subnet, transport) = {
        let mut s = switch.lock().await;
        let attach = s
            .attach()
            .await
            .map_err(|e| io::Error::other(format!("attaching OwnIp PTask to switch: {e}")))?;
        (attach.lease, s.subnet(), s.transport())
    };

    // This function is the HostShuttle (in-VM) path; the native LocalSpawn path
    // is handled rootless in the session host. Roll the attach back if a
    // misconfigured caller routes a LocalSpawn switch here.
    let SwitchTransport::HostShuttle { cid, port } = transport else {
        let _ = switch.lock().await.detach().await;
        return Err(io::Error::other(
            "attach_own_ip is the HostShuttle path; LocalSpawn own-IP is handled in the session host",
        ));
    };

    // A locally-administered tap name unique within the switch /16 (its low two
    // octets distinguish every PTask address) and within the 15-char `IFNAMSIZ`
    // limit (`mtapNNN_NNN` is at most 11 chars).
    let o = lease.ip.octets();
    let tap = format!("mtap{}_{}", o[2], o[3]);

    // On any failure after the switch attach succeeded, roll the attach back so
    // gvproxy's refcount stays accurate (a leaked count would keep it running).
    let relay = match async {
        let tap_fd = open_tap(&tap)?;
        move_tap_into_netns(&tap, netns_pid, lease, subnet).await?;
        // Relay the tap's raw frames over vsock to the host gvproxy `minvmd` owns.
        attach_to_switch_vsock(tap_fd, cid, port).await
    }
    .await
    {
        Ok(relay) => relay,
        Err(e) => {
            let _ = switch.lock().await.detach().await;
            return Err(e);
        }
    };

    // The forwarder API reaches the host gvproxy over the same vsock shuttle port
    // (the `-listen` socket serves `/services/forwarder/*` alongside `/connect`).
    // This path owns its own rollback (no session-host guard), so detach if the
    // ingress-applying tail fails.
    let control = ControlChannel::Vsock { cid, port };
    match finish_own_ip_attach(
        switch, relay, control, lease.ip, ingress, hostnames, session_id,
    )
    .await
    {
        Ok(guard) => Ok(guard),
        Err(e) => {
            let _ = switch.lock().await.detach().await;
            Err(e)
        }
    }
}

/// Completes a native (DM2/`LocalSpawn`) own-IP attach: relay the in-namespace
/// tap fd (created rootless by hakoniwa's RustSlirp and handed out via
/// `Child.rustslirp_tapfd`) to the local gvproxy `-listen` socket, then apply any
/// static ingress.
///
/// The lease was already allocated and gvproxy already ensured-running by the
/// pre-spawn `SwitchClient::attach()` (the IP had to be known before spawn to
/// configure the tap), so this only does the post-spawn relay + ingress and, on
/// failure, rolls the attach back. `lease_ip`/`sock` are the values snapshotted
/// from that pre-spawn attach.
pub(crate) async fn complete_local_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    tap_fd: OwnedFd,
    sock: PathBuf,
    lease_ip: Ipv4Addr,
    ingress: Option<&sessions::IngressPolicy>,
    hostnames: Arc<RwLock<HostnameRegistry>>,
    session_id: SessionId,
) -> io::Result<OwnIpGuard> {
    // Rollback of the pre-spawn phase-1 attach is owned by the session host's
    // launch guard (which also covers a cancelled launch), so a failure here just
    // propagates — detaching would double-decrement gvproxy's attach count.
    let relay = crate::net::switch::attach_to_switch(tap_fd, &sock).await?;
    let control = ControlChannel::Unix(sock);
    finish_own_ip_attach(
        switch, relay, control, lease_ip, ingress, hostnames, session_id,
    )
    .await
}

/// Shared tail of both own-IP attach paths: apply static ingress forwards (R2.3)
/// over `control`, then build the [`OwnIpGuard`]. On an ingress failure the relay
/// is dropped (closing the switch-side connection), but the attach-count rollback
/// is left to the caller — `attach_own_ip` (HostShuttle) detaches inline, while
/// the LocalSpawn path defers to the session host's launch guard so the refcount
/// is never double-decremented.
async fn finish_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    relay: SwitchRelay,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    ingress: Option<&sessions::IngressPolicy>,
    hostnames: Arc<RwLock<HostnameRegistry>>,
    session_id: SessionId,
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

    // Publish the live lease so in-VM host→PTask consumers (the `:7654`/`:7655`
    // proxies and `direct-tcpip`) dial the switch lease directly — the
    // host-loopback forwarder that DM2 relies on lives in the *host* netns and is
    // unreachable from inside the VM (G-N9). Only the VM path (`Vsock`) needs
    // this; DM2 (`Unix`) keeps the published-loopback placeholder, whose
    // shared-netns forwarder is reachable, so its verified behaviour is untouched.
    if let ControlChannel::Vsock { .. } = &control {
        let port_map = tcp_port_map(ingress);
        hostnames
            .write()
            .expect("hostname registry lock poisoned")
            .set_own_ip_lease(session_id, lease_ip, port_map);
    }

    Ok(OwnIpGuard {
        _relay: relay,
        switch: Arc::clone(switch),
        control,
        exposed,
        lease: lease_ip,
        hostnames,
        session_id,
    })
}

/// The static TCP ingress mappings as external→internal port pairs — the port
/// map published with the lease so the `:7654`/`:7655` proxies translate a
/// consumer's published external port to the PTask-internal port to dial. UDP
/// mappings are excluded: the HTTP proxies and `direct-tcpip` are TCP.
fn tcp_port_map(ingress: Option<&sessions::IngressPolicy>) -> Vec<(u16, u16)> {
    ingress
        .into_iter()
        .flat_map(|ingress| &ingress.port_mappings)
        .filter(|m| m.proto == sessions::IpProto::Tcp)
        .map(|m| (m.external_port, m.internal_port))
        .collect()
}
