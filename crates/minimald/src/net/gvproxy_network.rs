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
use std::pin::Pin;
use std::sync::Arc;

use sandbox2::{AttachFuture, NetGuard, Network, NetworkError};
use tokio::sync::Mutex;

use crate::net::SwitchClient;
use crate::net::policy::{ControlChannel, ExposedMapping};
use crate::net::switch::SwitchRelay;

/// An own-IP network: attaches a sandbox's network namespace to the per-host
/// gvproxy switch and applies its static ingress forwards (R1.5/R2.3).
pub(crate) struct GvproxyNetwork {
    /// The shared per-host switch (the daemon-scoped process owner / refcounter).
    switch: Arc<Mutex<SwitchClient>>,
    /// Static ingress port mappings to apply once attached; `None`/empty for none.
    ingress: Option<sessions::IngressPolicy>,
}

impl GvproxyNetwork {
    pub(crate) fn new(
        switch: Arc<Mutex<SwitchClient>>,
        ingress: Option<sessions::IngressPolicy>,
    ) -> Self {
        Self { switch, ingress }
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

    fn nameserver(&self) -> Option<std::net::Ipv4Addr> {
        // An own-IP PTask lives in a fresh netns where the host's stub resolver
        // (`127.0.0.53`, baked into the synth rootfs) is dead, so DNS fails even
        // though egress-by-IP works. gvproxy serves DNS at the switch gateway and
        // the PTask's default route already points there, so resolve via it.
        // Synchronous and lock-free by construction: the gateway is fixed by the
        // daemon's `DEFAULT_SUBNET`, so there is no need to lock the async
        // `SwitchClient` (a `tokio::sync::Mutex`) from this sync trait method.
        Some(crate::net::DEFAULT_SUBNET.gateway())
    }

    fn attach(&self, netns_pid: u32) -> AttachFuture<'_> {
        Box::pin(async move {
            let guard = attach_own_ip(&self.switch, netns_pid, self.ingress.as_ref())
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
struct OwnIpGuard {
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

/// Attaches an `OwnIp` PTask (identified by its sandbox process's netns-holding
/// PID) to the shared gvproxy switch: allocate a lease and ensure gvproxy is up,
/// open a host-side tap, move it into the PTask's network namespace and
/// configure its switch address there, then start the frame relay and apply any
/// static ingress.
async fn attach_own_ip(
    switch: &Arc<Mutex<SwitchClient>>,
    netns_pid: u32,
    ingress: Option<&sessions::IngressPolicy>,
) -> io::Result<OwnIpGuard> {
    use crate::net::SwitchTransport;
    use crate::net::switch::{
        attach_to_switch, attach_to_switch_vsock, move_tap_into_netns, open_netns_fd, open_tap,
        open_tap_in_netns,
    };

    // Pin the PTask net namespace immediately, before the (gvproxy-spawning)
    // switch attach: the just-spawned PTask process can exit during that window,
    // and an exited process's `/proc/<pid>/ns/net` vanishes. Holding an fd keeps
    // the namespace alive so the in-process (DM2) tap setup can still enter it.
    // Cheap and harmless on the DM1/3/4 path (it drops the fd and uses the PID).
    let netns = open_netns_fd(netns_pid)?;

    // Allocate a lease and ensure gvproxy is running, snapshotting the control
    // socket, subnet, and transport under one lock; the slow tap/relay work runs
    // unlocked so concurrent attaches don't serialize on the namespace plumbing.
    let (lease, sock, subnet, transport) = {
        let mut s = switch.lock().await;
        let attach = s
            .attach()
            .await
            .map_err(|e| io::Error::other(format!("attaching OwnIp PTask to switch: {e}")))?;
        // gvproxy's unexpected-exit closes the control socket, which ends the
        // relay's switch-side read on its own, so the relay self-terminates; we
        // do not additionally watch `attach.exit_signal` here.
        (attach.lease, s.control_socket(), s.subnet(), s.transport())
    };

    // A locally-administered tap name unique within the switch /16 (its low two
    // octets distinguish every PTask address) and within the 15-char `IFNAMSIZ`
    // limit (`mtapNNN_NNN` is at most 11 chars).
    let o = lease.ip.octets();
    let tap = format!("mtap{}_{}", o[2], o[3]);

    // On any failure after the switch attach succeeded, roll the attach back so
    // gvproxy's refcount stays accurate (a leaked count would keep it running).
    let relay = match async {
        // Set up the PTask tap in its namespace. DM2 (LocalSpawn, a host-native
        // daemon that may be unprivileged + `setcap`'d) does it in-process so no
        // privileged `ip`/`nsenter` child is needed; DM1/3/4 (HostShuttle, a
        // root-in-VM daemon) keep the proven `ip`/`nsenter` path.
        let tap_fd = match transport {
            SwitchTransport::LocalSpawn => open_tap_in_netns(&tap, netns, lease, subnet).await?,
            SwitchTransport::HostShuttle { .. } => {
                let tap_fd = open_tap(&tap)?;
                move_tap_into_netns(&tap, netns_pid, lease, subnet).await?;
                tap_fd
            }
        };
        // DM2 attaches the tap to the local gvproxy `-listen` socket; DM1/3/4
        // (HostShuttle) relays the tap's raw frames over vsock to the host
        // gvproxy `minvmd` owns. Both are the same HyperKit-framed L2 relay —
        // one gVisor stack in the path either way.
        match transport {
            SwitchTransport::LocalSpawn => attach_to_switch(tap_fd, &sock).await,
            SwitchTransport::HostShuttle { cid, port } => {
                attach_to_switch_vsock(tap_fd, cid, port).await
            }
        }
    }
    .await
    {
        Ok(relay) => relay,
        Err(e) => {
            let _ = switch.lock().await.detach().await;
            return Err(e);
        }
    };

    // The control channel for the forwarder API: the local socket on DM2, the
    // host gvproxy over the same vsock shuttle port on DM1/3/4 (the `-listen`
    // socket serves `/services/forwarder/*` alongside the `/connect` relay).
    let control = match transport {
        SwitchTransport::LocalSpawn => ControlChannel::Unix(sock),
        SwitchTransport::HostShuttle { cid, port } => ControlChannel::Vsock { cid, port },
    };

    // R2.3/R2.4-static: with the PTask attached, apply its static ingress
    // forwards via gvproxy's forwarder API, retaining handles to remove on exit.
    // A failure here rolls the whole attach back (drop the relay, then detach)
    // so a half-configured PTask is never left running.
    let exposed = match ingress {
        Some(ingress) if !ingress.port_mappings.is_empty() => {
            match crate::net::policy::apply_ingress(&control, lease.ip, ingress).await {
                Ok(exposed) => exposed,
                Err(e) => {
                    drop(relay);
                    if let Err(det_err) = switch.lock().await.detach().await {
                        tracing::warn!(
                            error = %det_err,
                            ingress_err = %e,
                            "detaching OwnIp PTask from switch during ingress-apply rollback"
                        );
                    }
                    return Err(e);
                }
            }
        }
        _ => Vec::new(),
    };

    Ok(OwnIpGuard {
        _relay: relay,
        switch: Arc::clone(switch),
        control,
        exposed,
    })
}
