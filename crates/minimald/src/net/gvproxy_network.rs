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

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};

use sandbox2::NetGuard;
use sessions::PortMapping;
use tokio::sync::Mutex;

use crate::net::policy::{BoxAdmissions, BoxZone, ControlChannel, ExposedMapping};
use crate::net::switch::{AdmittedPorts, SwitchRelay};
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
    /// This box's ingress as it stands while it runs: the forwards exposed on
    /// the switch (the static ones from its policy, R2.3, and any a dynamic
    /// ingress request added since), removed on teardown. Registered in
    /// `live_boxes` under the box's name for as long as the box runs.
    live: Arc<LiveIngress>,
    live_boxes: Arc<LiveBoxes>,
    /// The switch's in-guest box zone, and this box's name in it: withdrawn on
    /// teardown so a sibling's verdict and the zone dump name live boxes only
    /// (NET-072, NET-073).
    box_zone: Arc<BoxZone>,
    session_name: String,
}

/// A running own-address box's ingress, as it can change while the box runs:
/// what a dynamic ingress request decided `allow` adds a port to (NET-044),
/// and what its rollback takes the port out of again (NET-047).
///
/// A port a box publishes at runtime must reach it the way a declared one
/// does, and a declared port is admitted in four places fixed at attach: the
/// switch's forwarder, which carries the host-side port to the box's lease;
/// the relay's ingress gate, which admits the connection at the box's tap;
/// the box zone, where a sibling's verdict names the port; and the box's
/// declaration, which the daemon's hostname proxy decides routed requests
/// against. [`Self::admit`] adds the port to all four, and [`Self::retract`]
/// takes it out of them, so a running box needs no relaunch to serve it.
pub(crate) struct LiveIngress {
    /// gvproxy's control channel (local socket on DM2, host vsock on DM1/3/4):
    /// where the forwarder verbs are posted.
    control: ControlChannel,
    /// The box's switch lease, where the forwarder delivers.
    lease_ip: Ipv4Addr,
    /// The ports the box's relay admits inbound, shared with its ingress gate.
    ports: Arc<AdmittedPorts>,
    /// Every forward exposed on the switch for this box, removed on teardown.
    exposed: RwLock<Vec<ExposedMapping>>,
    box_zone: Arc<BoxZone>,
    admissions: Arc<RwLock<BoxAdmissions>>,
    session_name: String,
}

impl LiveIngress {
    /// The live ingress of the box named `session_name`, leased `lease_ip`,
    /// reached over `control`: `ports` is what its relay's gate admits, and
    /// `exposed` the forwards its static policy already put on the switch.
    pub(crate) fn new(
        control: ControlChannel,
        lease_ip: Ipv4Addr,
        ports: Arc<AdmittedPorts>,
        exposed: Vec<ExposedMapping>,
        box_zone: Arc<BoxZone>,
        admissions: Arc<RwLock<BoxAdmissions>>,
        session_name: &str,
    ) -> Self {
        Self {
            control,
            lease_ip,
            ports,
            exposed: RwLock::new(exposed),
            box_zone,
            admissions,
            session_name: session_name.to_string(),
        }
    }

    /// Exposes `mapping` on the switch and admits its port at the box's tap,
    /// in its zone entry and in its declaration.
    ///
    /// # Errors
    ///
    /// The switch's error when the forward could not be exposed; nothing is
    /// admitted then.
    pub(crate) async fn admit(&self, mapping: &PortMapping) -> io::Result<()> {
        let forward =
            crate::net::policy::expose_mapping(&self.control, self.lease_ip, mapping).await?;
        self.exposed
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(forward);
        self.ports.admit(mapping.proto, mapping.internal_port);
        self.box_zone
            .declare_port(&self.session_name, mapping.proto, mapping.internal_port);
        self.admissions
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .declare_port(&self.session_name, mapping.proto, mapping.external_port);
        Ok(())
    }

    /// Reverses [`Self::admit`] for `mapping`: the port is no longer admitted
    /// anywhere, and its forward is removed from the switch. Best-effort on
    /// the switch, like every unexpose: a forward that could not be removed is
    /// logged, and nothing admits the port any more either way.
    pub(crate) async fn retract(&self, mapping: &PortMapping) {
        self.admissions
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retract_port(&self.session_name, mapping.proto, mapping.external_port);
        self.box_zone
            .retract_port(&self.session_name, mapping.proto, mapping.internal_port);
        self.ports.retract(mapping.proto, mapping.internal_port);
        let local = crate::net::policy::expose_request(mapping, self.lease_ip).local;
        let removed: Vec<ExposedMapping> = {
            let mut exposed = self.exposed.write().unwrap_or_else(PoisonError::into_inner);
            let (removed, kept) = std::mem::take(&mut *exposed)
                .into_iter()
                .partition(|forward| forward.local() == local);
            *exposed = kept;
            removed
        };
        crate::net::policy::remove_ingress(&self.control, &removed).await;
    }

    /// Every forward exposed for the box so far, for the teardown to remove.
    fn exposed(&self) -> Vec<ExposedMapping> {
        self.exposed
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The running own-address boxes on the switch, by session name: what a
/// dynamic ingress request looks its box up in to publish a port to a box
/// that is already running. A box is registered as its attach completes and
/// withdrawn as its guard tears down; a box not in here is not running, and
/// a mapping recorded for it applies at its next attach.
#[derive(Debug, Default)]
pub(crate) struct LiveBoxes {
    boxes: RwLock<HashMap<String, Arc<LiveIngress>>>,
}

impl LiveBoxes {
    /// The live ingress of the running box named `session_name`, or `None`
    /// when no such box is running.
    #[must_use]
    pub(crate) fn get(&self, session_name: &str) -> Option<Arc<LiveIngress>> {
        self.boxes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(session_name)
            .cloned()
    }

    /// Registers `live` as the running box named `session_name`, replacing
    /// any earlier registration under the name (a relaunch).
    pub(crate) fn register(&self, session_name: &str, live: Arc<LiveIngress>) {
        self.boxes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_name.to_string(), live);
    }

    /// Withdraws the box named `session_name` as it stops running.
    pub(crate) fn withdraw(&self, session_name: &str) {
        self.boxes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(session_name);
    }
}

impl std::fmt::Debug for LiveIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveIngress")
            .field("lease_ip", &self.lease_ip)
            .field("session_name", &self.session_name)
            .finish_non_exhaustive()
    }
}

impl NetGuard for OwnIpGuard {
    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            // Remove ingress forwards (R2.3 teardown) before detaching: detach
            // may stop gvproxy once the last PTask leaves, so the unexpose must
            // reach a still-running switch first.
            // Withdrawn first, so no dynamic request admits a port to a box
            // that is going away.
            self.live_boxes.withdraw(&self.session_name);
            let exposed = self.live.exposed();
            if !exposed.is_empty() {
                crate::net::policy::remove_ingress(&self.live.control, &exposed).await;
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
    let ports = gate.ports();
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
        ports,
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
    /// The ports the relay's ingress gate admits, to admit a dynamic one into.
    ports: Arc<AdmittedPorts>,
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
        ports,
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
    let (box_zone, admissions, live_boxes) = {
        let switch = switch.lock().await;
        (switch.box_zone(), switch.admissions(), switch.live_boxes())
    };
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

    // The box runs from here: a dynamic ingress request finds it under its
    // name and admits a port into the relay, the switch and both tables above.
    let live = Arc::new(LiveIngress::new(
        control,
        lease_ip,
        ports,
        exposed,
        Arc::clone(&box_zone),
        admissions,
        session_name,
    ));
    live_boxes.register(session_name, Arc::clone(&live));

    Ok(OwnIpGuard {
        _relay: relay,
        switch: Arc::clone(switch),
        live,
        live_boxes,
        box_zone,
        session_name: session_name.to_string(),
    })
}
