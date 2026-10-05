//! One function that reads a PTask's network mode, and the own-IP provider it
//! returns. Every sandbox consumer in the daemon calls [`network_for`], and
//! nothing else reads the mode. The gvproxy **process** belongs to the
//! daemon-scoped [`SwitchClient`] (DM2) or to `minvmd` (DM1/3/4); this only
//! leases from it and wires a running switch into a sandbox's namespace.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use sandbox2::{
    AbandonFuture, AttachFuture, NetGuard, NetPlan, Network, NetworkError, PlanFuture, Resolver,
    Spawned, TapSpec,
};
use sessions::{NetworkMode, SessionId};
use tokio::sync::Mutex;

use crate::net::SwitchClient;
use crate::net::policy::ControlChannel;

/// Reports an own-address box's lease to the proxy's routing table (NET-001).
/// The session launcher mints one per launch carrying the stable `SessionId`,
/// so the lease the attach path reports stays with the session across a
/// rename — the registry keys the fact by the id, not the mutable name.
///
/// A task launch carries none: a task is a second PTask beside its session's
/// and owns no proxy route of its own.
#[derive(Debug, Clone)]
pub(crate) struct OwnAddressReporter {
    registry: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
    session_id: SessionId,
    /// The box's runtime publishes (NET-044), shared with its session actor:
    /// the attach this reporter rides hands it to the spawn's guard, so the
    /// runtime forwards come down with the spawn exactly as the declared
    /// ones do.
    runtime_ingress: RuntimeIngress,
}

/// One live runtime publish (NET-044): the forwarder the switch accepted,
/// paired with the mapping it published — held together, so the list the
/// policy surfaces read is exactly what the switch holds.
pub(crate) struct LiveIngressForward {
    /// The daemon-owned forward: its unexpose releases the port.
    pub(crate) forwarder: crate::net::policy::PortForwarder,
    /// The mapping as the policy surfaces read it.
    pub(crate) mapping: minimald_rpc::LiveMapping,
}

/// The row the policy surfaces read, not the forwarder's own internals —
/// `PortForwarder` is a handle, and the mapping is the fact it published.
impl std::fmt::Debug for LiveIngressForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveIngressForward")
            .field("mapping", &self.mapping)
            .finish()
    }
}

#[derive(Default)]
struct RuntimeIngressState {
    /// The spawn that held the box's switch address has ended and no new one
    /// has attached: a forward published now would deliver to a lease the
    /// switch may already have handed to another box.
    detached: bool,
    forwards: Vec<LiveIngressForward>,
}

/// The ports a box published at runtime with its own `min net expose`
/// (NET-044), shared between its session actor — which publishes, lists and
/// unbinds them at stop — and the guard of the spawn they deliver to. A
/// runtime forward delivers to that spawn's lease, and leases are per-spawn,
/// so the forwards follow the declared ones: the spawn's teardown unbinds
/// them beside its declared forwards, and the next spawn starts with none
/// rather than inheriting a forward aimed at a stale address.
#[derive(Clone, Default)]
pub(crate) struct RuntimeIngress(Arc<std::sync::Mutex<RuntimeIngressState>>);

impl std::fmt::Debug for RuntimeIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeIngress")
            .field("mappings", &self.snapshot())
            .finish()
    }
}

impl RuntimeIngress {
    fn state(&self) -> std::sync::MutexGuard<'_, RuntimeIngressState> {
        self.0.lock().expect("runtime ingress lock poisoned")
    }

    /// The live mappings, in publish order — the rows `min session policy`
    /// lists beside the declaration.
    pub(crate) fn snapshot(&self) -> Vec<minimald_rpc::LiveMapping> {
        self.state()
            .forwards
            .iter()
            .map(|live| live.mapping.clone())
            .collect()
    }

    /// Whether the spawn the box's forwards deliver to has ended with no new
    /// one attached.
    pub(crate) fn is_detached(&self) -> bool {
        self.state().detached
    }

    /// Records a publish the switch accepted. Refused — handing the forward
    /// back for the caller to unbind — when the spawn it delivers to ended
    /// while the publish was in flight, so a forward aimed at a dead lease is
    /// never recorded as live.
    pub(crate) fn record(&self, live: LiveIngressForward) -> Result<(), LiveIngressForward> {
        let mut state = self.state();
        if state.detached {
            return Err(live);
        }
        state.forwards.push(live);
        Ok(())
    }

    /// A spawn attached: its lease is the box's switch address from here on.
    fn attached(&self) {
        self.state().detached = false;
    }

    /// The spawn ended: takes every runtime forward for the guard to unbind
    /// beside the declared ones, and refuses publishes until the next attach.
    pub(crate) fn detach(&self) -> Vec<crate::net::policy::PortForwarder> {
        let mut state = self.state();
        state.detached = true;
        std::mem::take(&mut state.forwards)
            .into_iter()
            .map(|live| live.forwarder)
            .collect()
    }

    /// The box stopped: takes every runtime forward for the session actor to
    /// unbind.
    pub(crate) fn take_all(&self) -> Vec<crate::net::policy::PortForwarder> {
        std::mem::take(&mut self.state().forwards)
            .into_iter()
            .map(|live| live.forwarder)
            .collect()
    }
}

impl OwnAddressReporter {
    /// Builds the reporter for one session's launches.
    #[must_use]
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn new(
        registry: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
        session_id: SessionId,
    ) -> Self {
        Self {
            registry,
            session_id,
            runtime_ingress: RuntimeIngress::default(),
        }
    }

    /// The same reporter, sharing `runtime_ingress` with the session actor
    /// that publishes into it.
    #[must_use]
    pub(crate) fn with_runtime_ingress(mut self, runtime_ingress: RuntimeIngress) -> Self {
        self.runtime_ingress = runtime_ingress;
        self
    }

    /// The box's runtime publishes, for the spawn's guard to unbind at its
    /// teardown.
    pub(crate) fn runtime_ingress(&self) -> RuntimeIngress {
        self.runtime_ingress.clone()
    }

    /// Reports `lease` — with the box's ingress declaration as an
    /// external→internal port map — and registers `session_name`'s box name
    /// against it, so the name routes exactly when the box is reachable. The
    /// lease is always recorded; on a native host the registration follows it
    /// only where the box has a published address to route at (NET-010).
    pub(crate) fn report(&self, session_name: &str, lease: Ipv4Addr, ports: BTreeMap<u16, u16>) {
        let mut registry = self
            .registry
            .write()
            .expect("hostname registry lock poisoned");
        registry.report_own_address(self.session_id, session_name, lease, ports);
        drop(registry);
        self.runtime_ingress.attached();
    }

    /// The switch lease the attach reported for this box ([`Self::report`]),
    /// or `None` before an attach reported one. On a VM host the daemon
    /// builds the box's tap itself after the spawn
    /// ([`TapMechanism::Privileged`]), so the launch's plan carries no tap to
    /// read the lease from: this is where the lease is read there.
    pub(crate) fn lease(&self) -> Option<Ipv4Addr> {
        self.registry
            .read()
            .expect("hostname registry lock poisoned")
            .own_lease(self.session_id)
    }

    /// The host loopback address this box's declaration publishes on (NET-010):
    /// the address a creator handed the box and its record published — `None`
    /// when nobody handed one, because the daemon has no address of its own to
    /// stand in with. The attach path reads it here — rather than re-deriving
    /// one — so the forwards it binds and the name the registry answers stay at
    /// the one address the box owns, and a box nobody handed an address fails
    /// its attach rather than publishing at a default.
    pub(crate) fn published_address(&self) -> Option<Ipv4Addr> {
        self.registry
            .read()
            .expect("hostname registry lock poisoned")
            .published_own_address(self.session_id)
    }

    /// Withdraws `session_name`'s box name if this session still owns it —
    /// the failed attach's other half (NET-121): a bind that failed, or an
    /// address nobody handed, leaves no name standing that says "reachable
    /// here" over ports that are not.
    pub(crate) fn withdraw(&self, session_name: &str) {
        let mut registry = self
            .registry
            .write()
            .expect("hostname registry lock poisoned");
        registry.withdraw_own_name(self.session_id, session_name);
    }
}

/// The box's switch lease once its launch has attached, for the listen
/// watcher (NET-016): the tap the plan asked the sandbox to build carries it
/// where the sandbox builds the tap, and where the daemon builds it itself —
/// a VM host's privileged tap, whose plan carries no tap at all — the lease
/// the attach reported is read instead. `None` for a box with neither: no
/// own address, so nothing a listen could be published for.
pub(crate) fn attached_lease(
    plan: &NetPlan,
    own_address: Option<&OwnAddressReporter>,
) -> Option<Ipv4Addr> {
    plan.tap()
        .map(|tap| tap.address)
        .or_else(|| own_address.and_then(OwnAddressReporter::lease))
}

/// The network provider for `mode`. `NoNet` is the sandbox layer's own; `HostNet`
/// is the sandbox layer's plan, decided here against the switch (on a VM host
/// the resolver must be the node's DNS layer, not the host's) and against the
/// box's own declaration — a native deny-all box resolves through the box
/// zone's answerer, and its leaf is selected into the deny subtree, both from
/// the policy below (NET-079); `OwnIp` needs a
/// lease, a tap and a switch attach. An unrecognised mode (`NetworkMode` is
/// `#[non_exhaustive]`) gets the empty namespace, the safe direction.
///
/// `policy` is the launch's whole session policy — the own-IP relay gate carries
/// it in both directions (egress verdict per NET-062/063/064, inbound
/// default-block per finding #2), while other modes have no relay to gate;
/// `None` attaches ungated. The session launcher passes the box's *effective*
/// policy (NET-074), and a task launch passes its session's effective egress
/// alone when the rollout leaves one in force, `None` while the default is
/// only announced or the daemon opted out — an ungated task keeps the open
/// inbound it always had — because a task carries none of its session's
/// ingress, the session's own PTask being attached at the same time.
/// `own_address` carries the registry handle an own-address launch reports its
/// lease through once the box attaches (NET-001); a task launch passes `None`
/// for that too. `box_addresses` carries the switch and loopback addresses
/// the VM host daemon handed the box's registration (T66): its switch
/// address is what this `OwnIp` PTask attaches with instead of drawing one,
/// because the host-side table's row is keyed by it. A task launch passes
/// `None` deliberately — the task's sandbox is not the box the registration
/// named, and attaching it at the box's address would key its frames to the
/// session's row. `decision` carries the verdict decision this launch itself
/// read for the box before it reserved anything (NET-079) — the launch's own
/// fresh fact, never another launch's, which a process-wide memo left a
/// concurrent launch free to read in its place. A task launch passes `None`
/// deliberately too: it places no classifier leaf, so there is no per-box
/// verdict for its plan to follow.
pub(crate) fn network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: &str,
    policy: Option<sessions::SessionPolicy>,
    own_address: Option<OwnAddressReporter>,
    box_addresses: Option<sessions::BoxAddresses>,
    decision: Option<crate::net::classifier::Decision>,
) -> Arc<dyn Network> {
    match mode {
        NetworkMode::HostNet => Arc::new(HostIpAddressNetwork {
            switch: Arc::clone(switch),
            // NET-079: the subtree this box's declaration places its leaf
            // in — deny when the declaration admits no destination, allow
            // otherwise — selected here from the policy the launch passes,
            // so the plan the box is built around is the one its own
            // verdict decides.
            verdict: host_address_verdict(policy.as_ref().and_then(|p| p.egress.as_ref())),
            // NET-079: the decision this launch itself read, fresh before
            // it — the box's own verdict fact, carried in rather than
            // memoized, so the plan below follows this launch's reading and
            // never a concurrent launch's.
            decision,
        }),
        NetworkMode::OwnIp => Arc::new(OwnIpNetwork {
            switch: Arc::clone(switch),
            identity: identity.to_string(),
            policy,
            own_address,
            box_addresses,
            reserved: std::sync::Mutex::new(None),
        }),
        _ => Arc::new(sandbox2::NoNet),
    }
}

/// A host-address box: it shares the daemon host's network namespace, so its
/// plan is the sandbox layer's [`sandbox2::HostNet`] — except on a VM host,
/// where the namespace it shares is the *guest's* and the host's own resolver
/// is unreachable from it. There the plan points the resolver at the node's
/// DNS layer — the switch gateway, whose static `min.internal.` zone carries
/// the `host` record (NET-003) — whatever the rootfs ships. And on a native
/// host under a deny-all declaration, the plan points the resolver at the
/// box zone's answerer instead of the host's own (NET-079): the one
/// destination the deny rule admits, where the box resolves exactly the
/// names the box zone holds and nothing forwards upstream.
struct HostIpAddressNetwork {
    switch: Arc<Mutex<SwitchClient>>,
    /// The cohort subtree this box's declaration places its leaf in
    /// (NET-079) — the deny subtree when the declaration admits no
    /// destination. Decided before the box's first process exists, like the
    /// leaf itself, because the plan is built before the spawn.
    verdict: sandbox2::config::Verdict,
    /// The verdict decision this launch read before it reserved the plan
    /// (NET-079) — carried in by the launch that builds the plan, so the
    /// plan follows its own launch's reading and never a concurrent
    /// launch's, which a process-wide memo let a later launch overwrite in
    /// its place. `None` for a task launch: it places no classifier leaf,
    /// so there is no per-box verdict for its plan to follow.
    decision: Option<crate::net::classifier::Decision>,
}

impl std::fmt::Debug for HostIpAddressNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIpAddressNetwork")
            .finish_non_exhaustive()
    }
}

/// Which cohort subtree a host-address box's declaration places its leaf in
/// (NET-079) — the deny subtree when the declaration admits no destination,
/// the allow subtree otherwise. The leaf's *placement* is the session
/// launcher's (a migration the daemon makes); what the provider selects is
/// the subtree, because the plan it builds for the box is decided by the
/// same verdict its connections are.
///
/// Pure over the declaration, so the verdict a box's plan is built around is
/// pinned beside the plan it decides.
fn host_address_verdict(declaration: Option<&sessions::EgressPolicy>) -> sandbox2::config::Verdict {
    crate::net::classifier::verdict_of(declaration)
}

impl Network for HostIpAddressNetwork {
    /// Reads the switch's transport once, before the process starts. Nothing is
    /// attached, so this never starts or stops a gvproxy process.
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(async move {
            let vm_host = {
                let s = self.switch.lock().await;
                matches!(
                    s.transport(),
                    crate::net::SwitchTransport::HostShuttle { .. }
                )
            };
            if !vm_host {
                // A native deny-all box resolves through the box zone's
                // answerer (NET-079), never through the host's own resolver:
                // the host's resolver forwards any name upstream, so a
                // deny-all box pointed at it would resolve everything
                // outside through the one destination its connections are
                // admitted to. The plan names the answerer's address — the
                // one address the deny rule admits — and that is all
                // `/etc/resolv.conf` can name: the answerer's port is the
                // one the rule admits and the host's resolver hook names
                // with its `port` directive (NET-122, design §7.1), and it
                // stays the answerer's own, not the plan's.
                if self.verdict == sandbox2::config::Verdict::Deny {
                    // Over a table that decides per box, the carve-out it
                    // loaded must name the answerer actually serving: a
                    // stale target, or no answerer at all, refuses the box
                    // (NET-079), and the resolver is the live bind's own
                    // address, never a constant.
                    let live = crate::net::classifier::live_answerer();
                    if let Some(decision) = self
                        .decision
                        .as_ref()
                        .filter(|decision| decision.can_decide_per_box())
                        && let Some(refusal) = crate::net::classifier::stale_carve_out_refusal(
                            decision.carve_out(),
                            live,
                        )
                    {
                        return Err(NetworkError::new(std::io::Error::other(refusal)));
                    }
                    let answerer = match live {
                        Some(std::net::SocketAddr::V4(bound)) => *bound.ip(),
                        _ => crate::net::classifier::ANSWERER_ADDRESS,
                    };
                    return Ok(NetPlan::host().with_resolver(Resolver::Nameservers(vec![answerer])));
                }
                // Native host: the namespace the box shares is the host's own,
                // so the sandbox layer's plan answers `host.min.internal` from
                // `/etc/hosts` at the host's loopback.
                return sandbox2::HostNet.plan().await;
            }
            // NET-079: a VM host that decides per box gives a deny-all
            // host-address box no resolver. The node's DNS layer applies no
            // per-box name rule to host-address boxes, so the guest's table
            // carves nothing out for it and its DNS to the gateway is refused
            // like any other destination (follow-up gominimal/inbox#897).
            // The decision is the launch's own, carried in when the plan was
            // built: a guest whose boot's check or load failed, whose table
            // is gone behind its marker, or whose probe did not read a
            // refusal falls through to the node's DNS layer below, exactly
            // as before this host could decide — and a concurrent launch's
            // reading can never stand in for it.
            if self.verdict == sandbox2::config::Verdict::Deny
                && self
                    .decision
                    .as_ref()
                    .is_some_and(|decision| decision.can_decide_per_box())
            {
                return Ok(NetPlan::host().with_resolver(Resolver::Nameservers(Vec::new())));
            }
            // NET-003: on a VM host, 127.0.0.1 in the namespace a host-address
            // box shares is the guest's loopback, not the host's, and the host
            // resolver `/etc/hosts` would complement is unreachable. The node's
            // DNS layer answers the name at the gateway, and
            // `Resolver::Nameservers` replaces whatever the rootfs ships.
            let ns = { self.switch.lock().await.subnet().dns_server() };
            Ok(NetPlan::host().with_resolver(Resolver::Nameservers(vec![ns])))
        })
    }
}

/// Who builds the tap an own-IP PTask needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TapMechanism {
    /// The sandbox layer builds it *inside* the PTask's own network namespace,
    /// rootless, and hands the descriptor out.
    InNamespace,
    /// The daemon builds it in its own namespace under `CAP_NET_ADMIN` and moves
    /// it in with `ip`, after the process exists.
    Privileged,
}

/// Which mechanism builds this PTask's tap, decided from the control channel
/// once, before the sandbox starts.
///
/// A choice, not a fallback: in the x86_64 KVM guest, asking RustSlirp for a
/// tap yields no descriptor *and* takes the container supervisor with it, so
/// there is no namespace left to fall back into (spec 017, open questions).
/// `Privileged` execs `ip`/`nsenter` with `CAP_NET_ADMIN`, so it is used only
/// inside a microVM whose network the daemon owns, never on a native host.
fn tap_mechanism(control: &ControlChannel) -> TapMechanism {
    match control {
        // DM1/3/4: minimald is root in a guest whose network it owns outright.
        ControlChannel::Vsock { .. } => TapMechanism::Privileged,
        // DM2: unprivileged by design. No catch-all arm: a new transport must
        // decide this deliberately.
        ControlChannel::Unix(_) => TapMechanism::InNamespace,
    }
}

/// The plan an own-IP PTask needs, given its switch subnet, its lease, and who
/// is building its tap. Pure, so testable without a running switch.
fn own_ip_plan(
    subnet: crate::net::SwitchSubnet,
    lease_ip: std::net::Ipv4Addr,
    mechanism: TapMechanism,
) -> NetPlan {
    let plan = match mechanism {
        TapMechanism::InNamespace => NetPlan::isolated_with_tap(TapSpec {
            address: lease_ip,
            netmask: subnet.netmask(),
            gateway: subnet.gateway(),
            // Must match the relay's frame buffer.
            mtu: crate::net::DEFAULT_MTU,
        }),
        // The daemon puts the tap there itself, after the process exists.
        TapMechanism::Privileged => NetPlan::isolated(),
    };
    // A fresh netns cannot reach the host's stub resolver; the switch answers
    // DNS at the gateway (R3.1).
    plan.with_resolver(Resolver::Nameservers(vec![subnet.dns_server()]))
}

/// Creates a tap in the daemon's own network namespace, moves it into the
/// PTask's, and configures it there — the [`TapMechanism::Privileged`] path.
async fn privileged_tap(
    lease: crate::net::PtaskLease,
    subnet: crate::net::SwitchSubnet,
    netns_pid: u32,
) -> std::io::Result<std::os::fd::OwnedFd> {
    // Check the destination before making anything: a tap made for a namespace
    // that is already gone is left in the daemon's own, holding its name.
    let netns = format!("/proc/{netns_pid}/ns/net");
    if !std::path::Path::new(&netns).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "the PTask's network namespace is gone before its tap was made \
                 ({netns} does not exist); the sandbox did not survive its spawn"
            ),
        ));
    }
    // Unique across every subnet the switch accepts (`/8` to `/29`), within
    // the 15-char `IFNAMSIZ` limit.
    let o = lease.ip.octets();
    let tap = format!("mtap{}_{}_{}", o[1], o[2], o[3]);
    let tap_fd = crate::net::switch::open_tap(&tap)?;
    crate::net::switch::move_tap_into_netns(&tap, netns_pid, lease, subnet).await?;
    Ok(tap_fd)
}

/// What [`OwnIpNetwork::plan`] reserved, waiting for an attach or an abandon.
#[derive(Debug, Clone)]
struct Reserved {
    /// The full lease: the privileged mechanism needs the MAC too.
    lease: crate::net::PtaskLease,
    subnet: crate::net::SwitchSubnet,
    /// gvproxy's control channel: a local socket on DM2, host vsock on DM1/3/4.
    control: ControlChannel,
    /// Decided with the plan, so `attach` cannot reach a different conclusion
    /// than the plan the sandbox was built from.
    mechanism: TapMechanism,
}

/// An own-IP network: leases an address from the per-host gvproxy switch before
/// the sandbox starts, then relays the sandbox's own tap onto that switch,
/// gated by the session's policy — its declared egress enforced on the
/// relay's outbound leg, its static ingress forwards applied and inbound
/// ports gated on the other (R1.5/R2.3, NET-062).
struct OwnIpNetwork {
    switch: Arc<Mutex<SwitchClient>>,
    /// Registered as the PTask's `*.min.internal` hostname on attach (R3.1).
    identity: String,
    /// The launch's whole session policy, carried into the relay gate.
    policy: Option<sessions::SessionPolicy>,
    /// The registry handle the lease is reported through on attach, so the
    /// box's proxy route exists exactly while the lease does (NET-001). `None`
    /// for a task launch, which owns no proxy route.
    own_address: Option<OwnAddressReporter>,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when it was registered: the switch address this PTask attaches
    /// with instead of drawing one — the host-side table's row is keyed by
    /// it, so a self-allocated lease would never match — and the published
    /// loopback address the host side names the box by. `None` for a launch
    /// the activating client did not register, which draws as it always
    /// has.
    box_addresses: Option<sessions::BoxAddresses>,
    /// Taken by `plan`, taken back out by `attach` or `abandon`. A `std` mutex,
    /// never held across an await, so a cancelled launch cannot leak it.
    reserved: std::sync::Mutex<Option<Reserved>>,
}

impl std::fmt::Debug for OwnIpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnIpNetwork")
            .field("identity", &self.identity)
            .field("has_policy", &self.policy.is_some())
            .field("handed_addresses", &self.box_addresses.is_some())
            .finish_non_exhaustive()
    }
}

impl Network for OwnIpNetwork {
    /// Lease an address and make sure the switch is up, then describe the tap
    /// the sandbox layer should build. Before the process starts, because the
    /// sandbox layer assigns the address as it creates the tap.
    ///
    /// The lease is the host's handed address when the box was registered
    /// (T66) — the address the host-side table's row is keyed by — and a
    /// self-allocated one otherwise, exactly as before this existed.
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(async move {
            let (lease, control, subnet) = {
                let mut s = self.switch.lock().await;
                let subnet = s.subnet();
                let attach = match self.box_addresses.as_ref() {
                    Some(handed) => s
                        .attach_handed(handed.switch_address)
                        .await
                        .map_err(NetworkError::new)?,
                    None => s.attach().await.map_err(NetworkError::new)?,
                };
                let control = match s.transport() {
                    crate::net::SwitchTransport::LocalSpawn => {
                        ControlChannel::Unix(s.control_socket())
                    }
                    crate::net::SwitchTransport::HostShuttle { cid, port } => {
                        ControlChannel::Vsock { cid, port }
                    }
                };
                (attach.lease, control, subnet)
            };

            let mechanism = tap_mechanism(&control);
            *self.reserved.lock().unwrap() = Some(Reserved {
                lease,
                subnet,
                control,
                mechanism,
            });
            Ok(own_ip_plan(subnet, lease.ip, mechanism))
        })
    }

    /// Relay the sandbox's tap onto the switch and apply its ingress. The
    /// reservation is read, not taken, until the attach has succeeded: a
    /// failed attach hands the release to [`abandon`](Self::abandon) (017-008).
    fn attach(&self, mut spawned: Spawned) -> AttachFuture<'_> {
        Box::pin(async move {
            let Some(reserved) = self.reserved.lock().unwrap().clone() else {
                return Err(NetworkError::new(std::io::Error::other(
                    "own-IP attach without a plan: nothing was leased",
                )));
            };

            // The mechanism `plan` chose; only the matching branch can succeed.
            let tap_fd = match reserved.mechanism {
                TapMechanism::InNamespace => {
                    let Some(fd) = spawned.take_tap_fd() else {
                        // Report what building one in-namespace needs: which
                        // capability is missing separates a kernel-config
                        // problem from a policy one.
                        let tun = std::path::Path::new("/dev/net/tun").exists();
                        let userns = sandbox2::user_namespaces_restriction()
                            .map_or_else(|| "available".to_string(), |r| r.to_string());
                        return Err(NetworkError::new(std::io::Error::other(format!(
                            "own-IP sandbox produced no in-namespace tap fd \
                             (/dev/net/tun present: {tun}; user namespaces: {userns})"
                        ))));
                    };
                    fd
                }
                TapMechanism::Privileged => {
                    privileged_tap(reserved.lease, reserved.subnet, spawned.netns_pid())
                        .await
                        .map_err(NetworkError::new)?
                }
            };

            let guard = crate::net::gvproxy_network::complete_own_ip_attach(
                &self.switch,
                tap_fd,
                reserved.control,
                reserved.lease.ip,
                &self.identity,
                self.policy.as_ref(),
                self.own_address.as_ref(),
                self.box_addresses.is_some(),
            )
            .await
            .map_err(NetworkError::new)?;
            // Committed: the guard owns the release from here.
            self.reserved.lock().unwrap().take();
            Ok(Box::new(guard) as Box<dyn NetGuard>)
        })
    }

    /// Give the lease back; the sandbox layer runs this on every path out of a
    /// launch that does not reach `attach`. The detach releases the lease
    /// with the count (T66), so an abandoned launch leaves no lease in the
    /// static-lease table for a tap nothing holds — the handed one included,
    /// which is what lets the same box's re-attach re-hand its address.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(async move {
            let Some(reserved) = self
                .reserved
                .lock()
                .expect("reserved mutex poisoned")
                .take()
            else {
                // The plan failed or an attach took it; detaching anyway would
                // decrement the switch's count below the truth.
                return;
            };
            if let Err(e) = self.switch.lock().await.detach(reserved.lease.ip).await {
                tracing::warn!(error = %e, "detaching OwnIp PTask after an abandoned launch");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A switch whose attach/detach are pure bookkeeping: `HostShuttle` leaves
    /// the gvproxy process to `minvmd`, so only the count moves.
    fn counting_switch() -> Arc<Mutex<SwitchClient>> {
        Arc::new(Mutex::new(
            SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
                crate::net::SwitchTransport::HostShuttle {
                    cid: crate::net::VSOCK_HOST_CID,
                    port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
                },
            ),
        ))
    }

    /// 017-005's precondition: the mode decides the provider, in one place,
    /// and each provider plans what its mode states.
    #[tokio::test]
    async fn every_mode_gets_its_provider() {
        let switch = counting_switch();

        let host = network_for(NetworkMode::HostNet, &switch, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert!(!host.isolates_netns());
        // The fixture's switch is a `HostShuttle` — a VM host — so the
        // host-address box resolves through the node's DNS layer, not the
        // host's own resolver (NET-003; the native case is
        // `host_min_internal_resolves_to_host_reach_address_per_mode`).
        assert_eq!(
            host.resolver(),
            &Resolver::Nameservers(vec![crate::net::SwitchSubnet::default().dns_server()])
        );

        let no_net = network_for(NetworkMode::NoNet, &switch, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert!(no_net.isolates_netns() && no_net.tap().is_none());
        assert_eq!(no_net.resolver(), &Resolver::None);

        let own_ip = network_for(NetworkMode::OwnIp, &switch, "s", None, None, None, None);
        assert!(own_ip.plan().await.unwrap().isolates_netns());
        assert_eq!(switch.lock().await.attached(), 1, "own-IP takes a lease");
        own_ip.abandon().await;
        assert_eq!(switch.lock().await.attached(), 0);
    }

    /// The privileged tap is used where the daemon is privileged by deployment,
    /// and nowhere else.
    #[test]
    fn the_control_channel_decides_the_tap_mechanism() {
        assert_eq!(
            tap_mechanism(&ControlChannel::Vsock { cid: 2, port: 1024 }),
            TapMechanism::Privileged
        );
        assert_eq!(
            tap_mechanism(&ControlChannel::Unix("/run/gvproxy.sock".into())),
            TapMechanism::InNamespace
        );
    }

    /// The plan asks the sandbox layer for a tap only when the sandbox layer
    /// builds it: in the x86_64 KVM guest, asking RustSlirp for one it cannot
    /// build destroys the container supervisor.
    #[test]
    fn the_plan_asks_for_a_tap_only_where_the_sandbox_builds_one() {
        let subnet = crate::net::SwitchSubnet::default();
        let ip = std::net::Ipv4Addr::new(100, 64, 0, 9);

        let rootless = own_ip_plan(subnet, ip, TapMechanism::InNamespace);
        let privileged = own_ip_plan(subnet, ip, TapMechanism::Privileged);
        assert!(rootless.tap().is_some());
        assert!(
            privileged.tap().is_none(),
            "the daemon builds this one itself"
        );
        // The mechanism decides who makes the tap, not what the PTask gets.
        assert!(privileged.isolates_netns() && rootless.isolates_netns());
        assert_eq!(privileged.resolver(), rootless.resolver());
    }

    /// T94, NET-016: a VM host's privileged-tap plan carries no tap, so the
    /// listen watcher's lease comes from the attach's report — without it a
    /// VM box gets no listen plan, and no listen of its ever publishes.
    #[test]
    fn a_privileged_tap_box_reads_its_lease_from_the_attach_report() {
        let subnet = crate::net::SwitchSubnet::default();
        let lease = std::net::Ipv4Addr::new(100, 64, 128, 5);
        let registry = Arc::new(RwLock::new(crate::net::dns::HostnameRegistry::new(
            "dev", false,
        )));
        let reporter = OwnAddressReporter::new(registry, SessionId::nil());
        let privileged = own_ip_plan(subnet, lease, TapMechanism::Privileged);

        assert_eq!(
            attached_lease(&privileged, Some(&reporter)),
            None,
            "nothing is reported before the attach"
        );
        reporter.report("vm-box", lease, BTreeMap::new());
        assert_eq!(
            attached_lease(&privileged, Some(&reporter)),
            Some(lease),
            "the privileged plan has no tap, so the attach's reported lease is the box's"
        );
        let rootless = own_ip_plan(subnet, lease, TapMechanism::InNamespace);
        assert_eq!(attached_lease(&rootless, None), Some(lease));
        assert_eq!(attached_lease(&NetPlan::isolated(), None), None);
    }

    /// 017-009 and 017-006 for own-IP: the PTask gets its own namespace and
    /// one tap addressed with its lease, routed and resolving at the switch.
    #[test]
    fn own_ip_resolver_points_at_the_switch() {
        let subnet = crate::net::SwitchSubnet::default();
        let lease = std::net::Ipv4Addr::new(100, 64, 0, 7);
        let plan = own_ip_plan(subnet, lease, TapMechanism::InNamespace);

        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()])
        );
        // gvproxy answers DNS on the gateway; two accessors that could drift.
        assert_eq!(subnet.dns_server(), subnet.gateway());

        assert!(plan.isolates_netns());
        let tap = plan.tap().expect("own-IP gets a tap");
        assert_eq!(tap.address, lease);
        assert_eq!(tap.netmask, subnet.netmask());
        assert_eq!(tap.gateway, subnet.gateway());
        assert_eq!(tap.mtu, crate::net::DEFAULT_MTU);
    }

    /// 017-008. A launch whose attach fails leaves the switch's attachment
    /// count where it was: decremented once, not zero times and not twice.
    #[tokio::test]
    async fn failed_attach_releases_the_switch_once() {
        let switch = counting_switch();
        let before = switch.lock().await.attached();

        let net = network_for(NetworkMode::OwnIp, &switch, "s", None, None, None, None);
        net.plan().await.expect("planning leases an address");
        assert_eq!(switch.lock().await.attached(), before + 1);

        // A pid that cannot exist, so `privileged_tap`'s namespace check
        // refuses before anything is created (`counting_switch` is
        // `HostShuttle`, so this is the privileged mechanism).
        assert!(net.attach(Spawned::new(u32::MAX)).await.is_err());

        // The sandbox layer runs `abandon` on exactly this path.
        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            before,
            "a failed attach must give the lease back"
        );
        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            before,
            "an abandon with nothing reserved is a no-op"
        );
    }

    /// 017-N01, stated structurally: the switch is free once a plan returns,
    /// and four launches hold four leases at once. Whether the 2x bound holds
    /// in time is the measurement spec 017 still asks for.
    #[tokio::test]
    async fn concurrent_own_ip_launches_do_not_serialize() {
        let switch = counting_switch();
        let launches: Vec<_> = (0..4)
            .map(|i| {
                network_for(
                    NetworkMode::OwnIp,
                    &switch,
                    &format!("p{i}"),
                    None,
                    None,
                    None,
                    None,
                )
            })
            .collect();
        for net in &launches {
            net.plan().await.expect("planning leases an address");
            assert!(
                switch.try_lock().is_ok(),
                "the switch must be free between a plan and its attach"
            );
        }
        assert_eq!(switch.lock().await.attached(), 4);
        for net in &launches {
            net.abandon().await;
        }
        assert_eq!(switch.lock().await.attached(), 0);
    }

    /// NET-003: on a VM host the namespace a host-address box shares is the
    /// guest's, so it resolves `host.min.internal` through the node's DNS layer
    /// — the switch gateway — never through the host's own resolver and never
    /// from an `/etc/hosts` entry that would shadow the node's answer.
    #[tokio::test]
    async fn host_ip_box_resolves_through_node_dns_layer() {
        let subnet = crate::net::SwitchSubnet::default();
        let switch = counting_switch();
        let plan = network_for(NetworkMode::HostNet, &switch, "s", None, None, None, None)
            .plan()
            .await
            .expect("host-address plans do not fail");

        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "the resolver is the node's DNS layer, the switch gateway"
        );
        assert!(
            plan.hosts().is_empty(),
            "no /etc/hosts entry may shadow the node's answer"
        );

        // The same DNS layer an own-address box on the same host resolves
        // through: one switch, one zone, one answer for the host.
        let own = own_ip_plan(
            subnet,
            std::net::Ipv4Addr::new(100, 64, 0, 9),
            TapMechanism::InNamespace,
        );
        assert_eq!(plan.resolver(), own.resolver());
    }

    /// NET-079 natively: over a table that decides per box, a deny-all box's
    /// plan follows the live answerer bind — its resolver is the bind's own
    /// address while the table's recorded carve-out names that bind, and the
    /// plan refuses the box as a stale carve-out once it does not. A box that
    /// is not deny-all is unaffected.
    #[tokio::test]
    #[serial_test::serial]
    async fn carve_out_targets_live_answerer_bind_in_the_box_plan() {
        use crate::net::classifier::{Decision, clear_live_answerer, set_live_answerer};

        let deny_all = Some(sessions::SessionPolicy::new(
            Some(sessions::EgressPolicy::deny_all()),
            None,
        ));
        let native = Arc::new(Mutex::new(SwitchClient::new(
            "/usr/bin/gvproxy",
            "/run/minimal/gvproxy",
        )));
        let recorded = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 7656);
        let decision = Decision::decided().with_carve_out(Some(recorded));
        let plan = |policy| {
            network_for(
                NetworkMode::HostNet,
                &native,
                "s",
                policy,
                None,
                None,
                Some(decision.clone()),
            )
        };

        set_live_answerer(std::net::SocketAddr::V4(recorded));
        let live = plan(deny_all.clone())
            .plan()
            .await
            .expect("a carve-out naming the live bind plans the box");
        assert_eq!(
            live.resolver(),
            &Resolver::Nameservers(vec![*recorded.ip()]),
            "the resolver is the live bind's address"
        );

        set_live_answerer(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            7700,
        ));
        let stale = plan(deny_all.clone()).plan().await;
        let refusal = stale.expect_err("a carve-out naming another bind is stale");
        assert!(
            refusal.to_string().contains("stale carve-out"),
            "the plan refuses the box as a stale carve-out: {refusal}"
        );

        clear_live_answerer();
        assert!(
            plan(deny_all).plan().await.is_err(),
            "no live answerer refuses the deny-all box"
        );
        assert!(
            plan(None).plan().await.is_ok(),
            "a box that is not deny-all is unaffected"
        );
    }

    /// NET-079: on a native host, a deny-all host-address box resolves through
    /// the box zone's answerer — the resolver Minimal owns for it, the one
    /// destination its connections are admitted to — never through the host's
    /// own resolver, which forwards any name upstream and would hand the box
    /// everything outside through that one carve-out. A box that is not
    /// deny-all keeps the host's resolver, and a deny-all box on a VM host
    /// keeps the node's DNS layer: the answerer is this host's loopback, which
    /// a box in the guest's namespace has no reach into.
    #[tokio::test]
    async fn host_ip_box_resolves_through_answerer() {
        let deny_all = Some(sessions::SessionPolicy::new(
            Some(sessions::EgressPolicy::deny_all()),
            None,
        ));
        let native = Arc::new(Mutex::new(SwitchClient::new(
            "/usr/bin/gvproxy",
            "/run/minimal/gvproxy",
        )));

        let plan = network_for(
            NetworkMode::HostNet,
            &native,
            "s",
            deny_all.clone(),
            None,
            None,
            None,
        )
        .plan()
        .await
        .expect("host-address plans do not fail");
        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![crate::net::classifier::ANSWERER_ADDRESS]),
            "a native deny-all box resolves through the zone's answerer"
        );
        assert_ne!(
            plan.resolver(),
            &Resolver::Host,
            "never through the host's own resolver: it forwards any name upstream"
        );

        // The carve-out the table itself enforces for that resolver: the
        // installer's rendered table retargets the deny subtree's DNS
        // lookups — the one port a box cannot be refused on, or nothing it
        // asks ever resolves — onto the answerer's address and port, so the
        // one destination a deny-all box's connections are admitted to is
        // the one its resolver really is. Read off the step's own
        // `--print-ruleset` output, so what is pinned is what a host loads.
        // 53 is DNS, spelled here because the constant that owns it
        // (`dns_gate::DNS_PORT`) is private to its module.
        let ruleset = crate::net::classifier::rendered_ruleset();
        let dstnat = crate::net::classifier::chain_rules(&ruleset, "dstnat");
        let dnat = format!(
            "socket cgroupv2 level 3 \"minimald.slice/boxes/deny\" \
             ip daddr {} udp dport 53 dnat ip to {}:{}",
            crate::net::classifier::ANSWERER_ADDRESS,
            crate::net::classifier::ANSWERER_ADDRESS,
            crate::net::answerer::ANSWERER_PORT,
        );
        assert_eq!(
            dstnat,
            [dnat.as_str()],
            "the table retargets the deny subtree's DNS onto the answerer, and \
             does nothing else at dstnat: the carve-out is one DNAT rule"
        );

        // A box that is not deny-all inherits the host's resolver: no verdict
        // of its own, no carve-out to be routed through.
        let plain = network_for(NetworkMode::HostNet, &native, "s", None, None, None, None)
            .plan()
            .await
            .expect("host-address plans do not fail");
        assert_eq!(plain.resolver(), &Resolver::Host);

        // On a VM host the deny verdict alone changes nothing here: the
        // namespace the box shares is the guest's, and — with no decision
        // carried in — nothing decides per box, so the node's DNS layer
        // answers it. The decided case is the test below.
        let vm = counting_switch();
        let guest_plan = network_for(NetworkMode::HostNet, &vm, "s", deny_all, None, None, None)
            .plan()
            .await
            .expect("host-address plans do not fail");
        assert_eq!(
            guest_plan.resolver(),
            &Resolver::Nameservers(vec![crate::net::SwitchSubnet::default().dns_server()]),
            "a VM host's deny-all box resolves through the node's DNS layer"
        );
    }

    /// NET-079 on a VM host: the plan a deny-all host-address box gets follows
    /// its launch's own decision — a guest that decided per box gives the box
    /// no resolver, because the guest's table renders no resolver carve-out
    /// (follow-up gominimal/inbox#897); a guest that decided nothing —
    /// a boot whose check or load failed, a table gone behind its marker, a
    /// probe that read no refusal — keeps the node's DNS layer, exactly as
    /// before it could decide. The decision is a parameter the launch passes
    /// in, the very value its own reader read: the same box on the same host
    /// follows whichever decision its own launch hands the plan, a later
    /// launch can never read an earlier one's in its place, and a box that
    /// is not deny-all needs no carve-out enforced, so no decision changes
    /// its resolver.
    #[tokio::test]
    async fn guest_deny_all_renders_no_resolver_carve_out_in_the_box_plan() {
        use crate::net::classifier::{Cause, Decision};

        let deny_all = Some(sessions::SessionPolicy::new(
            Some(sessions::EgressPolicy::deny_all()),
            None,
        ));
        let switch = counting_switch();
        let subnet = crate::net::SwitchSubnet::default();
        let plan = |policy, decision| {
            network_for(
                NetworkMode::HostNet,
                &switch,
                "s",
                policy,
                None,
                None,
                decision,
            )
        };

        // Undecided — a launch that read an undecidable cause: the box
        // resolves through the node's DNS layer at the switch gateway, the
        // resolver it had before its guest could decide anything.
        let undecidable = plan(
            deny_all.clone(),
            Some(Decision::undecidable(Cause::GuestTableNotLoaded)),
        )
        .plan()
        .await
        .expect("host-address plans do not fail");
        assert_eq!(
            undecidable.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "a guest that decides nothing keeps the node's DNS layer"
        );

        // Decided per box: the same box gets no resolver — the guest's table
        // carves none out, so there is nothing its lookups may reach.
        let decided = plan(deny_all.clone(), Some(Decision::decided()))
            .plan()
            .await
            .expect("host-address plans do not fail");
        assert_eq!(
            decided.resolver(),
            &Resolver::Nameservers(Vec::new()),
            "a guest that decides per box gives a deny-all box no resolver"
        );

        // A launch that read no decision at all — a plan built before its
        // reader ran, or a task launch, which places no leaf to read one
        // over — decides nothing either.
        let unread = plan(deny_all.clone(), None)
            .plan()
            .await
            .expect("host-address plans do not fail");
        assert_eq!(
            unread.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "a launch that read no decision keeps the node's DNS layer"
        );

        // The decision is the launch's own parameter, never a default kept
        // between them: the next launch that reads an undecidable decision
        // falls back again, with no earlier launch's decided reading left
        // standing for it to inherit.
        let again = plan(
            deny_all,
            Some(Decision::undecidable(Cause::GuestTableNotLoaded)),
        )
        .plan()
        .await
        .expect("host-address plans do not fail");
        assert_eq!(
            again.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "the decision is read per launch: a later undecidable reading \
             falls back to the node's DNS layer"
        );

        // And the gate is the decision over a verdict that needs one: a box
        // that is not deny-all runs unenforced whatever the host decided, so
        // its resolver is the node's either way.
        let plain = plan(None, Some(Decision::decided()))
            .plan()
            .await
            .expect("host-address plans do not fail");
        assert_eq!(
            plain.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "a box that is not deny-all has no carve-out to resolve through, \
             decided or not"
        );
    }

    /// NET-079's cgroup half, as the provider selects it: a host-address box's
    /// leaf is one level under the subtree its verdict picked — deny or allow
    /// — never directly under the cohort, where the refusing rule's level
    /// arithmetic would silently miss it and the box would run unenforced
    /// while looking classified.
    #[test]
    fn host_ip_box_cannot_leave_its_cgroup() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();
        let cohort = root.join(sandbox2::classifier::BOXES_DIR);
        let deny = cohort.join(sandbox2::config::DENY_DIR);
        let allow = cohort.join(sandbox2::config::ALLOW_DIR);

        for (declaration, expected, why) in [
            (
                Some(sessions::EgressPolicy::deny_all()),
                sandbox2::config::Verdict::Deny,
                "a deny-all box",
            ),
            (
                None,
                sandbox2::config::Verdict::Allow,
                "a box with no egress section",
            ),
        ] {
            // The subtree the declaration picks is the one the leaf is placed
            // in — the same selection the launch's own placement makes.
            let verdict = host_address_verdict(declaration.as_ref());
            assert_eq!(verdict, expected, "{why} is classified by its declaration");
            let leaf = sandbox2::config::ClassifierLeaf::under(root, "a session", verdict);
            assert_eq!(
                leaf.dir().parent().and_then(std::path::Path::parent),
                Some(cohort.as_path()),
                "{why}'s leaf is one level under its subtree, one level under \
                 the cohort: {}",
                leaf.dir().display()
            );
            assert_eq!(
                leaf.dir().parent(),
                Some(match verdict {
                    sandbox2::config::Verdict::Deny => deny.as_path(),
                    sandbox2::config::Verdict::Allow => allow.as_path(),
                }),
                "{why}'s leaf is in the subtree its verdict picked"
            );
            assert!(
                leaf.dir().parent() != Some(cohort.as_path()),
                "no host-address leaf sits directly under the cohort: the deny \
                 rule's match is on the subtree, and a leaf beside it is \
                 outside both subtrees ({})",
                leaf.dir().display()
            );
        }

        // And the two subtrees are what the leaf is decided between: a
        // deny-all box's leaf is in the deny subtree and no other box's is in
        // it, the same arithmetic the refusing rule and the cohort's source
        // identity are keyed on.
        let deny_all = sandbox2::config::ClassifierLeaf::under(
            root,
            "a session",
            sandbox2::config::Verdict::Deny,
        );
        assert_eq!(
            deny_all.relative_dir(),
            std::path::PathBuf::from(sandbox2::classifier::BOXES_DIR)
                .join(sandbox2::config::DENY_DIR)
                .join(sandbox2::classifier::sanitize_box_id("a session")),
            "the leaf's in-box spelling keeps the whole subtree path"
        );
    }

    /// NET-003 for every box kind: `host.min.internal` answers with the address
    /// that reaches the host's loopback — `127.0.0.1` from `/etc/hosts` for a
    /// box sharing the native host's namespace, the switch gateway's DNS zone
    /// for own-address boxes and for host-address boxes on a VM host.
    #[tokio::test]
    async fn host_min_internal_resolves_to_host_reach_address_per_mode() {
        let subnet = crate::net::SwitchSubnet::default();

        // Native host-address: `/etc/hosts` at the host's loopback, because the
        // host's own resolver has no `min.internal.` zone to answer from.
        let native = Arc::new(Mutex::new(SwitchClient::new(
            "/usr/bin/gvproxy",
            "/run/minimal/gvproxy",
        )));
        let plan = network_for(NetworkMode::HostNet, &native, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert_eq!(plan.resolver(), &Resolver::Host);
        assert_eq!(plan.hosts().len(), 1, "one static entry for the host");
        let entry = &plan.hosts()[0];
        assert_eq!(entry.name, sandbox2::HOST_MIN_INTERNAL);
        assert_eq!(
            entry.address,
            std::net::Ipv4Addr::LOCALHOST,
            "the name answers at the host's loopback"
        );

        // VM-host host-address: the node's DNS layer answers the same name.
        let vm = counting_switch();
        let plan = network_for(NetworkMode::HostNet, &vm, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.gateway()])
        );

        // Own-address (the plan is transport-independent): the same gateway,
        // whose static zone answers the name with the NAT'd host-alias address.
        let own = own_ip_plan(
            subnet,
            std::net::Ipv4Addr::new(100, 64, 0, 9),
            TapMechanism::InNamespace,
        );
        assert_eq!(
            own.resolver(),
            &Resolver::Nameservers(vec![subnet.gateway()])
        );
        assert!(
            own.hosts().is_empty(),
            "own-address boxes resolve the host through the zone, not /etc/hosts"
        );
    }
}
