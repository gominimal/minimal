//! One function that reads a PTask's network mode, and the own-IP provider it
//! returns. Every sandbox consumer in the daemon calls [`network_for`], and
//! nothing else reads the mode. The gvproxy **process** belongs to the
//! daemon-scoped [`SwitchClient`] (DM2) or to `minvmd` (DM1/3/4); this only
//! leases from it and wires a running switch into a sandbox's namespace.

use std::sync::Arc;

use sandbox2::{
    AbandonFuture, AttachFuture, NetGuard, NetPlan, Network, NetworkError, PlanFuture, Resolver,
    Spawned, TapSpec,
};
use sessions::NetworkMode;
use tokio::sync::Mutex;

use crate::net::policy::{ControlChannel, HostReach};
use crate::net::{SwitchClient, SwitchSubnet, SwitchTransport};

/// The network provider for `mode`. `NoNet` is the sandbox layer's own;
/// `HostNet` shares the host's namespace but still has its resolver to decide
/// (NET-003), and `OwnIp` needs a lease, a tap and a switch attach. An
/// unrecognised mode (`NetworkMode` is `#[non_exhaustive]`) gets the empty
/// namespace, the safe direction.
pub(crate) fn network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: &str,
    ingress: Option<sessions::IngressPolicy>,
    egress: Option<sessions::EgressPolicy>,
) -> Arc<dyn Network> {
    match mode {
        NetworkMode::HostNet => Arc::new(HostNetNetwork {
            switch: Arc::clone(switch),
        }),
        NetworkMode::OwnIp => Arc::new(OwnIpNetwork {
            switch: Arc::clone(switch),
            identity: identity.to_string(),
            ingress,
            egress,
            reserved: std::sync::Mutex::new(None),
        }),
        _ => Arc::new(sandbox2::NoNet),
    }
}

/// Which reach `mode` gives a box on a switch reached by `transport` — its route
/// to the host's loopback, and so the address `host.min.internal` answers it
/// (NET-003). `None` for a mode with no route to the host at all.
///
/// The transport is the same signal [`tap_mechanism`] reads: a `HostShuttle`
/// switch belongs to a node inside a VM, where even a host-address box sharing
/// that node's namespace reaches the host across the switch. Both enums are
/// `#[non_exhaustive]`, so an unrecognised pairing promises nothing rather than
/// guessing an address that does not reach the host.
pub(crate) fn host_reach(mode: NetworkMode, transport: SwitchTransport) -> Option<HostReach> {
    match (mode, transport) {
        (NetworkMode::HostNet, SwitchTransport::LocalSpawn) => Some(HostReach::SharedNamespace),
        (NetworkMode::HostNet, SwitchTransport::HostShuttle { .. }) => Some(HostReach::Switch),
        (NetworkMode::OwnIp, _) => Some(HostReach::Switch),
        _ => None,
    }
}

/// A host-address box: it shares the host's (or its node's) network namespace, so
/// there is nothing to reserve and nothing to wire after the spawn. What it does
/// need decided is its resolver, which [`host_net_plan`] reads from the switch.
struct HostNetNetwork {
    switch: Arc<Mutex<SwitchClient>>,
}

impl std::fmt::Debug for HostNetNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostNetNetwork").finish_non_exhaustive()
    }
}

impl Network for HostNetNetwork {
    /// Reads the switch to learn which host this is — nothing is reserved, and
    /// the default no-op `attach`/`abandon` stand.
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(async move {
            let (transport, subnet) = {
                let switch = self.switch.lock().await;
                (switch.transport(), switch.subnet())
            };
            Ok(host_net_plan(subnet, transport))
        })
    }
}

/// The plan a host-address box launches with: the host's namespace, and the
/// resolver its reach implies (NET-003). Pure, so both hosts are testable
/// without a switch.
///
/// Inside a VM-backed host the host's own resolver is not this box's to use: it
/// sits on the far side of the switch, and `Resolver::Host` would leave the box
/// with whatever its rootfs shipped or a synthesized copy of the node's file. The
/// node's DNS layer — gvproxy, answering at the switch gateway — is what answers
/// the box zone and forwards what the box may resolve, so it is named outright.
fn host_net_plan(subnet: SwitchSubnet, transport: SwitchTransport) -> NetPlan {
    let resolver = match host_reach(NetworkMode::HostNet, transport) {
        Some(HostReach::Switch) => Resolver::Nameservers(vec![subnet.dns_server()]),
        // A native host: the box shares the host's namespace, and its resolver
        // with it.
        _ => Resolver::Host,
    };
    NetPlan::host().with_resolver(resolver)
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
/// the sandbox starts, then relays the sandbox's own tap onto that switch and
/// applies its static ingress forwards (R1.5/R2.3).
struct OwnIpNetwork {
    switch: Arc<Mutex<SwitchClient>>,
    /// Registered as the PTask's `*.min.internal` hostname on attach (R3.1).
    identity: String,
    /// Static ingress port mappings to apply once attached.
    ingress: Option<sessions::IngressPolicy>,
    /// The box's declared egress rules, enforced on its relay from the moment
    /// it attaches (NET-062 to NET-064); `None` (no `egress` section) allows
    /// every destination, while the source check (NET-084) always applies.
    egress: Option<sessions::EgressPolicy>,
    /// Taken by `plan`, taken back out by `attach` or `abandon`. A `std` mutex,
    /// never held across an await, so a cancelled launch cannot leak it.
    reserved: std::sync::Mutex<Option<Reserved>>,
}

impl std::fmt::Debug for OwnIpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnIpNetwork")
            .field("identity", &self.identity)
            .field("has_ingress", &self.ingress.is_some())
            .finish_non_exhaustive()
    }
}

impl Network for OwnIpNetwork {
    /// Lease an address and make sure the switch is up, then describe the tap
    /// the sandbox layer should build. Before the process starts, because the
    /// sandbox layer assigns the address as it creates the tap.
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(async move {
            let (lease, control, subnet) = {
                let mut s = self.switch.lock().await;
                let subnet = s.subnet();
                let attach = s.attach().await.map_err(NetworkError::new)?;
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

            // The frame verdict's inputs, owned and parsed once here: the
            // lease it must send from, its declared rules, and the resolver
            // carve-out at the switch's DNS address (design §4.1).
            let egress = Arc::new(crate::net::switch::EgressGate::for_box(
                self.identity.clone(),
                sessions::core::net_verdict::EgressRules::for_box(
                    reserved.lease.ip,
                    self.egress.as_ref(),
                    Some(sessions::core::net_verdict::Endpoint {
                        ip: reserved.subnet.dns_server(),
                        port: 53,
                    }),
                ),
            ));
            let guard = crate::net::gvproxy_network::complete_own_ip_attach(
                crate::net::gvproxy_network::OwnIpAttach {
                    switch: &self.switch,
                    tap_fd,
                    control: reserved.control,
                    lease_ip: reserved.lease.ip,
                    subnet: reserved.subnet,
                    session_name: &self.identity,
                    ingress: self.ingress.as_ref(),
                    egress,
                },
            )
            .await
            .map_err(NetworkError::new)?;
            // Committed: the guard owns the release from here.
            self.reserved.lock().unwrap().take();
            Ok(Box::new(guard) as Box<dyn NetGuard>)
        })
    }

    /// Give the lease back; the sandbox layer runs this on every path out of a
    /// launch that does not reach `attach`.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(async move {
            let reserved = self.reserved.lock().unwrap().take();
            if reserved.is_none() {
                // The plan failed or an attach took it; detaching anyway would
                // decrement the switch's count below the truth.
                return;
            }
            if let Err(e) = self.switch.lock().await.detach().await {
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

        let host = network_for(NetworkMode::HostNet, &switch, "s", None, None)
            .plan()
            .await
            .unwrap();
        assert!(!host.isolates_netns());
        // This switch belongs to a node inside a VM, where a host-address box
        // resolves through the node's DNS layer (NET-003);
        // `host_ip_box_resolves_through_node_dns_layer` covers both hosts.
        assert_eq!(
            host.resolver(),
            &Resolver::Nameservers(vec![crate::net::SwitchSubnet::default().dns_server()])
        );

        let no_net = network_for(NetworkMode::NoNet, &switch, "s", None, None)
            .plan()
            .await
            .unwrap();
        assert!(no_net.isolates_netns() && no_net.tap().is_none());
        assert_eq!(no_net.resolver(), &Resolver::None);

        let own_ip = network_for(NetworkMode::OwnIp, &switch, "s", None, None);
        assert!(own_ip.plan().await.unwrap().isolates_netns());
        assert_eq!(switch.lock().await.attached(), 1, "own-IP takes a lease");
        own_ip.abandon().await;
        assert_eq!(switch.lock().await.attached(), 0);
    }

    /// NET-038. `network_for` must route `NoNet` to its isolating, tapless
    /// plan regardless of what a caller passes for identity or ingress — a
    /// `none` PTask never picks up wiring meant for another mode. That plan
    /// is what leaves the sandbox with only a down `lo`
    /// ([`sandbox2::NoNet`]'s `no_net_plan_isolates_netns`), which is what
    /// refuses every socket it opens to the outside.
    #[tokio::test]
    async fn network_none_blocks_all_outside_sockets() {
        let switch = counting_switch();
        let ingress = Some(sessions::IngressPolicy {
            port_mappings: vec![sessions::PortMapping {
                external_port: 8080,
                internal_port: 80,
                proto: sessions::IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        });

        let plan = network_for(NetworkMode::NoNet, &switch, "some-session", ingress, None)
            .plan()
            .await
            .unwrap();

        assert!(
            plan.isolates_netns(),
            "a none box must run in its own empty network namespace"
        );
        assert!(
            plan.tap().is_none(),
            "a none box gets no tap to relay outside traffic through"
        );
        assert_eq!(
            plan.resolver(),
            &Resolver::None,
            "no resolver reaches an isolated box"
        );
    }

    /// NET-003's VM-backed clause: inside a VM-backed host a host-address box's
    /// lookups go to the node's DNS layer — gvproxy, answering at the switch
    /// gateway — and never to the host's own resolver, which `Resolver::Host`
    /// would otherwise leave it with (or leave to whatever its rootfs shipped).
    /// On a native host the box keeps sharing the host's resolver.
    #[tokio::test]
    async fn host_ip_box_resolves_through_node_dns_layer() {
        let subnet = crate::net::SwitchSubnet::default();

        // A node's switch inside a VM: taps reach the host gvproxy over the
        // vsock shuttle.
        let vm_backed = counting_switch();
        let plan = network_for(NetworkMode::HostNet, &vm_backed, "s", None, None)
            .plan()
            .await
            .unwrap();
        assert!(
            !plan.isolates_netns(),
            "a host-address box keeps the node's namespace"
        );
        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "the node's DNS layer, named outright"
        );
        assert_ne!(
            plan.resolver(),
            &Resolver::Host,
            "never the host's own resolver"
        );
        // That nameserver *is* the node's DNS layer: gvproxy answers DNS on the
        // switch gateway.
        assert_eq!(subnet.dns_server(), subnet.gateway());
        // And sharing a namespace takes no lease: nothing is attached.
        assert_eq!(vm_backed.lock().await.attached(), 0);

        // A native host: the box shares the host's namespace, and its resolver.
        let native = Arc::new(Mutex::new(SwitchClient::new(
            "/usr/bin/gvproxy",
            "/run/minimal/gvproxy",
        )));
        assert_eq!(
            native.lock().await.transport(),
            crate::net::SwitchTransport::LocalSpawn
        );
        let plan = network_for(NetworkMode::HostNet, &native, "s", None, None)
            .plan()
            .await
            .unwrap();
        assert_eq!(plan.resolver(), &Resolver::Host);
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

        let net = network_for(NetworkMode::OwnIp, &switch, "s", None, None);
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
            .map(|i| network_for(NetworkMode::OwnIp, &switch, &format!("p{i}"), None, None))
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
}
