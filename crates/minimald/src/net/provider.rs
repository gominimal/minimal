//! One function that reads a PTask's network mode, and the own-IP provider it
//! returns.
//!
//! Before this, the session host read the mode, computed the tap parameters,
//! held the rollback guard for the switch attachment and did the descriptor
//! transfer — all above the sandbox layer, and all reachable only from the
//! interactive-session path. A task, which is a PTask too, went through none of
//! it. [`network_for`] is the one place that reads the mode now, and every
//! sandbox consumer calls it.
//!
//! The provider keeps the deployment-model ownership rule (03-spec-networking
//! R1.4): the gvproxy **process** belongs to the daemon-scoped [`SwitchClient`]
//! (DM2) or to `minvmd` on the host (DM1/3/4). This only leases from it and
//! wires an already-running switch into a sandbox's namespace.

use std::sync::Arc;

use sandbox2::{
    AbandonFuture, AttachFuture, NetGuard, NetPlan, Network, NetworkError, PlanFuture, Resolver,
    Spawned, TapSpec,
};
use sessions::NetworkMode;
use tokio::sync::Mutex;

use crate::net::SwitchClient;
use crate::net::policy::ControlChannel;

/// The network provider for `mode`, or `None` for a mode the sandbox layer's
/// built-in handling already covers.
///
/// `NoNet` and `HostNet` need nothing from the daemon: they are an isolation
/// decision and no post-spawn work, which the sandbox layer makes from the mode
/// itself. `OwnIp` needs a lease, a tap and a switch attach, which is the
/// provider below.
///
/// `NetworkMode` is `#[non_exhaustive]`, so an unrecognised mode gets no
/// provider rather than a guess. That is the safe direction: the sandbox layer
/// fails closed on a mode it cannot isolate, where a guessed provider could
/// hand out access the mode never promised.
pub(crate) fn network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: &str,
    ingress: Option<sessions::IngressPolicy>,
) -> Option<Arc<dyn Network>> {
    match mode {
        NetworkMode::OwnIp => Some(Arc::new(OwnIpNetwork {
            switch: Arc::clone(switch),
            identity: identity.to_string(),
            ingress,
            reserved: Mutex::new(None),
        })),
        _ => None,
    }
}

/// Who builds the tap an own-IP PTask needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TapMechanism {
    /// The sandbox layer builds it *inside* the PTask's own network namespace,
    /// rootless, and hands the descriptor out — 03-spec-networking R1.5, and
    /// what every deployment model is meant to use.
    InNamespace,
    /// The daemon builds it in its own namespace under `CAP_NET_ADMIN` and moves
    /// it in with `ip`. The older mechanism, kept for the one deployment model
    /// where the first does not work; see [`tap_mechanism`].
    Privileged,
}

/// Which mechanism builds this PTask's tap, decided once, from the deployment
/// model the control channel identifies.
///
/// R1.5 wants one mechanism everywhere, and `InNamespace` is it: rootless, and
/// the only option on a native host, where the daemon has no `CAP_NET_ADMIN` to
/// make a tap with. It works there and in the aarch64 libkrun guest.
///
/// It does not work in the x86_64 KVM guest. Asking hakoniwa's RustSlirp for a
/// tap there yields no descriptor *and* takes the container supervisor with it:
/// the KVM lane caught `ip link set mtap0_2 netns 103` reporting `Invalid
/// "netns" value` with `/proc/103/ns/net present: false` — the sandbox was
/// already gone. So this is a choice made before the sandbox starts, not a
/// fallback after it fails: by the time a failure is visible there is no
/// namespace left to put a tap into.
///
/// Narrow on purpose. `Privileged` execs `ip`/`nsenter` with `CAP_NET_ADMIN`,
/// which is exactly the privilege the in-namespace tap exists to avoid (R3.4's
/// no-root direction), so it is offered only where the daemon already holds that
/// privilege as a matter of deployment — inside a microVM whose network it owns,
/// reached over vsock — and never on a native host, where an unprivileged daemon
/// must fail loudly instead of failing again one layer down.
fn tap_mechanism(control: &ControlChannel) -> TapMechanism {
    match control {
        // DM1/3/4: minimald is root in a guest whose network it owns outright.
        ControlChannel::Vsock { .. } => TapMechanism::Privileged,
        // DM2: the daemon is unprivileged by design, and the rootless mechanism
        // is proven here.
        //
        // No catch-all arm: a new transport must decide this deliberately, and
        // the compiler is the only thing that will insist.
        ControlChannel::Unix(_) => TapMechanism::InNamespace,
    }
}

/// The plan an own-IP PTask needs, given its switch subnet, its lease, and who
/// is building its tap.
///
/// Pure, so the values a PTask's namespace ends up configured with are testable
/// without a running switch — which is the whole of what the sandbox layer acts
/// on.
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
            // Must match the relay's frame buffer, or frames the switch sends
            // get truncated on the way into the namespace.
            mtu: crate::net::DEFAULT_MTU,
        }),
        // A namespace and nothing in it: the daemon puts the tap there itself,
        // after the process exists. Asking the sandbox layer for a tap it cannot
        // build is not free — in the guest where that is true it destroys the
        // namespace this depends on.
        TapMechanism::Privileged => NetPlan::isolated(),
    };
    // The switch answers DNS at the gateway. A fresh netns cannot reach the
    // host's stub resolver, so naming it here is what keeps an own-IP PTask able
    // to resolve anything at all (R3.1). True of both mechanisms: the resolver
    // is written into the sandbox's rootfs, not onto its tap.
    plan.with_resolver(Resolver::Nameservers(vec![subnet.dns_server()]))
}

/// Creates a tap in the daemon's own network namespace, moves it into the
/// PTask's, and configures it there — the [`TapMechanism::Privileged`] path.
async fn privileged_tap(
    lease: crate::net::PtaskLease,
    subnet: crate::net::SwitchSubnet,
    netns_pid: u32,
) -> std::io::Result<std::os::fd::OwnedFd> {
    // Check the destination before making anything. A tap created for a
    // namespace that is already gone cannot be moved and cannot be cleaned up
    // through the fd either — it is left in the daemon's own namespace, holding
    // its name, so the next PTask with that lease collides with a device nobody
    // owns. This is not hypothetical: it is what the KVM lane did, and the
    // orphaned `mtap0_2` is why its error named a device that already existed.
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
    // A locally-administered name unique within the switch /16 — its low two
    // octets distinguish every PTask address — and within the 15-char
    // `IFNAMSIZ` limit (`mtapNNN_NNN` is at most 11 chars).
    let o = lease.ip.octets();
    let tap = format!("mtap{}_{}", o[2], o[3]);
    let tap_fd = crate::net::switch::open_tap(&tap)?;
    crate::net::switch::move_tap_into_netns(&tap, netns_pid, lease, subnet).await?;
    Ok(tap_fd)
}

/// What [`OwnIpNetwork::plan`] reserved, waiting for an attach or an abandon.
#[derive(Debug, Clone)]
struct Reserved {
    /// The full lease, not just its address: the privileged fallback needs the
    /// MAC too, to configure a tap it made itself.
    lease: crate::net::PtaskLease,
    /// Carried for the same reason — the fallback renders the lease as CIDR.
    subnet: crate::net::SwitchSubnet,
    /// gvproxy's control channel: a local socket on DM2, host vsock on DM1/3/4.
    /// The one value the deployment model decides.
    control: ControlChannel,
    /// Who builds the tap, decided with the plan so that `attach` cannot reach a
    /// different conclusion than the plan the sandbox was built from.
    mechanism: TapMechanism,
}

/// An own-IP network: leases an address from the per-host gvproxy switch before
/// the sandbox starts, then relays the sandbox's own tap onto that switch and
/// applies its static ingress forwards (R1.5/R2.3).
struct OwnIpNetwork {
    /// The shared per-host switch (the daemon-scoped process owner / refcounter).
    switch: Arc<Mutex<SwitchClient>>,
    /// The PTask's name, registered as its `*.min.internal` hostname on attach
    /// so peers can resolve it (R3.1 / UC6).
    identity: String,
    /// Static ingress port mappings to apply once attached; `None`/empty for none.
    ingress: Option<sessions::IngressPolicy>,
    /// The lease taken by `plan`, taken back out by whichever of `attach` or
    /// `abandon` runs. `Mutex` because the trait takes `&self` — the sandbox
    /// layer guarantees at most one of those two follows a plan, so this never
    /// contends; it is here to make the handoff, not to arbitrate it.
    reserved: Mutex<Option<Reserved>>,
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
    /// the sandbox layer should build in the PTask's namespace.
    ///
    /// This has to happen before the process starts: the sandbox layer assigns
    /// the address to the tap as it creates it, so the address must already be
    /// known. That is the whole reason the trait needed a pre-spawn operation
    /// that returns data.
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
            *self.reserved.lock().await = Some(Reserved {
                lease,
                subnet,
                control,
                mechanism,
            });
            Ok(own_ip_plan(subnet, lease.ip, mechanism))
        })
    }

    /// Relay the sandbox's tap onto the switch and apply its ingress.
    /// The reservation is **read, not taken**, until the attach has actually
    /// succeeded. A failed attach hands the release back to
    /// [`abandon`](Self::abandon) — the sandbox layer runs it on that path —
    /// and an abandon that found nothing reserved would leak the lease and keep
    /// gvproxy running for a PTask that never came up (012-008).
    fn attach(&self, mut spawned: Spawned) -> AttachFuture<'_> {
        Box::pin(async move {
            let reserved = {
                let reserved = self.reserved.lock().await;
                let Some(r) = reserved.as_ref() else {
                    return Err(NetworkError::new(std::io::Error::other(
                        "own-IP attach without a plan: nothing was leased",
                    )));
                };
                r.clone()
            };

            // The mechanism `plan` chose, and that the sandbox was built for.
            // Not re-decided here: the plan either asked the sandbox layer for a
            // tap or did not, and only the matching branch can succeed.
            let tap_fd = match reserved.mechanism {
                TapMechanism::InNamespace => {
                    let Some(fd) = spawned.take_tap_fd() else {
                        // The sandbox layer was asked for a tap and produced
                        // none. Report what building one in-namespace needs,
                        // because the bare fact is not actionable: which
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
                self.ingress.as_ref(),
            )
            .await
            .map_err(NetworkError::new)?;
            // Committed: the guard owns the release from here, so clear the
            // reservation and let any later abandon find nothing to do.
            self.reserved.lock().await.take();
            Ok(Box::new(guard) as Box<dyn NetGuard>)
        })
    }

    /// Give the lease back. Runs when a launch stops between the plan and the
    /// attach — an early error, or a cancelled launch future.
    ///
    /// This is the rollback the session host used to hold in a drop guard of its
    /// own. It lives here now because this is what reserved the thing being
    /// released, and the sandbox layer runs it on every path out of a launch
    /// that does not reach `attach`.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(async move {
            if self.reserved.lock().await.take().is_none() {
                // Nothing reserved: the plan failed, or an attach already took
                // it. Either way there is nothing to give back, and detaching
                // anyway would decrement the switch's count below the truth.
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

    /// 012-005's precondition: the mode decides the provider, in one place.
    #[test]
    fn only_own_ip_needs_a_provider() {
        // Never started: `network_for` only decides which provider a mode needs,
        // so nothing here touches the switch.
        let switch = Arc::new(Mutex::new(SwitchClient::new(
            "/usr/bin/gvproxy",
            "/run/minimal/gvproxy",
        )));
        assert!(
            network_for(NetworkMode::OwnIp, &switch, "s", None).is_some(),
            "own-IP needs a lease, a tap and a switch attach"
        );
        assert!(
            network_for(NetworkMode::HostNet, &switch, "s", None).is_none(),
            "host-net is the sandbox layer's built-in handling"
        );
        assert!(
            network_for(NetworkMode::NoNet, &switch, "s", None).is_none(),
            "no-net is an isolation decision and no post-spawn work"
        );
    }

    /// The privileged tap is used where the daemon is privileged by deployment,
    /// and nowhere else.
    ///
    /// Getting this backwards is the whole risk of keeping two mechanisms: on a
    /// native host the privileged one would exec `ip` with a `CAP_NET_ADMIN` the
    /// daemon does not have, turning a clear "no tap descriptor" into a
    /// confusing permissions failure one layer further down — and eroding the
    /// no-root property (R3.4) the in-namespace tap exists to provide.
    #[test]
    fn only_the_in_vm_transport_may_fall_back_to_a_privileged_tap() {
        assert_eq!(
            tap_mechanism(&ControlChannel::Vsock { cid: 2, port: 1024 }),
            TapMechanism::Privileged,
            "an in-VM daemon owns its guest's network and makes the tap itself"
        );
        assert_eq!(
            tap_mechanism(&ControlChannel::Unix("/run/gvproxy.sock".into())),
            TapMechanism::InNamespace,
            "a native daemon is unprivileged by design; rootless is the only way"
        );
    }

    /// The plan must ask the sandbox layer for a tap only when the sandbox layer
    /// is the one building it.
    ///
    /// Not a tidiness point. In the x86_64 KVM guest, asking RustSlirp for a tap
    /// it cannot build destroys the container supervisor — `ip link set ... netns
    /// <pid>` then reports `Invalid "netns" value` because `/proc/<pid>/ns/net`
    /// is already gone, and the daemon has nothing left to move a tap into. A
    /// plan that carries tap parameters the deployment model cannot honour is
    /// therefore not a wasted request; it is the failure.
    #[test]
    fn the_plan_asks_for_a_tap_only_where_the_sandbox_builds_one() {
        let subnet = crate::net::SwitchSubnet::default();
        let ip = std::net::Ipv4Addr::new(100, 64, 0, 9);

        let rootless = own_ip_plan(subnet, ip, TapMechanism::InNamespace);
        assert!(
            rootless.tap().is_some(),
            "the sandbox layer is told what tap to build"
        );

        let privileged = own_ip_plan(subnet, ip, TapMechanism::Privileged);
        assert!(
            privileged.tap().is_none(),
            "the daemon builds this one after the process exists; asking the \
             sandbox layer for it is what kills the namespace"
        );

        // Both still isolate, and both still resolve through the switch: the
        // mechanism decides who makes the tap, not what the PTask ends up with.
        assert!(privileged.isolates_netns() && rootless.isolates_netns());
        assert_eq!(privileged.resolver(), rootless.resolver());
    }

    /// 012-009. An own-IP PTask resolves through the switch, not through the
    /// synth rootfs's host stub — which is unreachable from a fresh netns, so a
    /// PTask that inherited it would resolve nothing and have no way to say why.
    #[test]
    fn own_ip_resolver_points_at_the_switch() {
        let subnet = crate::net::SwitchSubnet::default();
        let plan = own_ip_plan(
            subnet,
            std::net::Ipv4Addr::new(100, 64, 0, 7),
            TapMechanism::InNamespace,
        );
        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()]),
            "the resolver must name the switch's DNS server"
        );
        // gvproxy answers DNS on the gateway, so those are the same address —
        // stated here because the two are separate accessors that could drift.
        assert_eq!(subnet.dns_server(), subnet.gateway());
    }

    /// A switch whose attach/detach are pure bookkeeping: `HostShuttle` leaves
    /// the gvproxy process to `minvmd`, so `SwitchClient` spawns nothing and
    /// writes no config — only the count moves, which is what these assert on.
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

    /// 012-008. A launch whose attach fails leaves the switch's attachment count
    /// exactly where it was — decremented once, not zero times and not twice.
    ///
    /// Zero times leaks: gvproxy keeps running for a PTask that never came up,
    /// and it is never stopped, because the count never reaches zero. Twice is
    /// worse: it can stop the switch out from under a PTask that *is* up.
    #[tokio::test]
    async fn failed_attach_releases_the_switch_once() {
        let switch = counting_switch();
        let before = switch.lock().await.attached();

        let net = network_for(NetworkMode::OwnIp, &switch, "s", None).expect("own-IP has one");
        let plan = net.plan().await.expect("planning leases an address");
        assert!(
            plan.isolates_netns(),
            "an own-IP PTask gets its own namespace"
        );
        assert_eq!(
            switch.lock().await.attached(),
            before + 1,
            "planning takes the lease"
        );

        // An attach that cannot work, for a reason no environment can turn into
        // a success: a pid that cannot exist, so the namespace check in
        // `privileged_tap` refuses before anything is created. (`counting_switch`
        // is `HostShuttle`, so this is the privileged mechanism; a pid that
        // happened to exist could create a real tap on a privileged runner.)
        assert!(
            net.attach(Spawned::new(u32::MAX)).await.is_err(),
            "no namespace to wire means nothing to relay"
        );

        // The sandbox layer runs `abandon` on exactly this path — a failed
        // attach leaves the release owed — so the count must come back.
        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            before,
            "a failed attach must give the lease back"
        );

        // And only once. A second abandon finds nothing reserved and must not
        // decrement again.
        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            before,
            "the release must not run twice"
        );
    }

    /// The other half of the same property: once an attach succeeds the guard
    /// owns the release, so a later abandon must do nothing.
    ///
    /// Driven through `abandon` alone because a successful attach needs a live
    /// switch to relay to; what is provable here is that a *cleared* reservation
    /// is inert, which is the state a successful attach leaves behind.
    #[tokio::test]
    async fn abandon_without_a_reservation_does_not_decrement() {
        let switch = counting_switch();
        let net = network_for(NetworkMode::OwnIp, &switch, "s", None).expect("own-IP has one");
        net.plan().await.expect("planning");
        let leased = switch.lock().await.attached();

        net.abandon().await;
        let after_first = switch.lock().await.attached();
        assert_eq!(after_first, leased - 1);

        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            after_first,
            "an abandon with nothing reserved is a no-op"
        );
    }

    /// 012-006, for the mode that needs a provider: an own-IP PTask gets its own
    /// namespace and exactly one tap, addressed with its own lease and routed at
    /// the switch gateway. No more than the mode states, and no less.
    #[test]
    fn the_mode_bounds_the_network_access() {
        let subnet = crate::net::SwitchSubnet::default();
        let lease = std::net::Ipv4Addr::new(100, 64, 0, 7);
        let plan = own_ip_plan(subnet, lease, TapMechanism::InNamespace);

        assert!(plan.isolates_netns(), "own-IP runs in its own namespace");
        let tap = plan.tap().expect("own-IP gets a tap");
        assert_eq!(tap.address, lease, "the tap carries this PTask's lease");
        assert_eq!(tap.netmask, subnet.netmask());
        assert_eq!(
            tap.gateway,
            subnet.gateway(),
            "egress leaves through the switch, not anywhere else"
        );
        assert_eq!(
            tap.mtu,
            crate::net::DEFAULT_MTU,
            "a tap MTU that disagrees with the relay's frame buffer truncates"
        );
    }

    /// 012-N01. Four own-IP launches that start together must not serialize.
    ///
    /// The one thing that could serialize them is the daemon-wide
    /// `Mutex<SwitchClient>`: every own-IP plan leases an address through it.
    /// Handing out addresses *must* be serialized — that is what an allocator
    /// is. What must not be is the rest of the launch: building the tap,
    /// relaying it to the switch, applying ingress. Those are the slow part, and
    /// a provider that held the switch across them would turn four launches into
    /// four launches end to end.
    ///
    /// So the bound is measured over a launch, not over a lease. The sleep
    /// stands in for the tap-and-relay work, which a unit test has no tap to do
    /// for real; it is what gives the ratio meaning. Widen the critical section
    /// to cover it and this goes to ~4x and fails, which is the regression the
    /// requirement is about. Measured lease-only the ratio is ~2.4x on this
    /// machine and says nothing, because then the whole operation is the lock.
    ///
    /// The `try_lock` assertion is the same property stated deterministically,
    /// and is what fails first and most legibly.
    ///
    /// Real `SwitchClient`, no gvproxy: in `HostShuttle` mode attach and detach
    /// are pure bookkeeping, so the lease path under test is the production one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_own_ip_launches_do_not_serialize() {
        use std::time::{Duration, Instant};

        /// Stands in for tap creation and the relay handshake: the part of a
        /// launch that happens after the lease and must not hold the switch.
        const POST_LEASE_WORK: Duration = Duration::from_millis(50);

        /// One launch: lease, do the slow part, release. Returns how many
        /// PTasks the switch had attached while this one was in its slow part —
        /// the direct evidence of overlap, independent of any clock.
        async fn launch(switch: &Arc<Mutex<SwitchClient>>, identity: &str) -> usize {
            let net =
                network_for(NetworkMode::OwnIp, switch, identity, None).expect("own-IP has one");
            net.plan().await.expect("planning leases an address");
            tokio::time::sleep(POST_LEASE_WORK).await;
            let in_flight = switch.lock().await.attached();
            net.abandon().await;
            in_flight
        }

        let switch = counting_switch();

        // One launch, measured, to set the bound the other four are held to.
        let solo = Instant::now();
        launch(&switch, "solo").await;
        let one = solo.elapsed();
        assert!(
            switch.try_lock().is_ok(),
            "the switch must be free between a plan and its attach; a provider \
             that held it across them would serialize every other launch",
        );

        // Four at once, each with its own provider, as `network_for` hands them
        // out per PTask — sharing only the switch, which is the contended thing.
        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..4 {
            let switch = Arc::clone(&switch);
            set.spawn(async move { launch(&switch, &format!("p{i}")).await });
        }
        let mut in_flight = Vec::new();
        while let Some(joined) = set.join_next().await {
            in_flight.push(joined.expect("no launch task may panic"));
        }
        let four = started.elapsed();

        // All four held a lease at once. This is the property itself, stated
        // without reference to a clock: if the switch serialized them, each
        // would have seen exactly one attached PTask — its own.
        assert_eq!(
            in_flight.iter().copied().max(),
            Some(4),
            "four launches must overlap, not queue; saw {in_flight:?} attached"
        );

        // And the switch is back where it started — four leases, four releases.
        assert_eq!(switch.lock().await.attached(), 0);

        assert!(
            four < 2 * one,
            "four concurrent own-IP launches took {four:?}, more than twice a \
             single launch ({one:?}) — the shared switch is serializing them",
        );

        // The measurement 012-N01's open question asks for, so the bound stops
        // being a guess. Visible with `--nocapture`.
        eprintln!("012-N01: one own-IP launch {one:?}; four concurrently {four:?}");
    }
}
