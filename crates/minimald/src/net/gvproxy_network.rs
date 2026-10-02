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
use crate::net::dns;
use crate::net::policy::{ControlChannel, PortForwarder};
use crate::net::switch::{SessionGate, SwitchRelay};

/// The own-IP attachment guard. Returned by [`complete_own_ip_attach`] and torn
/// down explicitly via [`NetGuard::teardown`] at the end of the sandbox's life.
///
/// Teardown removes this PTask's ingress forwards then detaches it from the
/// switch (decrementing the switch refcount — which stops gvproxy once the last
/// `OwnIp` PTask leaves — and releasing the lease with the count, handed or
/// drawn alike; a handed lease released with it is what lets the same box's
/// re-attach re-hand its address, T66). It is **explicit** — driven on a
/// live runtime by the owner — rather than a `Drop` schedule, so it cannot be
/// lost to a stopped runtime. Dropping the held [`SwitchRelay`] aborts the
/// frame relay either way.
pub(crate) struct OwnIpGuard {
    /// Held for its `Drop`, which aborts the relay tasks; never read.
    _relay: SwitchRelay,
    /// The shared switch, locked on teardown to detach this PTask.
    switch: Arc<Mutex<SwitchClient>>,
    /// gvproxy's control channel (local socket on DM2, host vsock on DM1/3/4),
    /// used on teardown to remove this PTask's ingress forwards before detaching.
    control: ControlChannel,
    /// The declared ports' forwarders (NET-121) this attach bound — the
    /// forwards the box's name is published beside, held until the box
    /// stops, each able to unbind its port and end its connections. Removed
    /// on teardown. Empty when no ingress was configured.
    exposed: Vec<PortForwarder>,
    /// The lease ip this guard's attach holds, passed to `detach` so the
    /// lease is released with the count (T66) — handed or drawn alike, a
    /// lease's life is its attachment's.
    lease_ip: Ipv4Addr,
}

impl OwnIpGuard {
    /// Revokes one declared port's ingress (NET-121): unbinds the
    /// forwarder(s) bound for `external_port` — terminating the connections
    /// they hold through the box's gate, then unexposing — and leaves the
    /// box's other declared ports alone. The entry point the policy layer
    /// drives when a port's ingress is withdrawn while the box stays up.
    ///
    /// # Errors
    ///
    /// `NotFound` when no forwarder was bound for `external_port` — the port
    /// the call names was never declared, or its bind failed — naming the
    /// port either way; the unexpose error when the forwarder's own unbind
    /// failed.
    #[allow(dead_code)] // No policy-update trigger drives this yet; the NET-121 proof does.
    pub(crate) async fn revoke_ingress(&self, external_port: u16) -> io::Result<()> {
        let matching: Vec<&PortForwarder> = self
            .exposed
            .iter()
            .filter(|forwarder| {
                forwarder
                    .host_port()
                    .is_some_and(|(_, port)| port == external_port)
            })
            .collect();
        if matching.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no forwarder bound for external port {external_port}"),
            ));
        }
        let mut last_err = None;
        for forwarder in matching {
            if let Err(e) = forwarder.revoke(&self.control).await {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
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
            if let Err(e) = self.switch.lock().await.detach(self.lease_ip).await {
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
/// The relay is gated by the session's whole policy: the egress leg enforces
/// its declared egress rules (NET-062/063/064), the ingress leg its declared
/// inbound ports. The lease the box was allocated goes into the relay either
/// way: the egress leg rejects any frame whose source is not it (NET-084), so
/// a task's ungated relay is bound by its lease too. The gate also carries
/// the session's DNS dimension — its `egress.allow_dns_hosts` and
/// `egress.deny_subnets` ride the same
/// [`SessionGate`](crate::net::switch::SessionGate) into the relay, where
/// the DNS gate pins the addresses those names resolve to for their
/// admission window (NET-066), refuses the ones that land in denied ranges
/// (NET-067), and answers AAAA/HTTPS/SVCB lookups NODATA (NET-136).
///
/// The lease was already allocated and gvproxy already ensured-running by the
/// provider's plan, so this only does the post-spawn relay + ingress. A failure
/// here just propagates: the release of that lease stays with the launch
/// (`sandbox2::PlannedLaunch`), and detaching as well would double-decrement
/// gvproxy's attach count.
///
/// `handed_from_host` says whether `lease_ip` is the address the VM host
/// daemon allocated for this box's registration and handed back (T66), or
/// one this daemon drew itself — the one debug line per attach names the
/// address and that distinction, so a log tail can tell an attach that
/// honored its handed address from one that did not.
// Left positional: a single call site that has just planned the launch, so a
// struct would be single-use ceremony.
#[expect(
    clippy::too_many_arguments,
    reason = "left positional: a single call site that has just planned the launch, so a struct would be single-use ceremony"
)]
pub(crate) async fn complete_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    tap_fd: OwnedFd,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    session_name: &str,
    policy: Option<&sessions::SessionPolicy>,
    own_address: Option<&crate::net::provider::OwnAddressReporter>,
    handed_from_host: bool,
) -> io::Result<OwnIpGuard> {
    tracing::debug!(
        session = session_name,
        switch_address = %lease_ip,
        handed_from_host,
        "own-address box attached to the switch"
    );
    // The relay's egress carve-out and deprecation notice (NET-004) derive
    // their addresses from the subnet of the switch this box attaches to, so
    // a custom-subnet switch is keyed to its own resolver and watched at its
    // own host alias.
    let subnet = switch.lock().await.subnet();
    // The gate is held in an `Arc` so the relay's legs and the ingress
    // forwarders this attach goes on to build (NET-121) share one gate: a
    // revoked port's refusal on the legs is the same gate state the
    // forwarder's revocation sets.
    let gate = policy
        .map(|policy| SessionGate::for_session(lease_ip.to_string(), lease_ip, policy, subnet))
        .map(Arc::new);
    let relay = match (&control, &gate) {
        (ControlChannel::Unix(sock), Some(gate)) => {
            crate::net::switch::attach_to_switch(
                tap_fd,
                sock,
                Some(Arc::clone(gate)),
                lease_ip,
                subnet,
            )
            .await?
        }
        (ControlChannel::Vsock { cid, port }, Some(gate)) => {
            crate::net::switch::attach_to_switch_vsock(
                tap_fd,
                *cid,
                *port,
                Some(Arc::clone(gate)),
                lease_ip,
                subnet,
            )
            .await?
        }
        (ControlChannel::Unix(sock), None) => {
            crate::net::switch::attach_to_switch(tap_fd, sock, None, lease_ip, subnet).await?
        }
        (ControlChannel::Vsock { cid, port }, None) => {
            crate::net::switch::attach_to_switch_vsock(tap_fd, *cid, *port, None, lease_ip, subnet)
                .await?
        }
    };
    finish_own_ip_attach(
        switch,
        relay,
        control,
        lease_ip,
        session_name,
        policy.and_then(|p| p.ingress.as_ref()),
        gate.as_ref(),
        own_address,
    )
    .await
}

/// Tail of the own-IP attach: apply static ingress forwards (R2.3) over
/// `control`, then build the [`OwnIpGuard`]. On an ingress failure the relay is
/// dropped (closing the switch-side connection); the attach-count rollback is
/// left to the launch, so the refcount is never double-decremented.
///
/// NET-121's order is this function's shape: the declared ports are bound
/// first — each failure its own warn line, from `apply_ingress`, and neither
/// the name nor a substitute address published for a port whose bind failed,
/// because the error short-circuits everything below — and only the binds
/// that succeeded are followed by the name's registration and the route's
/// report, so the name never exists a moment before its ports are reachable.
#[expect(
    clippy::too_many_arguments,
    reason = "left positional: the single call site has just built every one of these, so a struct would be single-use ceremony"
)]
async fn finish_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    relay: SwitchRelay,
    control: ControlChannel,
    lease_ip: Ipv4Addr,
    session_name: &str,
    ingress: Option<&sessions::IngressPolicy>,
    gate: Option<&Arc<SessionGate>>,
    own_address: Option<&crate::net::provider::OwnAddressReporter>,
) -> io::Result<OwnIpGuard> {
    // The host loopback address this box's declaration publishes on (NET-010):
    // the box's own leased address, read back from the registry rather than
    // re-derived, so the forwards bind where the box's name answers. A launch
    // without a reporter — a task, which owns no proxy route of its own —
    // publishes on the node's shared address, the same interim a box without
    // an address of its own does (NET-123).
    let published =
        own_address.map_or(Ipv4Addr::LOCALHOST, |reporter| reporter.published_address());
    let exposed = match ingress {
        Some(ingress) if !ingress.port_mappings.is_empty() => {
            match crate::net::policy::apply_ingress(&control, published, lease_ip, ingress, gate)
                .await
            {
                Ok(exposed) => exposed,
                // The failure is already said — one warn per failed bind,
                // with the port and the reason, where the bind happened — so
                // no aggregate line re-tells it here. The attach fails: no
                // name is registered, no route reported, no substitute
                // address stands in for the port that could not bind.
                Err(e) => {
                    drop(relay);
                    return Err(e);
                }
            }
        }
        _ => Vec::new(),
    };

    // One info line per bound forwarder (NET-040, NET-121): the host address
    // it is reachable at, the port, and the session it belongs to — so the
    // daemon log tail (and the `min bug` bundle carrying it) shows each
    // forwarder bind and its result when a publish goes wrong. Reported from
    // `exposed` — the forwards the switch actually accepted, 1:1 with the
    // request since a failed apply rolls back and errors above — and from
    // each forward's own `local` bind, never from the request: the record
    // stays true to what the forwarder holds if the address `expose_request`
    // binds ever moves off the loopback.
    //
    // The message text is a contract beside the fields: `session-e2e.sh`'s
    // `published_loopback_host` reads the publish record — the address the
    // forwarder actually bound — out of the daemon log by exactly this
    // phrase, so it is not reworded without that reader moving too.
    for forwarder in &exposed {
        match forwarder.host_port() {
            Some((host, port)) => tracing::info!(
                host,
                port,
                session = session_name,
                "exposed ingress port on the host loopback"
            ),
            // `expose_request` cannot build a `local` that splits into no
            // host and port; if one ever appears, name what the forwarder
            // holds rather than invent a port for it.
            None => tracing::info!(
                local = %forwarder.local(),
                session = session_name,
                "exposed ingress port on the host loopback"
            ),
        }
    }

    // Register this PTask's two-label name — with the deprecated three-label
    // forms beside it (NET-002) — pointing at its current lease, so peer
    // sessions can resolve it (finding #3 / UC6). Done for *every* own-IP
    // PTask, even with no ingress: resolvable names are how peers find each other,
    // and the ingress gate independently governs reachability. The host label
    // is this daemon instance's own id — carried by the switch, same as the
    // proxy's registry — so the *instance-scoped* record a second daemon on
    // the host publishes (`<name>.<id>`) sits beside the first's instead of
    // over it (NET-027). The two-label `<name>` record and the deprecated
    // `local` one are shared names, and where they land depends on who owns
    // the gvproxy: a native daemon owns its own, so its zone is its own; two
    // VM daemons on one host share the host gvproxy's one zone, where both
    // publish the same row at their own leases and gvproxy's newest-wins
    // merge (see `policy`'s `DnsZone`) resolves whichever daemon registered
    // last — the ambiguity NET-010's host-global allocation is the layer
    // that arbitrates, and the reason the instance-scoped record is the one
    // two daemons can rely on. The routing side answers the same pair
    // (`HostnameRegistry`'s `host_ids`). Best-effort — a DNS
    // hiccup must not fail an otherwise-working attach.
    //
    // NET-121: this registration runs *after* the binds above — the name
    // resolves only to a box whose declared ports are already bound, so a
    // connection by name is never answered before its port is reachable,
    // and a failed bind never leaves a name behind for a port that refused.
    let host_ids = dns::host_ids_for(switch.lock().await.host_id());
    for host_id in host_ids {
        if let Err(e) =
            crate::net::policy::register_dns_name(&control, &host_id, session_name, lease_ip).await
        {
            tracing::warn!(error = %e, session = session_name, "registering *.min.internal name on gvproxy");
        }
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
        lease_ip,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::path::PathBuf;
    use std::sync::Arc;

    use switch::MacAddr;
    use sandbox2::NetGuard as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{Mutex, mpsc};

    use crate::net::PtaskLease;
    use crate::net::SwitchClient;
    use crate::net::SwitchTransport;
    use crate::net::dns;
    use crate::net::policy::{ControlChannel, register_dns_name};
    use crate::net::provider::network_for;
    use crate::test_harness::CaptureWriter;
    use sessions::BoxAddresses;

    /// Reads one control request off `sock` — its head up to the
    /// end-of-head marker, then exactly its `Content-Length` body — and
    /// returns the body bytes. The mirror of `policy::post_json`'s
    /// keep-alive framing: never read to EOF, which would block on the
    /// connection the client holds open until it has drained the response.
    async fn read_request_body(sock: &mut UnixStream) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        let mut scratch = [0u8; 512];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                break i;
            }
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake gvproxy must receive the control request");
            assert!(n > 0, "the control client closed before sending its head");
            buf.extend_from_slice(&scratch[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let len: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake gvproxy must receive the request body");
            assert!(n > 0, "the control client closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        buf[head_end..head_end + len].to_vec()
    }

    /// Serves a gvproxy-shaped control channel at `path`, answering every
    /// request with an empty 200 and handing the first `requests` request
    /// bodies to the returned receiver — the fake forwarder the publishes
    /// below are driven against, standing in for the one host gvproxy two
    /// VM daemons on one machine share.
    fn spawn_control_channel_capturing(path: PathBuf, requests: usize) -> mpsc::Receiver<Vec<u8>> {
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = mpsc::channel(requests);
        tokio::spawn(async move {
            for _ in 0..requests {
                let (mut sock, _) = listener
                    .accept()
                    .await
                    .expect("the fake gvproxy must accept every publish");
                let body = read_request_body(&mut sock).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .expect("the fake gvproxy must answer 200");
                tx.send(body)
                    .await
                    .expect("the test is still collecting the publish bodies");
                // `sock` drops here, held open past its response the way the
                // real forwarder holds the keep-alive exchange; the client
                // reads its Content-Length and closes first.
            }
        });
        rx
    }

    /// NET-027's DNS-publish half, observed at the wire a shared gvproxy
    /// sees: two daemons on one machine — here the shape whose control
    /// channel is the one host gvproxy both attach to — each publish their
    /// own `web` box's names exactly the way `finish_own_ip_attach` does
    /// (`host_ids_for` per daemon: its own id, then the promised `local`),
    /// both into the *same* zone. What the two daemons put there:
    ///
    /// - the instance-scoped records are distinct names, so both daemons'
    ///   boxes stay resolvable beside each other — the disjoint half of
    ///   NET-027, the reason the instance label exists;
    /// - the shared two-label `web` row and the deprecated `web.local` row
    ///   are the *same names* published twice at different leases — one
    ///   row each in the one zone, which gvproxy's newest-wins merge (the
    ///   `DnsZone` doc) resolves whichever daemon registered last. That
    ///   is the ambiguity across daemons NET-010's host-global allocation
    ///   is the layer that arbitrates; pinned here as observable fact
    ///   rather than left unexercised by a test that never looks at the
    ///   publish path.
    #[tokio::test]
    async fn instance_zone_records_stay_distinct_in_one_shared_zone() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("gvproxy.sock");
        let mut bodies_rx = spawn_control_channel_capturing(sock_path.clone(), 4);
        let control = ControlChannel::Unix(sock_path);

        // Two daemons, two instance ids, each with a `web` box at its own
        // lease — the collision case a shared two-label name space has.
        let id_a = "aaaa1";
        let id_b = "bbbb2";
        let lease_a = Ipv4Addr::new(100, 64, 1, 5);
        let lease_b = Ipv4Addr::new(100, 64, 2, 5);
        for (id, lease) in [(id_a, lease_a), (id_b, lease_b)] {
            for host_id in dns::host_ids_for(id) {
                register_dns_name(&control, &host_id, "web", lease)
                    .await
                    .expect("the fake gvproxy control channel must accept the publish");
            }
        }

        let mut bodies = Vec::with_capacity(4);
        while let Some(body) = bodies_rx.recv().await {
            bodies.push(String::from_utf8(body).expect("the zone body is ASCII JSON"));
        }

        // Two publishes per daemon: its own zone, then `local`, each carrying
        // every record at that daemon's own lease.
        let publishes_of = |ip: &str| -> Vec<&String> {
            bodies
                .iter()
                .filter(|body| body.contains(&format!("\"ip\":\"{ip}\"")))
                .collect()
        };
        let publishes_a = publishes_of(&lease_a.to_string());
        let publishes_b = publishes_of(&lease_b.to_string());
        assert_eq!(
            publishes_a.len(),
            2,
            "daemon A publishes its own zone and the `local` zone, got: {bodies:?}"
        );
        assert_eq!(
            publishes_b.len(),
            2,
            "daemon B publishes its own zone and the `local` zone, got: {bodies:?}"
        );

        // The instance-scoped records are distinct names — the half of
        // NET-027 two daemons can rely on: each daemon's zone holds its own
        // `<name>.<id>` row beside the other daemon's, not over it.
        let own_a = format!("\"name\":\"web.{id_a}\"");
        let own_b = format!("\"name\":\"web.{id_b}\"");
        assert_ne!(own_a, own_b, "two daemon instances mint two host labels");
        assert!(
            publishes_a.iter().any(|body| body.contains(&own_a)),
            "daemon A must publish its instance-scoped record, got: {bodies:?}"
        );
        assert!(
            publishes_b.iter().any(|body| body.contains(&own_b)),
            "daemon B must publish its instance-scoped record, got: {bodies:?}"
        );

        // The shared forms are the same row published twice at different
        // leases — what a shared gvproxy's newest-wins merge resolves
        // last-writer-wins, the boundary the instance-scoped record draws
        // and NET-010's allocation arbitrates.
        for body in &publishes_a {
            assert!(
                body.contains(&format!("\"name\":\"web\",\"ip\":\"{}\"", lease_a)),
                "daemon A's publish carries the shared two-label row at its \
                 own lease, got: {body}"
            );
        }
        for body in &publishes_b {
            assert!(
                body.contains(&format!("\"name\":\"web\",\"ip\":\"{}\"", lease_b)),
                "daemon B's publish carries the shared two-label row at its \
                 own lease, got: {body}"
            );
        }
        assert!(
            publishes_a
                .iter()
                .any(|body| body.contains("\"name\":\"web.local\"")),
            "daemon A publishes the deprecated `local` row, got: {bodies:?}"
        );
        assert!(
            publishes_b
                .iter()
                .any(|body| body.contains("\"name\":\"web.local\"")),
            "daemon B publishes the deprecated `local` row too — the same \
             shared name both daemons publish, got: {bodies:?}"
        );
    }

    /// A switch whose attach/detach are pure bookkeeping: `HostShuttle`
    /// leaves the gvproxy process to `minvmd`, so only the count moves —
    /// the shape a VM-backed host's daemon carries. Carries the same
    /// instance host id the NET-121 proofs build their registry with
    /// (`aaaa1`), the pairing the daemon itself makes
    /// (`sessions.rs` builds its registry from this switch's `host_id`),
    /// so the attach's per-id `/services/dns/add` publishes — its own id
    /// beside the deprecated `local` one — are the two the proofs count.
    fn vm_host_switch() -> Arc<Mutex<SwitchClient>> {
        Arc::new(Mutex::new(
            SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy")
                .with_host_id("aaaa1")
                .with_transport(SwitchTransport::HostShuttle {
                    cid: crate::net::VSOCK_HOST_CID,
                    port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
                }),
        ))
    }

    /// T66, both halves of the daemon-side promise, on a VM host's switch:
    ///
    /// An own-address attach whose launch carries the addresses the VM host
    /// daemon handed its registration attaches **at the handed address** —
    /// the address the host-side table's row is keyed by — and **selects
    /// none**: the allocator's run shows exactly the handed lease, no
    /// self-allocation spent beside it. The lease releases with its attach,
    /// so the same box re-attaching — the re-attach an in-process host
    /// rebuild produces, where this allocator survives the rebuild — re-hands
    /// its own address, and the next unregistered box self-allocates from
    /// the daemon's reserve: the plan run's lower half, disjoint from the
    /// hand-out run the handed address came from, so the two allocators
    /// cannot meet. The attach names the handed address in one debug line,
    /// with the handed/self-drawn distinction a log tail reads. A handed
    /// address that would put a second tap beside a live one is refused at
    /// the attach path rather than shared with it — a reserve address, and
    /// an attach's own address alike.
    #[tokio::test]
    async fn own_ip_attach_uses_handed_address() {
        let switch = vm_host_switch();
        // The handed address comes from the hand-out run — the plan run's
        // upper half, above the daemon's self-allocation reserve, which is
        // where a real host's registrations hand from.
        let handed_switch = Ipv4Addr::new(100, 64, 128, 9);
        let handed_loopback = Ipv4Addr::new(127, 0, 64, 9);
        let net = network_for(
            sessions::NetworkMode::OwnIp,
            &switch,
            "web",
            None,
            None,
            Some(BoxAddresses {
                switch_address: handed_switch,
                loopback_address: handed_loopback,
            }),
        );

        // The plan's lease IS the handed address — the address the tap is
        // configured with, whatever mechanism builds it — and the switch's
        // table carries exactly that one lease: nothing was drawn beside it.
        let plan = net.plan().await.expect("the handed attach plans");
        assert_eq!(
            switch.lock().await.attached(),
            1,
            "the handed attach counts like any other"
        );
        assert_eq!(
            switch.lock().await.leases(),
            &[PtaskLease {
                ip: handed_switch,
                mac: MacAddr::for_switch_ip(handed_switch),
            }],
            "the handed attach records the handed lease and selects nothing else"
        );
        let _ = plan; // the plan's resolver/tap carry the same lease; asserted above

        // Releasing it detaches like any other — and the handed lease goes
        // with the count: the address is the registered box's, keyed by the
        // host-side row, so once its attach ends the same box re-attaching
        // re-hands it instead of meeting the collision refusal. That is the
        // re-attach an in-process host rebuild produces, where this
        // allocator survives the rebuild.
        net.abandon().await;
        assert_eq!(switch.lock().await.attached(), 0, "the abandon detaches");
        assert!(
            switch.lock().await.leases().is_empty(),
            "the abandon releases the handed lease with the count"
        );

        // The next box — one the activating client did not register —
        // self-allocates from the daemon's reserve: the plan run's lower
        // half, a sub-run disjoint from the hand-out run the handed address
        // came from, so the two allocators cannot meet and the handed
        // address is never drawn.
        let unregistered = network_for(
            sessions::NetworkMode::OwnIp,
            &switch,
            "other",
            None,
            None,
            None,
        );
        let _ = unregistered
            .plan()
            .await
            .expect("a self-allocated attach plans");
        let leases = switch.lock().await.leases().to_vec();
        assert_eq!(
            leases.len(),
            1,
            "the released handed lease is out of the table; one draw beside \
             it: {leases:?}"
        );
        let drawn = *leases
            .first()
            .expect("the assert above pinned exactly one lease in the table");
        assert_eq!(
            drawn.ip,
            Ipv4Addr::new(100, 64, 0, 2),
            "the self-allocation draws the reserve's first address — the \
             sub-run is disjoint from the hand-out run, so the handed \
             address is never drawn, got {leases:?}"
        );

        // A handed address inside the reserve is refused at the attach path
        // — the shape a host that hands from the run's start would produce —
        // and the refusal spends nothing: no lease joins the table, no
        // attach is counted.
        let colliding_reserve = network_for(
            sessions::NetworkMode::OwnIp,
            &switch,
            "third",
            None,
            None,
            Some(BoxAddresses {
                switch_address: drawn.ip,
                loopback_address: Ipv4Addr::LOCALHOST,
            }),
        );
        let err = colliding_reserve
            .plan()
            .await
            .expect_err("a handed address inside the reserve refuses");
        assert!(
            err.to_string().contains("self-allocation reserve"),
            "the refusal names the reserve: {err}"
        );
        assert_eq!(
            switch.lock().await.leases().len(),
            1,
            "the refusal added no lease to the table"
        );
        assert_eq!(
            switch.lock().await.attached(),
            1,
            "only the self-allocated attach counts; the refused one never did"
        );

        // The same box re-attaching re-hands its own address: the lease its
        // previous attach released is back in the table, and the
        // select-none half of the promise holds on the re-attach too — the
        // table holds exactly the drawn lease and the handed one, nothing
        // drawn beside it, and the attach counts like any other.
        let reattached = network_for(
            sessions::NetworkMode::OwnIp,
            &switch,
            "web",
            None,
            None,
            Some(BoxAddresses {
                switch_address: handed_switch,
                loopback_address: handed_loopback,
            }),
        );
        let _ = reattached
            .plan()
            .await
            .expect("the same box re-attaching re-hands its own address");
        let leases = switch.lock().await.leases().to_vec();
        assert_eq!(
            leases.len(),
            2,
            "the re-hand records the handed lease beside the drawn one: \
             {leases:?}"
        );
        assert!(
            leases.contains(&PtaskLease {
                ip: handed_switch,
                mac: MacAddr::for_switch_ip(handed_switch),
            }),
            "the re-hand carries the same lease the first attach recorded: \
             {leases:?}"
        );
        assert_eq!(
            switch.lock().await.attached(),
            2,
            "the re-hand counts like any attach"
        );

        // While that attach is live, handing its address again is refused —
        // two taps on one address would key one PTask's frames to the
        // other's host-side row. The refusal spends nothing.
        let colliding_live = network_for(
            sessions::NetworkMode::OwnIp,
            &switch,
            "fourth",
            None,
            None,
            Some(BoxAddresses {
                switch_address: handed_switch,
                loopback_address: Ipv4Addr::LOCALHOST,
            }),
        );
        let err = colliding_live
            .plan()
            .await
            .expect_err("a handed address a live attach holds refuses");
        assert!(
            err.to_string().contains("already held by a lease"),
            "the refusal names the held lease: {err}"
        );
        assert_eq!(
            switch.lock().await.leases().len(),
            2,
            "the refusal added no lease to the table"
        );
        assert_eq!(
            switch.lock().await.attached(),
            2,
            "the refused hand never counted"
        );

        // The attach's one debug line names the address the box carries and
        // says it was handed. Driven through the completion the provider's
        // attach calls, against a stand-in control channel, with a socketpair
        // standing in for the tap. The capture reads at DEBUG — the
        // harness's global capture reads at INFO and would never see it.
        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let dir = tempfile::TempDir::new().unwrap();
        let control_path = dir.path().join("gvproxy.sock");
        // One `/connect` upgrade plus one DNS publish per host id.
        let _bodies = spawn_control_channel_capturing(control_path.clone(), 8);
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `socketpair` with a valid domain/type either returns -1
        // (checked) or fills `fds` with two fresh descriptors.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let tap_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let _box_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            tap_fd,
            ControlChannel::Unix(control_path),
            handed_switch,
            "web",
            None,
            None,
            true,
        )
        .await
        .expect("the attach completes against the stand-in");
        drop(guard);
        let log = capture.contents();
        assert!(
            log.contains(&format!("switch_address={handed_switch}"))
                && log.contains("handed_from_host=true"),
            "the attach's debug line names the handed address and says it was \
             handed: {log}"
        );
        assert!(
            !log.contains("handed_from_host=false"),
            "this run handed every address; no self-drawn attach was logged: {log}"
        );
    }

    // ---- NET-121: bind before the name; failed bind, no substitute; revocation
    // -----------------------------------------------------------------------

    /// Reads one control request off `sock` — its head, then exactly its
    /// `Content-Length` body — and returns both. The mirror of
    /// `policy::post_json`'s keep-alive framing; the `/connect` upgrade
    /// carries no body, and the head is what tells it apart.
    async fn read_request_head_and_body(
        sock: &mut UnixStream,
    ) -> std::io::Result<(String, Vec<u8>)> {
        let mut buf = Vec::with_capacity(512);
        let mut scratch = [0u8; 512];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                break i;
            }
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake gvproxy must receive the control request");
            assert!(n > 0, "the control client closed before sending its head");
            buf.extend_from_slice(&scratch[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let len: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake gvproxy must receive the request body");
            assert!(n > 0, "the control client closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        Ok((head, buf[head_end..head_end + len].to_vec()))
    }

    /// The gvproxy stand-in the NET-121 proofs drive `complete_own_ip_attach`
    /// against: every control request is read in full, answered with the
    /// status `decide` picks for `(path, body)`, and recorded as
    /// `(path, body)` on `events` in arrival order — the order the attach's
    /// binds and registrations happened in. The `/connect` upgrade is
    /// hijacked the way the real switch hijacks it: no response is written,
    /// and the upgraded stream is handed to the test, which becomes the
    /// switch side of the box's relay for as long as it holds it.
    ///
    /// Abort the returned handle when the test is done; the fake accepts
    /// until then.
    fn spawn_control_channel_deciding(
        path: PathBuf,
        decide: impl Fn(&str, &str) -> u16 + Send + Sync + 'static,
        events: mpsc::Sender<(String, String)>,
        handed: mpsc::Sender<UnixStream>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let Ok((head, body)) = read_request_head_and_body(&mut sock).await else {
                    return;
                };
                if head.starts_with("POST /connect") {
                    // The real switch hijacks the connection and writes no
                    // response; the relay legs take it from here.
                    handed
                        .send(sock)
                        .await
                        .expect("the test still holds the handed stream");
                    continue;
                }
                let request_path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let body = String::from_utf8_lossy(&body).into_owned();
                let status = decide(&request_path, &body);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                sock.write_all(
                    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await
                .expect("the fake gvproxy must answer");
                events
                    .send((request_path, body))
                    .await
                    .expect("the test is still collecting the control requests");
            }
        })
    }

    /// Reads one 2-byte-LE-framed frame the relay put on the handed stream —
    /// the switch side's view of what left the box, resets included.
    async fn read_framed_stream(sock: &mut UnixStream) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        sock.read_exact(&mut len_buf).await?;
        let n = u16::from_le_bytes(len_buf) as usize;
        let mut frame = vec![0u8; n];
        sock.read_exact(&mut frame).await?;
        Ok(frame)
    }

    /// Writes one frame to the switch side of the relay, framed the way
    /// gvproxy writes to it.
    async fn write_framed_stream(sock: &mut UnixStream, frame: &[u8]) -> std::io::Result<()> {
        let mut framed = Vec::with_capacity(2 + frame.len());
        framed.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        framed.extend_from_slice(frame);
        sock.write_all(&framed).await
    }

    /// Reads one frame the relay wrote back toward the box, polling the
    /// nonblocking box end until it arrives — the local twin of the switch
    /// tests' reader, for the handed-stream harness here.
    async fn read_box_end_frame(box_end: &std::fs::File) -> std::io::Result<Vec<u8>> {
        crate::net::switch::set_nonblocking(box_end.as_raw_fd())?;
        let mut buf = vec![0u8; 1600];
        for _ in 0..500 {
            match (&*box_end).read(&mut buf) {
                Ok(n) if n > 0 => return Ok(buf[..n].to_vec()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no frame arrived from the relay",
        ))
    }

    /// Whether the box end is silent — nothing the relay would forward.
    fn box_end_is_silent(box_end: &std::fs::File) -> bool {
        crate::net::switch::set_nonblocking(box_end.as_raw_fd()).unwrap();
        let mut probe = [0u8; 1];
        matches!(
            (&*box_end).read(&mut probe),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
        )
    }

    /// A TCP segment over the switch, with the addresses, ports and sequence
    /// pair the NET-121 handshake needs — the switch tests' builders fix
    /// their numbers, and a handshake here needs its own.
    fn tcp_segment(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.push(0x45); // IPv4, IHL 5, fragment offset 0
        f.push(0x00);
        f.extend_from_slice(&40u16.to_be_bytes()); // total length (unread)
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(crate::net::switch::IPPROTO_TCP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unread)
        f.extend_from_slice(&src.0.octets());
        f.extend_from_slice(&dst.0.octets());
        f.extend_from_slice(&src.1.to_be_bytes());
        f.extend_from_slice(&dst.1.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ack.to_be_bytes());
        f.push(0x50); // data offset 5, reserved
        f.push(flags);
        f.extend_from_slice(&0u16.to_be_bytes()); // window
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        f
    }

    /// The two declared ports the NET-121 proofs publish: host `:8080` and
    /// `:9090`, each forwarding to its own number on the box.
    fn declared_two_ports() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![
                    sessions::PortMapping {
                        external_port: 8080,
                        internal_port: 80,
                        proto: sessions::IpProto::Tcp,
                    },
                    sessions::PortMapping {
                        external_port: 9090,
                        internal_port: 90,
                        proto: sessions::IpProto::Tcp,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
        }
    }

    /// Reads control events until `want` requests on `path` have arrived.
    async fn collect_until(
        events: &mut mpsc::Receiver<(String, String)>,
        path: &str,
        want: usize,
    ) -> Vec<(String, String)> {
        let mut seen = Vec::new();
        loop {
            let event = match tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
                .await
            {
                Ok(Some(event)) => event,
                Ok(None) => {
                    panic!("the fake gvproxy stopped before {want} {path} requests arrived")
                }
                Err(_) => panic!("no {path} request arrived within 5s; seen so far: {seen:?}"),
            };
            let hit = event.0 == path;
            seen.push(event);
            if hit && seen.iter().filter(|(p, _)| p == path).count() >= want {
                return seen;
            }
        }
    }

    /// The `local` fields of every request on `path`, in order.
    fn locals_of(events: &[(String, String)], path: &str) -> Vec<String> {
        events
            .iter()
            .filter(|(p, _)| p == path)
            .filter_map(|(_, body)| {
                body.split("\"local\":\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .map(str::to_string)
            })
            .collect()
    }

    /// NET-121: the declared ports are bound before the name is registered —
    /// every expose call reaches the switch before any `/services/dns/add`
    /// does, and the registry's route is reported last of all — so the name
    /// resolves only to a box whose ports are already reachable, and a
    /// connection by name never arrives before its port exists. The
    /// forwarders stay on the guard for the box's lifetime: its teardown
    /// unbinds them.
    #[tokio::test]
    async fn declared_ports_bound_before_name_registered() {
        let dir = tempfile::TempDir::new().unwrap();
        let control_path = dir.path().join("gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake =
            spawn_control_channel_deciding(control_path.clone(), |_, _| 200, events_tx, handed_tx);
        let switch = vm_host_switch();
        let registry = Arc::new(std::sync::RwLock::new(dns::HostnameRegistry::new(
            "aaaa1", true,
        )));
        let reporter = crate::net::provider::OwnAddressReporter::new(
            Arc::clone(&registry),
            sessions::SessionId::nil(),
        );
        let policy = declared_two_ports();

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `socketpair` with a valid domain/type either returns -1
        // (checked) or fills `fds` with two fresh descriptors.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let tap_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let _box_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            tap_fd,
            ControlChannel::Unix(control_path),
            Ipv4Addr::new(100, 64, 0, 9),
            "web",
            Some(&policy),
            Some(&reporter),
            false,
        )
        .await
        .expect("the attach completes against the stand-in");

        // The attach's control traffic, up to the name registration — the
        // harness switch answers for the one default host id, so one
        // publish.
        let events = collect_until(&mut events_rx, "/services/dns/add", 1).await;

        // Every expose precedes every name registration: the binds are the
        // attach's first control requests.
        let last_expose = events
            .iter()
            .rposition(|(p, _)| p == "/services/forwarder/expose")
            .expect("the declared ports were exposed");
        let first_dns = events
            .iter()
            .position(|(p, _)| p == "/services/dns/add")
            .expect("the name was registered");
        assert!(
            last_expose < first_dns,
            "binds must precede the name: {events:?}"
        );

        // Both declared ports bound, each at the box's published address —
        // the registry has none yet, so the attach published on the node's
        // shared interim (NET-123) at `127.0.0.1`.
        let exposed = locals_of(&events, "/services/forwarder/expose");
        assert_eq!(
            exposed,
            vec!["127.0.0.1:8080", "127.0.0.1:9090"],
            "each declared port bound once, in declaration order: {events:?}"
        );

        // The registry's route exists now, after the binds — the report is
        // the last of the three steps the attach takes. The route is the
        // full zone name the registry answers (`<name>.min.internal`).
        let held = registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert!(
            matches!(held, crate::net::dns::ZoneEntry::Held { .. }),
            "the name routes only after the binds: {held:?}"
        );

        // The forwarders are held until stop: the guard's teardown unbinds
        // them, one unexpose per bound port. Teardown is explicit — the
        // sandbox layer drives it at the box's end — so the proof drives it
        // too: a bare drop would only abort the frame relay and leave the
        // forwards standing.
        Box::new(guard).teardown().await;
        let unbound = collect_until(&mut events_rx, "/services/forwarder/unexpose", 2).await;
        assert_eq!(
            locals_of(&unbound, "/services/forwarder/unexpose"),
            vec!["127.0.0.1:8080", "127.0.0.1:9090"],
            "teardown unbinds every forwarder it held: {unbound:?}"
        );
        fake.abort();
    }

    /// NET-121's sub 2: a declared port whose forwarder cannot bind is
    /// *reported* — the failed bind says its own warn line, with the port and
    /// the reason the switch gave — and the attach fails, so neither the
    /// name nor any substitute address is ever published for it: no
    /// registration reaches the switch, the registry holds no route, and the
    /// binds that did succeed are rolled back.
    #[tokio::test]
    async fn failed_forwarder_bind_is_reported_not_substituted() {
        let capture = crate::test_harness::captured_log();
        let dir = tempfile::TempDir::new().unwrap();
        let control_path = dir.path().join("gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        // The fake refuses `:9090`'s expose the way the real forwarder
        // answers a bind failure, and answers everything else.
        let fake = spawn_control_channel_deciding(
            control_path.clone(),
            |path, body| {
                if path == "/services/forwarder/expose" && body.contains("127.0.0.1:9090") {
                    500
                } else {
                    200
                }
            },
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let registry = Arc::new(std::sync::RwLock::new(dns::HostnameRegistry::new(
            "aaaa1", true,
        )));
        let reporter = crate::net::provider::OwnAddressReporter::new(
            Arc::clone(&registry),
            sessions::SessionId::nil(),
        );
        let policy = declared_two_ports();

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `socketpair` with a valid domain/type either returns -1
        // (checked) or fills `fds` with two fresh descriptors.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let tap_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let _box_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let err = match crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            tap_fd,
            ControlChannel::Unix(control_path),
            Ipv4Addr::new(100, 64, 0, 9),
            "web",
            Some(&policy),
            Some(&reporter),
            false,
        )
        .await
        {
            Ok(_) => panic!("a failed bind must fail the attach"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("9090") || err.to_string().contains("500"),
            "the failure names the bind that failed: {err}"
        );

        // What reached the switch: both exposes, then the rollback of the
        // one that succeeded. No registration, ever.
        let mut events = Vec::new();
        while let Ok(event) = events_rx.try_recv() {
            events.push(event);
        }
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec!["127.0.0.1:8080", "127.0.0.1:9090"],
            "both binds were attempted: {events:?}"
        );
        assert_eq!(
            locals_of(&events, "/services/forwarder/unexpose"),
            vec!["127.0.0.1:8080"],
            "the bind that succeeded is rolled back with the failed one: {events:?}"
        );
        assert!(
            !events.iter().any(|(p, _)| p == "/services/dns/add"),
            "a failed bind publishes no name: {events:?}"
        );

        // And no route in the registry: the name the box's declaration
        // wanted is held by nothing — looked up as the full zone name the
        // registry answers, so the assertion is about the route the attach
        // never reported, not a name nothing ever held.
        let held = registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held,
            crate::net::dns::ZoneEntry::Absent,
            "no substitute address stands in for the failed bind: {held:?}"
        );

        // The failure is the log's own fact: one warn per failed bind, with
        // the port and the reason.
        let log = capture.contents();
        assert!(
            log.contains("binding declared ingress port failed")
                && log.contains("port=9090")
                && log.contains("error="),
            "the failed bind says its line with the port and the reason: {log}"
        );
        fake.abort();
    }

    /// NET-121's sub 1: a declared port's ingress revoked ends its
    /// connections at once. The proof drives a whole handshake through the
    /// relay the attach built — the client connects, the box answers — then
    /// revokes the port: the connection's reset is on the switch side before
    /// the unexpose finishes, a further connection attempt to the port is
    /// refused with a reset and never reaches the box, and the forwarder's
    /// unbind reaches the switch. A port no forwarder was bound for is
    /// refused by name.
    #[tokio::test]
    async fn ingress_revocation_unbinds_forwarder_and_terminates_connections() {
        const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;

        let capture = crate::test_harness::captured_log();
        let dir = tempfile::TempDir::new().unwrap();
        let control_path = dir.path().join("gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, mut handed_rx) = mpsc::channel(4);
        let fake =
            spawn_control_channel_deciding(control_path.clone(), |_, _| 200, events_tx, handed_tx);
        let switch = vm_host_switch();
        let registry = Arc::new(std::sync::RwLock::new(dns::HostnameRegistry::new(
            "aaaa1", true,
        )));
        let reporter = crate::net::provider::OwnAddressReporter::new(
            Arc::clone(&registry),
            sessions::SessionId::nil(),
        );
        // One declared port: host :8080 forwards to the box's :80.
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
        };

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `socketpair` with a valid domain/type either returns -1
        // (checked) or fills `fds` with two fresh descriptors.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let tap_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let mut box_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            tap_fd,
            ControlChannel::Unix(control_path),
            LEASE,
            "web",
            Some(&policy),
            Some(&reporter),
            false,
        )
        .await
        .expect("the attach completes against the stand-in");
        // The attach's own traffic first: the binds and the registrations.
        let _attach_events = collect_until(&mut events_rx, "/services/dns/add", 2).await;

        // The switch side of the box's relay, hijacked from the control
        // upgrade.
        let mut switch_end = handed_rx
            .recv()
            .await
            .expect("the attach upgrades exactly one control connection");

        // A client connects to the declared port: its SYN is admitted by the
        // ingress gate and reaches the box.
        let syn = tcp_segment((CLIENT, 40000), (LEASE, 80), 1000, 0, SYN);
        write_framed_stream(&mut switch_end, &syn)
            .await
            .expect("the switch accepts the client's SYN");
        let reached = read_box_end_frame(&box_end)
            .await
            .expect("the declared port admits the connection");
        assert_eq!(reached, syn, "the SYN reaches the box unchanged");

        // The box answers: its SYN-ACK rides the relay back to the switch.
        let syn_ack = tcp_segment((LEASE, 80), (CLIENT, 40000), 5000, 1001, SYN | ACK);
        box_end.write_all(&syn_ack).unwrap();
        let answered = read_framed_stream(&mut switch_end)
            .await
            .expect("the box's answer rides the relay");
        assert_eq!(answered, syn_ack, "the SYN-ACK reaches the client");

        // The client completes the handshake, and the box confirms: the
        // connection is established and held by the forwarder's port.
        let client_ack = tcp_segment((CLIENT, 40000), (LEASE, 80), 1001, 5001, ACK);
        write_framed_stream(&mut switch_end, &client_ack)
            .await
            .expect("the switch accepts the handshake's last leg");
        let confirmed = read_box_end_frame(&box_end)
            .await
            .expect("the box sees the connection established");
        assert_eq!(confirmed, client_ack);

        // The revocation: the port's ingress is withdrawn while the box
        // stays up.
        guard
            .revoke_ingress(8080)
            .await
            .expect("the declared port's forwarder unbinds");

        // The connection the port held is terminated: its reset — built from
        // the last packet the gate saw of the flow, so it rides the flow's
        // own sequence pair — is on the switch side.
        let reset = read_framed_stream(&mut switch_end)
            .await
            .expect("the revoked port's connection is terminated at once");
        assert_reset_terminated(&reset, (LEASE, 80), (CLIENT, 40000), 5001, 1001);
        assert!(
            box_end_is_silent(&box_end),
            "the reset is the switch's refusal, not the box's: nothing else \
             was forwarded"
        );

        // And the port stays refused: a fresh connection attempt to it is
        // answered with a reset at the gate and never reaches the box.
        let retry = tcp_segment((CLIENT, 40001), (LEASE, 80), 2000, 0, SYN);
        write_framed_stream(&mut switch_end, &retry)
            .await
            .expect("the switch accepts the retry");
        let refused = read_framed_stream(&mut switch_end)
            .await
            .expect("a revoked port refuses instantly");
        assert_reset_terminated(&refused, (LEASE, 80), (CLIENT, 40001), 0, 2001);
        assert!(
            box_end_is_silent(&box_end),
            "a revoked port's connection attempt never reaches the box"
        );

        // The unbind reached the switch: the forwarder's unexpose is on the
        // control channel.
        let events = collect_until(&mut events_rx, "/services/forwarder/unexpose", 1).await;
        assert_eq!(
            locals_of(&events, "/services/forwarder/unexpose"),
            vec!["127.0.0.1:8080"],
            "the revoked port's forwarder is unbound: {events:?}"
        );

        // The log names the revocation: the port, the connection it ended,
        // and the reason.
        let log = capture.contents();
        assert!(
            log.contains("unbinding ingress forwarder")
                && log.contains("port=8080")
                && log.contains("terminated=1"),
            "the revocation says what it ended: {log}"
        );

        // A port no forwarder was bound for is refused by name.
        let err = guard
            .revoke_ingress(9999)
            .await
            .expect_err("an undeclared port has no forwarder to revoke");
        assert!(
            err.to_string().contains("9999"),
            "the refusal names the port it was asked for: {err}"
        );
        fake.abort();
    }

    /// Asserts `frame` is the reset that terminated the connection
    /// `(src, sport) → (dst, dport)`, built from that flow's own last
    /// packet: tuple swapped, RST|ACK, and the sequence pair the caller
    /// observed — `seq` what the sender expected next from the box, `ack`
    /// what the box acknowledged of the sender's stream.
    fn assert_reset_terminated(
        frame: &[u8],
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        seq: u32,
        ack: u32,
    ) {
        assert_eq!(frame.len(), 14 + 20 + 20, "an Ethernet + IPv4 + TCP reset");
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes(), "EtherType IPv4");
        assert_eq!(frame[23], crate::net::switch::IPPROTO_TCP);
        let source = (
            Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]),
            u16::from_be_bytes([frame[34], frame[35]]),
        );
        let destination = (
            Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]),
            u16::from_be_bytes([frame[36], frame[37]]),
        );
        assert_eq!(source, src, "the reset rides the connection's own tuple");
        assert_eq!(destination, dst);
        let read_seq = u32::from_be_bytes([frame[38], frame[39], frame[40], frame[41]]);
        let read_ack = u32::from_be_bytes([frame[42], frame[43], frame[44], frame[45]]);
        assert_eq!(read_seq, seq, "the reset rides the flow's sequence pair");
        assert_eq!(read_ack, ack);
        assert_eq!(frame[47], 0x14, "RST|ACK: a termination, not an answer");
    }
}
