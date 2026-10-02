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
    use std::collections::{BTreeSet, HashMap};
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::path::PathBuf;
    use std::sync::Arc;

    use sandbox2::NetGuard as _;
    use switch::MacAddr;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
    use tokio::sync::{Mutex, mpsc, oneshot};

    use crate::net::PtaskLease;
    use crate::net::SwitchClient;
    use crate::net::SwitchTransport;
    use crate::net::dns;
    use crate::net::policy::{ControlChannel, register_dns_name};
    use crate::net::provider::network_for;
    use crate::test_harness::CaptureWriter;
    use sessions::BoxAddresses;

    /// The fake gvproxy's answer for a request it serves happily.
    fn ok() -> (u16, String) {
        (200, String::new())
    }

    /// One `"key":"value"` string field of a JSON body — the stand-ins' own
    /// read of the forwarder verbs' requests.
    fn json_string_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
        body.split(&format!("\"{key}\":\""))
            .nth(1)?
            .split('"')
            .next()
    }

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
    /// status and reason body `decide` picks for `(path, body)`, and recorded
    /// as `(path, body)` on `events` in arrival order — the order the
    /// attach's binds and registrations happened in. The `/connect` upgrade
    /// is hijacked the way the real switch hijacks it: no response is
    /// written, and the upgraded stream is handed to the test, which becomes
    /// the switch side of the box's relay for as long as it holds it.
    ///
    /// Abort the returned handle when the test is done; the fake accepts
    /// until then.
    fn spawn_control_channel_deciding(
        path: PathBuf,
        decide: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
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
                let (status, reason_body) = decide(&request_path, &body);
                let reason = match status {
                    200..=299 => "OK",
                    403 => "Forbidden",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Answered",
                };
                let mut response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                    reason_body.len()
                )
                .into_bytes();
                response.extend_from_slice(reason_body.as_bytes());
                sock.write_all(&response)
                    .await
                    .expect("the fake gvproxy must answer");
                events
                    .send((request_path, body))
                    .await
                    .expect("the test is still collecting the control requests");
            }
        })
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

    /// Three declared ports — one more than any one attach can bind before a
    /// refusal — so a proof can show the rollback of a half-bound box: two
    /// bound, the third refused, and the two unbound with it.
    fn declared_three_ports() -> sessions::SessionPolicy {
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
                    sessions::PortMapping {
                        external_port: 7070,
                        internal_port: 70,
                        proto: sessions::IpProto::Tcp,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
        }
    }

    /// One failed-bind scenario's pieces: the control path its stand-in
    /// listens on, the registry the box's name would publish in, the
    /// reporter that would report it, and the relay's own two ends — the
    /// box's half held for its life, never read, so the box stays reachable
    /// for as long as the scenario runs — everything but the fake that
    /// answers and the attach itself.
    struct AttachScenario {
        control_path: PathBuf,
        registry: Arc<std::sync::RwLock<dns::HostnameRegistry>>,
        reporter: crate::net::provider::OwnAddressReporter,
        tap_fd: std::os::fd::OwnedFd,
        _box_end: std::fs::File,
    }

    /// Builds one scenario inside `dir`, on its own `socket`, so a test can
    /// drive two attaches without one's traffic landing on the other's
    /// stand-in or registry.
    fn attach_scenario(dir: &tempfile::TempDir, socket: &str) -> AttachScenario {
        let control_path = dir.path().join(socket);
        let registry = Arc::new(std::sync::RwLock::new(dns::HostnameRegistry::new(
            "aaaa1", true,
        )));
        let reporter = crate::net::provider::OwnAddressReporter::new(
            Arc::clone(&registry),
            sessions::SessionId::nil(),
        );
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
        let box_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        AttachScenario {
            control_path,
            registry,
            reporter,
            tap_fd,
            _box_end: box_end,
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
            spawn_control_channel_deciding(control_path.clone(), |_, _| ok(), events_tx, handed_tx);
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

    /// NET-121's sub 2, both shapes of a bind that did not land:
    ///
    /// A *gate refusal* — the switch answering an expose with a refusal, the
    /// way the session gate answers a port the box's row does not declare —
    /// is a failed bind exactly like a bind that errored: the attach fails,
    /// neither the name nor any substitute address is published for the
    /// refused port, and the refusal's own reason reaches the caller beside
    /// the port, in the returned error and in the warn line.
    ///
    /// And either shape rolls the whole half back: the ports that *did* bind
    /// are unexposed before the attach gives up, so a half-bound box holds
    /// nothing — the rollback is asserted per shape, not by extrapolating
    /// from one port's.
    #[tokio::test]
    async fn failed_forwarder_bind_is_reported_not_substituted() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        let capture = crate::test_harness::captured_log();
        let dir = tempfile::TempDir::new().unwrap();

        // Shape one: the gate refuses the third of three declared ports,
        // with the reason a real gate refusal carries.
        let refused = attach_scenario(&dir, "gvproxy.sock");
        let (refused_events_tx, mut refused_events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let refused_fake = spawn_control_channel_deciding(
            refused.control_path.clone(),
            |path, body| {
                if path == "/services/forwarder/expose" && body.contains("127.0.0.1:7070") {
                    (403, "port 7070 is not declared on this row".to_string())
                } else {
                    ok()
                }
            },
            refused_events_tx,
            handed_tx,
        );
        let refused_switch = vm_host_switch();
        let refused_policy = declared_three_ports();
        let err = match crate::net::gvproxy_network::complete_own_ip_attach(
            &refused_switch,
            refused.tap_fd,
            ControlChannel::Unix(refused.control_path.clone()),
            LEASE,
            "web",
            Some(&refused_policy),
            Some(&refused.reporter),
            false,
        )
        .await
        {
            Ok(_) => panic!("a refused bind must fail the attach like a failed one"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("7070")
                && err.to_string().contains("not declared on this row"),
            "the refusal names its port and carries the reason the gate gave: {err}"
        );

        // Every declared port was attempted — the refusal is answered, not
        // anticipated — and both binds that landed are rolled back with it:
        // a half-bound box holds nothing.
        let events = collect_until(&mut refused_events_rx, "/services/forwarder/unexpose", 2).await;
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec!["127.0.0.1:8080", "127.0.0.1:9090", "127.0.0.1:7070"],
            "all three binds were attempted: {events:?}"
        );
        assert_eq!(
            locals_of(&events, "/services/forwarder/unexpose"),
            vec!["127.0.0.1:8080", "127.0.0.1:9090"],
            "the binds that succeeded are rolled back with the refused one: {events:?}"
        );
        assert!(
            !events.iter().any(|(p, _)| p == "/services/dns/add"),
            "a refused bind publishes no name: {events:?}"
        );
        let held = refused
            .registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held,
            crate::net::dns::ZoneEntry::Absent,
            "no substitute address stands in for the refused bind: {held:?}"
        );
        // The refusal is the log's own fact, said per port: the declared
        // number, and the reason the gate gave, in the same warn line.
        let log = capture.contents();
        assert!(
            log.contains("binding declared ingress port failed")
                && log.contains("port=7070")
                && log.contains("port 7070 is not declared on this row"),
            "the refused bind says its line with the port and the reason: {log}"
        );
        refused_fake.abort();

        // Shape two: a bind that errors — the real forwarder answering a
        // bind failure — fails the attach the same way, on its own ports.
        let failed = attach_scenario(&dir, "gvproxy-2.sock");
        let (failed_events_tx, mut failed_events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let failed_fake = spawn_control_channel_deciding(
            failed.control_path.clone(),
            |path, body| {
                if path == "/services/forwarder/expose" && body.contains("127.0.0.1:9090") {
                    (500, String::new())
                } else {
                    ok()
                }
            },
            failed_events_tx,
            handed_tx,
        );
        let failed_switch = vm_host_switch();
        let failed_policy = declared_two_ports();
        let err = match crate::net::gvproxy_network::complete_own_ip_attach(
            &failed_switch,
            failed.tap_fd,
            ControlChannel::Unix(failed.control_path.clone()),
            LEASE,
            "web",
            Some(&failed_policy),
            Some(&failed.reporter),
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

        // Both binds attempted, the one that landed rolled back, and no
        // registration — the same shape the refusal proved, on its own ports.
        let events = collect_until(&mut failed_events_rx, "/services/forwarder/unexpose", 1).await;
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
        let held = failed
            .registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held,
            crate::net::dns::ZoneEntry::Absent,
            "no substitute address stands in for the failed bind: {held:?}"
        );
        let log = capture.contents();
        assert!(
            log.contains("binding declared ingress port failed") && log.contains("port=9090"),
            "the failed bind says its line with the port: {log}"
        );
        failed_fake.abort();
    }

    /// A forwarding stand-in: the gvproxy a host-side client can actually
    /// talk to. An expose binds a real host TCP listener at the `local` the
    /// attach named; an unexpose drops that listener and confirms it is gone
    /// *before* the answer goes back, so a revocation that returned has
    /// really unbound the port; and the `/connect` upgrade is driven the
    /// way the real switch drives its half of the relay — a host connection
    /// becomes a leg with its own source port and a fresh SYN toward the
    /// box's `remote`, the frames that come back are answered (a SYN-ACK
    /// earns the handshake's last ACK), and a reset closes the leg's host
    /// socket, the way the real forwarder ends its side of a connection the
    /// box terminated.
    ///
    /// Every frame the stand-in reads off the relay is copied to
    /// `switch_frames`, in arrival order, for the proof to inspect.
    ///
    /// The order the daemon's revocation takes — the gate's reset queued
    /// before the unexpose request is written — cannot be shown as one wire
    /// order by a stand-in that sees the relay and the control channel as
    /// two connections, so each half is pinned where it is observable: the
    /// reset is read off the relay and only its arrival closes the host
    /// socket, and the unexpose is answered only after the listener is
    /// confirmed dropped.
    fn spawn_forwarder_gvproxy(
        path: PathBuf,
        events: mpsc::Sender<(String, String)>,
        switch_frames: mpsc::Sender<Vec<u8>>,
    ) -> tokio::task::JoinHandle<()> {
        // One live forward by its `local` address: the channel that tells
        // its accept loop to drop its listener.
        let forwards: Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<oneshot::Sender<()>>>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        // Accepted host sockets, on their way to the switch side with the
        // box-side address their forward targets.
        let (accepted_tx, accepted_rx) = mpsc::channel(4);
        let mut accepted_rx = Some(accepted_rx);
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
                    // response; this stand-in *is* the switch side from here
                    // on.
                    if let Some(accepted_rx) = accepted_rx.take() {
                        tokio::spawn(switch_side(sock, switch_frames.clone(), accepted_rx));
                    }
                    continue;
                }
                let request_path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let body = String::from_utf8_lossy(&body).into_owned();
                // The stand-in's own answers: a forward it can bind answers
                // 200; a bind that fails answers 500 — a failed bind, which
                // the attach reports; an unexpose for a forward it holds
                // drops the listener first, and one it does not hold
                // answers 404, the real switch's answer for a name it
                // never bound.
                let (status, reason_body) = match (request_path.as_str(), body.as_str()) {
                    ("/services/forwarder/expose", _) => {
                        let local = json_string_field(&body, "local").unwrap_or_default();
                        let remote = json_string_field(&body, "remote").unwrap_or_default();
                        let bind = local.rsplit_once(':').and_then(|(host, port)| {
                            Some((host.parse::<IpAddr>().ok()?, port.parse::<u16>().ok()?))
                        });
                        let target = remote.rsplit_once(':').and_then(|(ip, port)| {
                            Some((ip.parse::<Ipv4Addr>().ok()?, port.parse::<u16>().ok()?))
                        });
                        match (bind, target) {
                            (Some((host, port)), Some(target)) => {
                                match TcpListener::bind((host, port)).await {
                                    Ok(bound) => {
                                        let (stop_tx, stop_rx) = mpsc::channel(1);
                                        forwards
                                            .lock()
                                            .expect("the stand-in's forwards lock")
                                            .insert(local.to_string(), stop_tx);
                                        let accepted_tx = accepted_tx.clone();
                                        tokio::spawn(async move {
                                            let mut stop_rx = stop_rx;
                                            let stopped: Option<oneshot::Sender<()>> = loop {
                                                tokio::select! {
                                                    accepted = bound.accept() => {
                                                        match accepted {
                                                            Ok((socket, _)) => {
                                                                if accepted_tx
                                                                    .send((socket, target))
                                                                    .await
                                                                    .is_err()
                                                                {
                                                                    break None;
                                                                }
                                                            }
                                                            Err(_) => break None,
                                                        }
                                                    }
                                                    confirm = stop_rx.recv() => {
                                                        break confirm;
                                                    }
                                                }
                                            };
                                            drop(bound);
                                            if let Some(confirm) = stopped {
                                                let _ = confirm.send(());
                                            }
                                        });
                                        ok()
                                    }
                                    Err(_) => (500, "bind failed".to_string()),
                                }
                            }
                            _ => (500, "malformed forward request".to_string()),
                        }
                    }
                    ("/services/forwarder/unexpose", _) => {
                        let local = json_string_field(&body, "local").unwrap_or_default();
                        let stop = forwards
                            .lock()
                            .expect("the stand-in's forwards lock")
                            .remove(local);
                        match stop {
                            Some(stop) => {
                                let (confirm_tx, confirm_rx) = oneshot::channel();
                                if stop.send(confirm_tx).await.is_ok() {
                                    let _ = confirm_rx.await;
                                }
                                ok()
                            }
                            None => (404, "no forward bound for that local".to_string()),
                        }
                    }
                    _ => ok(),
                };
                let reason = match status {
                    200..=299 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Answered",
                };
                let mut response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                    reason_body.len()
                )
                .into_bytes();
                response.extend_from_slice(reason_body.as_bytes());
                sock.write_all(&response)
                    .await
                    .expect("the forwarding stand-in must answer");
                events
                    .send((request_path, body))
                    .await
                    .expect("the test is still collecting the control requests");
            }
        })
    }

    /// The switch side of the relay, as the forwarding stand-in drives it:
    /// every accepted host socket becomes a leg with its own source port,
    /// whose SYN rides the relay toward the box; the box's answers are
    /// completed (a SYN-ACK earns the last ACK) and its resets end the
    /// leg — closing the host socket, which is where the client's
    /// connection ends.
    async fn switch_side(
        mut sock: UnixStream,
        frames: mpsc::Sender<Vec<u8>>,
        mut accepted: mpsc::Receiver<(TcpStream, (Ipv4Addr, u16))>,
    ) {
        // The leg's own address — the source gvproxy's forward legs speak
        // from, on the box's own reserved range.
        const LEG_SOURCE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
        const FIRST_LEG_PORT: u16 = 40000;
        const LEG_ISN: u32 = 1000;
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        const RST: u8 = 0x04;

        // The legs' host sockets, by the leg's source port.
        let mut live: HashMap<u16, TcpStream> = HashMap::new();
        let mut next_leg_port = FIRST_LEG_PORT;
        // The relay's frames, buffered: a read can straddle a frame's
        // length header, so the loop takes whole frames out of the buffer
        // and keeps the rest for the next read.
        let mut buffered: Vec<u8> = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            tokio::select! {
                accepted = accepted.recv() => {
                    let Some((socket, (remote_ip, remote_port))) = accepted else {
                        break;
                    };
                    let leg_port = next_leg_port;
                    next_leg_port += 1;
                    live.insert(leg_port, socket);
                    let syn = tcp_segment(
                        (LEG_SOURCE, leg_port),
                        (remote_ip, remote_port),
                        LEG_ISN,
                        0,
                        SYN,
                    );
                    write_framed_stream(&mut sock, &syn)
                        .await
                        .expect("the leg's SYN rides the relay");
                }
                read = sock.read(&mut scratch) => {
                    let Ok(n) = read else { break };
                    buffered.extend_from_slice(&scratch[..n]);
                    while let Some(frame) = take_framed(&mut buffered) {
                        frames
                            .send(frame.clone())
                            .await
                            .expect("the proof still collects the relay's frames");
                        let destination_port = u16::from_be_bytes([frame[36], frame[37]]);
                        if !live.contains_key(&destination_port) {
                            continue;
                        }
                        let flags = frame[47];
                        if flags & RST != 0 {
                            // The box's connection was terminated at the
                            // gate: the forwarder closes its half, and the
                            // host-side client's connection ends.
                            live.remove(&destination_port);
                            continue;
                        }
                        if flags & SYN != 0 && flags & ACK != 0 {
                            // The box answered the leg's SYN: complete the
                            // handshake on the leg's side.
                            let source_ip =
                                Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
                            let source_port =
                                u16::from_be_bytes([frame[34], frame[35]]);
                            let sequence =
                                u32::from_be_bytes([frame[38], frame[39], frame[40], frame[41]]);
                            let ack = tcp_segment(
                                (LEG_SOURCE, destination_port),
                                (source_ip, source_port),
                                LEG_ISN + 1,
                                sequence + 1,
                                ACK,
                            );
                            write_framed_stream(&mut sock, &ack)
                                .await
                                .expect("the leg completes the handshake");
                        }
                    }
                }
            }
        }
    }

    /// Takes one length-framed frame out of `buffered`, if a whole one is
    /// there — the switch side's own read, which must survive reads that
    /// straddle a frame's header.
    fn take_framed(buffered: &mut Vec<u8>) -> Option<Vec<u8>> {
        let len = u16::from_le_bytes([*buffered.first()?, *buffered.get(1)?]) as usize;
        let frame = buffered.get(2..2 + len)?.to_vec();
        buffered.drain(..2 + len);
        Some(frame)
    }

    /// NET-121's sub 1, proved from the host-side client's view: a declared
    /// port's ingress revoked ends the client's connection at once and
    /// refuses the next one.
    ///
    /// The stand-in gvproxy binds real host listeners for the attach's
    /// exposes, so the client here is a real socket on the host loopback —
    /// not a frame the test writes into the relay. The connection is driven
    /// end to end (the client connects, the stand-in opens the client's leg
    /// through the relay, the test plays the box's half of the handshake),
    /// and then the port is revoked while the box stays up.
    ///
    /// What the revocation owes the client, and what this asserts: the
    /// connection it held *ends* — an EOF or a reset, within the bound
    /// below, never a hang — because the gate terminated the flow it had
    /// tracked: the reset rides the flow's own sequence pair, is addressed
    /// to the leg, and is the last thing the relay ever says, with nothing
    /// further reaching the box. And the next connect to the port is
    /// *refused* — a connection refused, not an accepted-then-dropped —
    /// because the forwarder's unexpose really dropped the host listener
    /// before the revocation returned.
    ///
    /// The order the daemon takes — the gate's reset, then the unexpose —
    /// cannot be shown as one wire order by a stand-in that sees the relay
    /// and the control channel as two connections, so each half is pinned
    /// where it is observable: the reset is read off the relay (and only
    /// its arrival closes the client's socket), and the unexpose is answered
    /// only after the listener is confirmed dropped.
    #[tokio::test]
    async fn ingress_revocation_unbinds_forwarder_and_terminates_connections() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        // The leg's address — the same the stand-in's `switch_side` speaks
        // from, so the assertions below can name it.
        const LEG_SOURCE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
        const LEG_PORT: u16 = 40000;
        const LEG_ISN: u32 = 1000;
        const HOST_PORT: u16 = 48080;
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        const RST: u8 = 0x04;
        // The bound the revocation owes the client its connection's end
        // within — long enough that only a hang, not a scheduling hiccup,
        // overruns it.
        const REVOCATION_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

        let capture = crate::test_harness::captured_log();
        let dir = tempfile::TempDir::new().unwrap();
        let control_path = dir.path().join("gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (frames_tx, mut frames_rx) = mpsc::channel(64);
        let fake = spawn_forwarder_gvproxy(control_path.clone(), events_tx, frames_tx);
        let switch = vm_host_switch();
        let registry = Arc::new(std::sync::RwLock::new(dns::HostnameRegistry::new(
            "aaaa1", true,
        )));
        let reporter = crate::net::provider::OwnAddressReporter::new(
            Arc::clone(&registry),
            sessions::SessionId::nil(),
        );
        // One declared port: host :48080 forwards to the box's :80.
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: HOST_PORT,
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
        .expect("the attach completes against the forwarding stand-in");
        // The attach's own traffic first: the binds and the registrations.
        let _attach_events = collect_until(&mut events_rx, "/services/dns/add", 2).await;

        // A host-side client connects to the declared port — a real socket
        // on the host loopback, at the address the forwarder bound.
        let mut client = TcpStream::connect((IpAddr::from(Ipv4Addr::LOCALHOST), HOST_PORT))
            .await
            .expect("the bound port admits a host-side client");

        // The forwarder opens the client's leg through the relay: the box
        // sees a SYN from the leg's own address, at the port's declared
        // number.
        let syn = read_box_end_frame(&box_end)
            .await
            .expect("the client's connection reaches the box");
        assert_eq!(
            syn,
            tcp_segment((LEG_SOURCE, LEG_PORT), (LEASE, 80), LEG_ISN, 0, SYN),
            "the forwarder's leg SYN arrives from the leg's own address"
        );

        // The box answers, and the leg completes the handshake: the
        // connection is established, and the gate has the flow tracked.
        box_end
            .write_all(&tcp_segment(
                (LEASE, 80),
                (LEG_SOURCE, LEG_PORT),
                5000,
                LEG_ISN + 1,
                SYN | ACK,
            ))
            .unwrap();
        let leg_ack = read_box_end_frame(&box_end)
            .await
            .expect("the leg completes the handshake");
        assert_eq!(
            leg_ack,
            tcp_segment((LEG_SOURCE, LEG_PORT), (LEASE, 80), LEG_ISN + 1, 5001, ACK),
            "the handshake's last leg rides the relay"
        );

        // The revocation: the port's ingress is withdrawn while the box
        // stays up.
        guard
            .revoke_ingress(HOST_PORT)
            .await
            .expect("the declared port's forwarder unbinds");

        // The client's connection ends within the bound: an EOF — the
        // forwarder closing its half of a connection the gate terminated —
        // or the reset itself; never a hang, and never data.
        let ended = tokio::time::timeout(REVOCATION_BOUND, client.read(&mut [0u8; 1]))
            .await
            .expect("the revoked port ends the client's connection within the bound");
        match ended {
            Ok(0) => {}
            Ok(n) => panic!("the revoked connection delivered {n} bytes, not an end"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ),
                "the revoked connection ended with an error that is not a reset: {e}"
            ),
        }

        // The next connect to the port is refused — the listener is gone,
        // not a forwarder that accepts and drops.
        let refused = TcpStream::connect((IpAddr::from(Ipv4Addr::LOCALHOST), HOST_PORT)).await;
        assert!(
            matches!(&refused, Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused),
            "a revoked port refuses new connections instead of accepting them: {refused:?}"
        );

        // The reset that ended the connection is the gate's, not the box's:
        // built from the flow the gate had tracked — the flow's own sequence
        // pair, addressed to the leg — and the last thing the relay said.
        let reset = loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(5), frames_rx.recv())
                .await
                .expect("the gate's reset rides the relay")
                .expect("the switch side keeps tapping the relay's frames");
            let destination_port = u16::from_be_bytes([frame[36], frame[37]]);
            if frame[47] & RST != 0 && destination_port == LEG_PORT {
                break frame;
            }
        };
        assert_reset_terminated(
            &reset,
            (LEASE, 80),
            (LEG_SOURCE, LEG_PORT),
            5001,
            LEG_ISN + 1,
        );
        assert!(
            box_end_is_silent(&box_end),
            "the reset is the gate's refusal, not the box's: nothing else \
             was forwarded"
        );

        // The unbind reached the switch: the forwarder's unexpose is on the
        // control channel, at the same `local` it bound — and by the time
        // the revocation returned, the host listener was already dropped,
        // which is what makes the connect above a refusal.
        let events = collect_until(&mut events_rx, "/services/forwarder/unexpose", 1).await;
        assert_eq!(
            locals_of(&events, "/services/forwarder/unexpose"),
            vec![format!("{}:{HOST_PORT}", Ipv4Addr::LOCALHOST)],
            "the revoked port's forwarder is unbound: {events:?}"
        );

        // The log names the revocation: the port, the connection it ended,
        // and the reason.
        let log = capture.contents();
        assert!(
            log.contains("unbinding ingress forwarder")
                && log.contains(&format!("port={HOST_PORT}"))
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

    /// NET-121's `local` is the box's handed host loopback address (T66):
    /// a box whose registration the VM host daemon completed hands its
    /// host loopback address in with the launch, and the attach's exposes
    /// name exactly that address and the declared port — never `127.0.0.1`,
    /// the node's shared interim a box without a handed address falls back
    /// to (NET-123), and never an address the daemon picked for itself.
    /// The same address comes off again at teardown: what was bound where
    /// it was named is unbound there too.
    ///
    /// The daemon's own registration is the in-guest zone only; host-OS
    /// name publication belongs to the host-side creator whose row handed
    /// the address in — and this proof's registry row stands for that row.
    #[tokio::test]
    async fn local_is_the_handed_loopback_address() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        // The host loopback address the box's registration handed it — the
        // row's own slice of the reserved local range (T66).
        const HANDED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);

        let dir = tempfile::TempDir::new().unwrap();
        let scenario = attach_scenario(&dir, "gvproxy.sock");
        // The host-side registration's row: the box's own address, published
        // by the same stable id the reporter reads back — what `session`'s
        // finalize does for a handed box, standing in for the host-side
        // creator that owns the row.
        scenario
            .registry
            .write()
            .expect("registry lock")
            .publish_own_address(
                sessions::SessionId::nil(),
                "web",
                HANDED,
                BTreeSet::from([8080u16, 9090]),
            );
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake = spawn_control_channel_deciding(
            scenario.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let policy = declared_two_ports();

        let guard = match crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            scenario.tap_fd,
            ControlChannel::Unix(scenario.control_path.clone()),
            LEASE,
            "web",
            Some(&policy),
            Some(&scenario.reporter),
            false,
        )
        .await
        {
            Ok(guard) => guard,
            Err(e) => panic!("the attach completes at the handed address: {e}"),
        };
        let events = collect_until(&mut events_rx, "/services/dns/add", 1).await;

        // The binds name the handed address and the declared ports — never
        // `127.0.0.1`, and never a port number the daemon substituted.
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "every bind names the handed loopback address: {events:?}"
        );

        // Teardown unbinds at the same address it bound: the handed
        // address is the forward's for its whole life, not just its bind.
        Box::new(guard).teardown().await;
        let unbound = collect_until(&mut events_rx, "/services/forwarder/unexpose", 2).await;
        assert_eq!(
            locals_of(&unbound, "/services/forwarder/unexpose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "teardown unbinds every forwarder at the handed address: {unbound:?}"
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
