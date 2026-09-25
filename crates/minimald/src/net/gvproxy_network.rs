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
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use crate::net::dns;
    use crate::net::policy::{ControlChannel, register_dns_name};

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
}
