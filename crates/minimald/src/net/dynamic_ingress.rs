//! Dynamic ingress: a `min net expose <port>` request decided against the
//! box's `dynamic_ingress` setting (NET-043, NET-044, NET-047).
//!
//! The request arrives as one shape whatever host it is evaluated on
//! ([`ExposeRequest`](minimald_rpc::ExposeRequest)); on an un-enrolled host
//! the local daemon evaluates it here. [`evaluate`] is the decision: the
//! request is checked against what the box can publish at all (an address
//! of its own, an unprivileged port, a transport the forwarder carries), then
//! against the box's `dynamic_allowed_range`, and only then against its
//! `dynamic_ingress` setting. [`expose`] acts on an `allow`: the port is
//! bound at the box's published address, admitted into the running box's
//! relay and switch forward when the box is running, and the mapping is
//! written into the box's ingress policy, where `min session policy` lists
//! it, each step rolled back when the next fails, so a refused or failed
//! request leaves no partial mapping — not in the zone, not on the switch,
//! not in the policy.
//!
//! An `ask` is answered here as a refusal: nobody is prompted yet, so nobody
//! is attached to answer (NET-045's failure case). Prompting the attached
//! human and recording each decision in the audit log (NET-046) build on this
//! module.

use std::sync::{Arc, RwLock};

use minimald_rpc::{ExposeRefusal, ExposeResponse};
use sessions::{DynamicIngress, IpProto, NetworkMode, PortMapping, Record};
use tokio::sync::Mutex;

use super::SwitchClient;
use super::dns::HOSTNAME_SUFFIX;
use super::publish::{DeclaredPort, Forwarders, PublishTable, port_answer};
use crate::store::SessionRecordHandle;

/// What a request evaluated against the box's setting is decided, short of
/// a refusal: publish it, or ask the attached human first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The box's `dynamic_ingress` is `allow` and the port is within its
    /// range: publish the port.
    Allow,
    /// The box's `dynamic_ingress` is `ask`: the attached human decides.
    Ask,
}

/// Decides a request to publish `port` of the box `record` describes, over
/// `proto`, against the box's policy (NET-043).
///
/// The checks run from what the box can publish at all to what it chose to:
/// a box with no address of its own has nowhere to publish the port, a
/// privileged port and a transport the forwarder cannot carry are never
/// published, a port the policy already maps is not mapped twice, a port
/// outside the box's `dynamic_allowed_range` is refused whatever the
/// decision says (NET-047), and only a request that passes all of that
/// reaches the `dynamic_ingress` setting: `allow` and `ask` are decisions,
/// `deny` and no setting at all are refusals, each named as itself (NET-044).
///
/// # Errors
///
/// The typed [`ExposeRefusal`] naming why the request is refused.
pub fn evaluate(record: &Record, port: u16, proto: IpProto) -> Result<Decision, ExposeRefusal> {
    if record.network != NetworkMode::OwnIp {
        return Err(ExposeRefusal::NoOwnAddress {
            mode: record.network,
        });
    }
    if !matches!(proto, IpProto::Tcp | IpProto::Udp) {
        return Err(ExposeRefusal::UnsupportedProtocol { proto });
    }
    if port < 1024 {
        return Err(ExposeRefusal::PrivilegedPort { port });
    }
    let ingress = record.policy.ingress.as_ref();
    if ingress.is_some_and(|ingress| {
        ingress
            .port_mappings
            .iter()
            .any(|m| m.internal_port == port || m.external_port == port)
    }) {
        return Err(ExposeRefusal::AlreadyPublished { port });
    }
    if let Some((lo, hi)) = ingress.and_then(|ingress| ingress.dynamic_allowed_range)
        && !(lo..=hi).contains(&port)
    {
        return Err(ExposeRefusal::OutOfRange { port, lo, hi });
    }
    match record.policy.dynamic_ingress {
        Some(DynamicIngress::Allow) => Ok(Decision::Allow),
        Some(DynamicIngress::Ask) => Ok(Decision::Ask),
        Some(DynamicIngress::Deny) => Err(ExposeRefusal::Denied),
        None => Err(ExposeRefusal::Unset),
    }
}

/// Serves one expose request for the box `handle` holds the record of: the
/// decision, and on an `allow` the publication (NET-044).
///
/// The port is bound at the box's published address first; then, when the
/// box is running on `switch`, it is admitted into the box's live ingress —
/// the switch forward that carries the port to its lease and the relay gate
/// that admits the connection, so the port answers without a relaunch; then
/// it is added to the box's publication and written into its ingress
/// policy, from where a later attach applies it. A failure at any step
/// undoes the steps before it, so the box's zone entry, its live ingress and
/// its policy either all carry the port or none does (NET-047). One info
/// line per request names the box, the port, the decision and the outcome.
///
/// # Errors
///
/// The store's error when the record cannot be read, or cannot be written
/// once the port is bound — the port is unbound again before it returns.
pub async fn expose(
    handle: &SessionRecordHandle,
    published: &RwLock<PublishTable>,
    switch: &Arc<Mutex<SwitchClient>>,
    port: u16,
    proto: IpProto,
) -> Result<ExposeResponse, std::io::Error> {
    let record = handle.record().await?;
    let session_name = crate::session::registry_name(&record);
    let setting = record
        .policy
        .dynamic_ingress
        .map_or_else(|| "unset".to_string(), |d| d.to_string());
    let refuse = |reason: ExposeRefusal| {
        tracing::info!(
            session_id = %record.id,
            box_name = %session_name,
            port,
            %proto,
            decision = %setting,
            outcome = "refused",
            reason = %reason,
            "dynamic ingress request refused"
        );
        ExposeResponse::Refused { reason }
    };

    match evaluate(&record, port, proto) {
        Ok(Decision::Allow) => {}
        Ok(Decision::Ask) => return Ok(refuse(ExposeRefusal::NobodyToAsk)),
        Err(reason) => return Ok(refuse(reason)),
    }

    // The address first, then the bind outside the lock: a bind is a syscall
    // away, and the table is read by the answerer on every lookup.
    let Some((address, kind)) = published
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .published_at(&session_name)
    else {
        return Ok(refuse(ExposeRefusal::NotPublished));
    };
    let declared = DeclaredPort {
        port,
        answer: port_answer(kind, proto, port),
    };
    let forwarders = match Forwarders::bind(address, &[declared]).await {
        Ok(forwarders) => forwarders.admitted_by(DynamicIngress::Allow),
        Err(failure) => {
            return Ok(refuse(ExposeRefusal::PortHeld {
                port,
                address: failure.address,
                error: failure.error.to_string(),
            }));
        }
    };
    let mapping = PortMapping {
        external_port: port,
        internal_port: port,
        proto,
    };

    // A running box takes the port now: the forward on the switch and the
    // gate at its tap are fixed at attach, so without this the port would
    // answer only after a relaunch. A box that is not running has nothing
    // to admit into; the recorded mapping applies at its next attach.
    let live = switch.lock().await.live_boxes().get(&session_name);
    if let Some(live) = &live
        && let Err(error) = live.admit(&mapping).await
    {
        forwarders.unbind().await;
        return Ok(refuse(ExposeRefusal::NotForwarded {
            port,
            error: error.to_string(),
        }));
    }

    if !published
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .add_ports(&session_name, forwarders)
    {
        // Withdrawn between the read and now; the forwarders dropped with
        // the refused add, so the port is unbound again.
        if let Some(live) = &live {
            live.retract(&mapping).await;
        }
        return Ok(refuse(ExposeRefusal::NotPublished));
    }

    let mut new_record = record.clone();
    new_record
        .policy
        .ingress
        .get_or_insert_with(Default::default)
        .port_mappings
        .push(mapping.clone());
    if let Err(error) = handle.write(new_record).await {
        // The policy did not take the mapping, so neither the zone nor the
        // running box may keep the port: unbound, delisted and retracted, as
        // if never requested.
        let unbinding = published
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove_port(&session_name, port);
        if let Some(unbinding) = unbinding {
            unbinding.finished().await;
        }
        if let Some(live) = &live {
            live.retract(&mapping).await;
        }
        tracing::error!(
            session_id = %record.id,
            box_name = %session_name,
            port,
            %error,
            "could not record a dynamic ingress mapping; the port was unbound again"
        );
        return Err(error);
    }

    let hostname = format!("{session_name}.{HOSTNAME_SUFFIX}").to_ascii_lowercase();
    tracing::info!(
        session_id = %record.id,
        box_name = %session_name,
        port,
        %proto,
        decision = %setting,
        outcome = "published",
        %address,
        running = live.is_some(),
        "dynamic ingress request published a port"
    );
    Ok(ExposeResponse::Published {
        hostname,
        address,
        mapping,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    use minimald_rpc::{
        Errorable, Expose, ExposeRefusal, ExposeRequest, ExposeResponse, GetSessionPolicy,
        GetSessionPolicyRequest,
    };
    use sessions::core::net_verdict::{DropRule, EgressRules, Verdict};
    use sessions::{DynamicIngress, IngressPolicy, IpProto, NetworkMode, SessionId};
    use tokio::net::TcpStream;

    use super::*;
    use crate::net::gvproxy_network::LiveIngress;
    use crate::net::policy::{BoxDeclaration, ControlChannel};
    use crate::net::publish::{ForwarderState, PublishedBox};
    use crate::net::switch::AdmittedPorts;
    use crate::test_harness::{TestClient, TestServer, create_session_req, unwrap_ready};

    /// Every daemon here publishes its first own-address box at the same
    /// address, the first the reserved range leases, and the tests run side
    /// by side on one host — so each test takes a port of its own from this
    /// range, and none races another's forwarder for it.
    const RANGE: (u16, u16) = (18_400, 18_499);

    /// Creates, configures and finalizes an own-address box named `name`
    /// with the given `dynamic_ingress` setting and dynamic range.
    async fn own_ip_box(
        client: &mut TestClient,
        name: &str,
        setting: Option<DynamicIngress>,
        range: Option<(u16, u16)>,
    ) -> SessionId {
        use minimald_rpc::{
            ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, FinalizeSession,
            FinalizeSessionRequest,
        };
        let mut req = create_session_req(name, "/uwu");
        req.config.network = NetworkMode::OwnIp;
        req.config.policy.dynamic_ingress = setting;
        req.config.policy.ingress = range.map(|range| IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: Some(range),
        });
        let id = client.call::<CreateSession>(&req).await.unwrap().id;
        unwrap_ready(
            client
                .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                    session_id: id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );
        match client
            .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
            .await
        {
            Errorable::Ok(_) => id,
            Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
        }
    }

    /// The request `min net expose <port>` sends, over the local RPC.
    async fn expose_rpc(client: &mut TestClient, id: SessionId, port: u16) -> ExposeResponse {
        match client
            .call::<Expose>(&ExposeRequest {
                id,
                port,
                proto: IpProto::Tcp,
            })
            .await
        {
            Errorable::Ok(response) => response,
            Errorable::Err { error } => panic!("Expose RPC failed: {error}"),
        }
    }

    /// The mappings `min session policy` lists for the box.
    async fn listed_mappings(client: &mut TestClient, id: SessionId) -> Vec<PortMapping> {
        client
            .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(id))
            .await
            .unwrap()
            .ingress
            .map(|ingress| ingress.port_mappings)
            .unwrap_or_default()
    }

    /// The box's entry in the zone the answerer serves.
    async fn entry(server: &TestServer, name: &str) -> PublishedBox {
        let zone = server.state.sessions_manager().await.published();
        let entries = zone.read().unwrap().entries();
        entries
            .into_iter()
            .find(|e| e.hostname == format!("{name}.min.internal"))
            .unwrap_or_else(|| panic!("{name} is published"))
    }

    /// Asserts nothing of `port` is left on the box: not in its policy, not
    /// in the zone, and nothing bound at its address (NET-047).
    async fn assert_no_mapping(
        server: &TestServer,
        client: &mut TestClient,
        id: SessionId,
        name: &str,
        port: u16,
    ) {
        assert!(
            listed_mappings(client, id).await.is_empty(),
            "{name}'s policy must list no mapping"
        );
        let entry = entry(server, name).await;
        assert!(
            !entry.ports.contains(&port),
            "{name} must not publish {port}: {:?}",
            entry.ports
        );
        assert!(
            entry.forwarders.iter().all(|p| p.port != port),
            "{name} must hold no forwarder for {port}: {:?}",
            entry.forwarders
        );
        // A privileged port is never bound by the daemon and may not be
        // bindable by the test either; for the rest, the address is free.
        if port >= 1024 {
            let free = TcpListener::bind((entry.address, port)).unwrap_or_else(|e| {
                panic!("{}:{port} must be free after a refusal: {e}", entry.address)
            });
            drop(free);
        }
    }

    /// NET-043: on an un-enrolled host the one request shape `min net
    /// expose` sends reaches the local daemon's RPC and is decided by the
    /// box's `dynamic_ingress` setting alone: the same port on four boxes
    /// is published under `allow`, refused under `deny`, refused for want of
    /// someone to ask under `ask`, and refused where nothing is declared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_unenrolled_local_rpc_evaluates_dynamic_ingress() {
        const PORT: u16 = 18_410;
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let allow = own_ip_box(&mut client, "allowing", Some(DynamicIngress::Allow), None).await;
        let deny = own_ip_box(&mut client, "denying", Some(DynamicIngress::Deny), None).await;
        let ask = own_ip_box(&mut client, "asking", Some(DynamicIngress::Ask), None).await;
        let unset = own_ip_box(&mut client, "silent", None, None).await;

        let allowed = expose_rpc(&mut client, allow, PORT).await;
        assert!(
            matches!(
                allowed,
                ExposeResponse::Published { ref hostname, ref mapping, .. }
                    if hostname == "allowing.min.internal" && mapping.internal_port == PORT
            ),
            "allow publishes: {allowed:?}"
        );
        assert_eq!(
            expose_rpc(&mut client, deny, PORT).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::Denied
            }
        );
        assert_eq!(
            expose_rpc(&mut client, ask, PORT).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::NobodyToAsk
            }
        );
        assert_eq!(
            expose_rpc(&mut client, unset, PORT).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::Unset
            },
            "a box that declares nothing refuses, and says so"
        );
        // A box with no address of its own has nowhere to publish the port.
        let host_address =
            crate::test_harness::create_configured_session(&mut client, "shared", "/uwu").await;
        assert_eq!(
            expose_rpc(&mut client, host_address, PORT).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::NoOwnAddress {
                    mode: NetworkMode::HostNet
                }
            }
        );
    }

    /// NET-044: a request decided `allow` publishes the port — it is in the
    /// zone at the box's own address, a forwarder answers it, the
    /// published-port table marks it as admitted by the allow — and the
    /// mapping shows in `min session policy`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_allow_publishes_and_lists() {
        const PORT: u16 = 18_420;
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let id = own_ip_box(&mut client, "web", Some(DynamicIngress::Allow), Some(RANGE)).await;

        let response = expose_rpc(&mut client, id, PORT).await;
        let ExposeResponse::Published {
            hostname,
            address,
            mapping,
        } = response
        else {
            panic!("an allow must publish: {response:?}");
        };
        assert_eq!(hostname, "web.min.internal");
        assert_eq!(
            mapping,
            PortMapping {
                external_port: PORT,
                internal_port: PORT,
                proto: IpProto::Tcp
            }
        );

        assert_eq!(listed_mappings(&mut client, id).await, vec![mapping]);

        let entry = entry(&server, "web").await;
        assert_eq!(entry.address, address);
        assert_eq!(entry.ports, vec![PORT]);
        assert_eq!(entry.forwarders.len(), 1);
        assert_eq!(entry.forwarders[0].port, PORT);
        assert_eq!(entry.forwarders[0].state, ForwarderState::Bound);
        assert_eq!(entry.forwarders[0].admitted, Some(DynamicIngress::Allow));
        TcpStream::connect((address, PORT))
            .await
            .unwrap_or_else(|e| panic!("{address}:{PORT} must answer once published: {e}"));
    }

    /// NET-044: a request decided `deny` is refused with the typed error,
    /// and nothing of it is published.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_deny_typed_error() {
        const PORT: u16 = 18_430;
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let id = own_ip_box(
            &mut client,
            "closed",
            Some(DynamicIngress::Deny),
            Some(RANGE),
        )
        .await;

        let response = expose_rpc(&mut client, id, PORT).await;
        assert_eq!(
            response,
            ExposeResponse::Refused {
                reason: ExposeRefusal::Denied
            }
        );
        let ExposeResponse::Refused { reason } = response else {
            unreachable!()
        };
        assert!(
            reason.to_string().contains("dynamic_ingress"),
            "the refusal names the setting: {reason}"
        );
        assert_no_mapping(&server, &mut client, id, "closed", PORT).await;
    }

    /// NET-047: a request that is out of range or not permitted leaves no
    /// partial mapping: not in the policy, not in the zone, nothing bound —
    /// and a port already mapped is not mapped twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_rejected_leaves_no_partial_mapping() {
        const PORT: u16 = 18_440;
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let id = own_ip_box(
            &mut client,
            "ranged",
            Some(DynamicIngress::Allow),
            Some(RANGE),
        )
        .await;

        assert_eq!(
            expose_rpc(&mut client, id, 9000).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::OutOfRange {
                    port: 9000,
                    lo: RANGE.0,
                    hi: RANGE.1
                }
            }
        );
        assert_no_mapping(&server, &mut client, id, "ranged", 9000).await;

        assert_eq!(
            expose_rpc(&mut client, id, 80).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::PrivilegedPort { port: 80 }
            }
        );
        assert_no_mapping(&server, &mut client, id, "ranged", 80).await;

        // A port already published stays published once: the second
        // request is refused and the policy still lists one mapping.
        assert!(matches!(
            expose_rpc(&mut client, id, PORT).await,
            ExposeResponse::Published { .. }
        ));
        assert_eq!(
            expose_rpc(&mut client, id, PORT).await,
            ExposeResponse::Refused {
                reason: ExposeRefusal::AlreadyPublished { port: PORT }
            }
        );
        assert_eq!(listed_mappings(&mut client, id).await.len(), 1);
        assert_eq!(entry(&server, "ranged").await.ports, vec![PORT]);
    }

    /// A stand-in for gvproxy's control socket: answers every forwarder verb
    /// with `status` and records each request's path and body.
    async fn fake_switch(
        dir: &std::path::Path,
        status: u16,
    ) -> (ControlChannel, Arc<std::sync::Mutex<Vec<(String, String)>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = dir.join("gvproxy-api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut raw = Vec::new();
                let mut buf = [0u8; 1024];
                let (head_end, body_len) = loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0, "request cut short");
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..end]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (end + 4, len);
                    }
                };
                while raw.len() < head_end + body_len {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0, "body cut short");
                    raw.extend_from_slice(&buf[..n]);
                }
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let path = head.split_whitespace().nth(1).unwrap().to_string();
                let body = String::from_utf8_lossy(&raw[head_end..head_end + body_len]).to_string();
                seen.lock().unwrap().push((path, body));
                stream
                    .write_all(
                        format!("HTTP/1.1 {status} Reply\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        (ControlChannel::Unix(path), requests)
    }

    /// Registers `name` as a box running on the daemon's switch, leased
    /// `lease` and reached over `control`, as its attach would: in the box
    /// zone, in the declarations, and among the live boxes. Returns the ports
    /// its relay's gate admits.
    async fn running_box(
        server: &TestServer,
        name: &str,
        lease: Ipv4Addr,
        control: ControlChannel,
    ) -> Arc<AdmittedPorts> {
        let switch = server.state.net_switch().await;
        let (box_zone, admissions, live_boxes) = {
            let switch = switch.lock().await;
            (switch.box_zone(), switch.admissions(), switch.live_boxes())
        };
        box_zone.register(name, lease, None);
        admissions.write().unwrap().declare(
            name,
            BoxDeclaration::for_own_address(lease, EgressRules::for_box(lease, None, None), None),
        );
        let ports = Arc::new(AdmittedPorts::for_ingress(None));
        live_boxes.register(
            name,
            Arc::new(LiveIngress::new(
                control,
                lease,
                Arc::clone(&ports),
                vec![],
                box_zone,
                admissions,
                name,
            )),
        );
        ports
    }

    /// What the daemon's hostname proxy decides for a request to `name`'s
    /// box on `port` from a process on the host.
    async fn routed_verdict(server: &TestServer, name: &str, port: u16) -> Verdict {
        let admissions = server.state.box_admissions().await;
        let admissions = admissions.read().unwrap();
        admissions.verdict(IpAddr::V4(Ipv4Addr::LOCALHOST), name, port)
    }

    /// NET-044: a request decided `allow` for a box that is running admits
    /// the port into the box as it runs — the switch gets the forward to the
    /// box's lease, the relay's gate admits the port, a sibling's verdict and
    /// the hostname proxy name it declared — so the port answers with no
    /// relaunch; and a retraction reverses each of those.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_on_a_running_box_forwards_on_the_switch_and_admits_at_its_tap() {
        const PORT: u16 = 18_450;
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let id = own_ip_box(
            &mut client,
            "running",
            Some(DynamicIngress::Allow),
            Some(RANGE),
        )
        .await;
        let dir = tempfile::TempDir::new().unwrap();
        let (control, requests) = fake_switch(dir.path(), 200).await;
        let lease = Ipv4Addr::new(100, 64, 0, 9);
        let ports = running_box(&server, "running", lease, control).await;
        assert_eq!(
            routed_verdict(&server, "running", PORT).await,
            Verdict::Drop(DropRule::UndeclaredPort),
            "nothing is declared before the request"
        );

        let response = expose_rpc(&mut client, id, PORT).await;
        let ExposeResponse::Published { mapping, .. } = response else {
            panic!("an allow on a running box publishes: {response:?}");
        };
        assert_eq!(
            listed_mappings(&mut client, id).await,
            vec![mapping.clone()]
        );

        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1, "one forward posted: {requests:?}");
            let (path, body) = &requests[0];
            assert_eq!(path, "/services/forwarder/expose");
            assert!(
                body.contains(&format!("\"local\":\"127.0.0.1:{PORT}\""))
                    && body.contains(&format!("\"remote\":\"{lease}:{PORT}\""))
                    && body.contains("\"protocol\":\"tcp\""),
                "the forward carries the host port to the box's lease: {body}"
            );
        }
        assert!(
            ports.admits(IpProto::Tcp, PORT),
            "the relay's gate admits the port"
        );
        let zone = server.state.box_zone().await;
        assert_eq!(
            zone.target_at(lease, IpProto::Tcp, PORT)
                .map(|t| t.ingress.to_string()),
            Some("declared".to_string()),
            "a sibling's verdict names the port declared"
        );
        assert_eq!(
            routed_verdict(&server, "running", PORT).await,
            Verdict::Admit
        );

        // Retracted, each of those is undone and the switch drops the forward.
        let live = server
            .state
            .net_switch()
            .await
            .lock()
            .await
            .live_boxes()
            .get("running")
            .unwrap();
        live.retract(&mapping).await;
        assert!(!ports.admits(IpProto::Tcp, PORT));
        assert_eq!(
            zone.target_at(lease, IpProto::Tcp, PORT)
                .map(|t| t.ingress.to_string()),
            Some("undeclared".to_string())
        );
        assert_eq!(
            routed_verdict(&server, "running", PORT).await,
            Verdict::Drop(DropRule::UndeclaredPort)
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "one unexpose posted: {requests:?}");
        assert_eq!(requests[1].0, "/services/forwarder/unexpose");
        assert!(
            requests[1]
                .1
                .contains(&format!("\"local\":\"127.0.0.1:{PORT}\"")),
            "the unexpose names the forward: {}",
            requests[1].1
        );
    }

    /// NET-047: when the switch refuses the forward for a running box, the
    /// request is refused with the typed error and nothing of it is left —
    /// not at the box's address, not in its gate, not in its policy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_not_forwarded_by_the_switch_leaves_no_partial_mapping() {
        const PORT: u16 = 18_460;
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let id = own_ip_box(
            &mut client,
            "stalled",
            Some(DynamicIngress::Allow),
            Some(RANGE),
        )
        .await;
        let dir = tempfile::TempDir::new().unwrap();
        let (control, requests) = fake_switch(dir.path(), 500).await;
        let lease = Ipv4Addr::new(100, 64, 0, 10);
        let ports = running_box(&server, "stalled", lease, control).await;

        let response = expose_rpc(&mut client, id, PORT).await;
        assert!(
            matches!(
                response,
                ExposeResponse::Refused {
                    reason: ExposeRefusal::NotForwarded { port: PORT, .. }
                }
            ),
            "the switch's refusal is the typed error: {response:?}"
        );
        assert_no_mapping(&server, &mut client, id, "stalled", PORT).await;
        assert!(!ports.admits(IpProto::Tcp, PORT), "the gate admits nothing");
        assert_eq!(
            routed_verdict(&server, "stalled", PORT).await,
            Verdict::Drop(DropRule::UndeclaredPort)
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "the one refused attempt: {requests:?}");
    }

    /// The pure decision, checked from what a box can publish to what it
    /// chose to: mode, transport and privilege before the range, the range
    /// before the setting.
    #[test]
    fn evaluate_orders_the_refusals() {
        let mut record = Record {
            id: SessionId::nil(),
            name: Some("r".to_string()),
            username: None,
            project_path: paths::HostAbsPath::try_new("/p").unwrap(),
            network: NetworkMode::OwnIp,
            policy: sessions::SessionPolicy::new(
                None,
                Some(IngressPolicy {
                    port_mappings: vec![],
                    dynamic_allowed_range: Some((3000, 4000)),
                }),
            ),
            status: sessions::SessionStatus::Active,
            hooks_enabled: true,
            attrs: Default::default(),
        };
        record.policy.dynamic_ingress = Some(DynamicIngress::Allow);
        assert_eq!(evaluate(&record, 3000, IpProto::Tcp), Ok(Decision::Allow));
        assert_eq!(evaluate(&record, 4000, IpProto::Udp), Ok(Decision::Allow));
        assert_eq!(
            evaluate(&record, 4001, IpProto::Tcp),
            Err(ExposeRefusal::OutOfRange {
                port: 4001,
                lo: 3000,
                hi: 4000
            })
        );
        assert_eq!(
            evaluate(&record, 443, IpProto::Tcp),
            Err(ExposeRefusal::PrivilegedPort { port: 443 })
        );
        assert_eq!(
            evaluate(&record, 3000, IpProto::Icmp),
            Err(ExposeRefusal::UnsupportedProtocol {
                proto: IpProto::Icmp
            })
        );

        record.policy.dynamic_ingress = Some(DynamicIngress::Ask);
        assert_eq!(evaluate(&record, 3000, IpProto::Tcp), Ok(Decision::Ask));
        assert_eq!(
            evaluate(&record, 9000, IpProto::Tcp),
            Err(ExposeRefusal::OutOfRange {
                port: 9000,
                lo: 3000,
                hi: 4000
            }),
            "the range is checked before the setting"
        );

        record.policy.dynamic_ingress = None;
        record.policy.ingress = None;
        assert_eq!(
            evaluate(&record, 3000, IpProto::Tcp),
            Err(ExposeRefusal::Unset)
        );
        record.policy.dynamic_ingress = Some(DynamicIngress::Allow);
        assert_eq!(
            evaluate(&record, 65535, IpProto::Tcp),
            Ok(Decision::Allow),
            "no range leaves every unprivileged port to the setting"
        );

        record.network = NetworkMode::NoNet;
        assert_eq!(
            evaluate(&record, 3000, IpProto::Tcp),
            Err(ExposeRefusal::NoOwnAddress {
                mode: NetworkMode::NoNet
            })
        );
    }
}
