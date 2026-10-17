//! The guest's own DNS listener (NET-141 slice 2): what a deny-all
//! host-address box's lookups meet inside a VM-backed guest.
//!
//! The guest classifier dstnats the deny subtree's UDP-53 lookups onto a
//! loopback listener on the answerer's port — free inside a guest, where the
//! in-VM daemon starts no box-zone answerer — and denies everything but the
//! reply direction and that listener, so a deny-all box that cannot resolve
//! out-of-zone names at the switch's resolver (the interim NET-079 carve-out
//! admitted the gateway's port 53 whole) now meets a listener that refuses
//! every name outside the box zone instead: nothing outside the machine is
//! asked. In-zone questions are refused unless every one of them is a type-A
//! question for a name the switch's resolver answers itself
//! ([`answered_on_the_switch`], NET-141), and those — the zone's own A
//! records, `host.min.internal` among them — are forwarded to the switch
//! gateway's port 53 alone (NET-003), the one resolver left to ask.
//!
//! Deliberately narrower than the relay's [`super::dns_gate`]: the gate also
//! answers a zone name the switch would send upstream with NXDOMAIN
//! (NET-006), while the guest's table steers lookups here only from a
//! deny-all box, whose every question outside the switch's own zone match is
//! refused regardless. The listener does not consult the box zone
//! (`boxes::core::zone_answer`): on a VM host the zone is the VM host
//! daemon's to serve (NET-138), so an in-guest listener answering zone
//! names itself would answer stale.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::RecordType;
use tokio::net::UdpSocket;

use super::SwitchSubnet;
use super::answerer::{ANSWERER_PORT, bind_answerer};
use super::dns_gate::answered_on_the_switch;

/// The `component` field every guest listener log line carries, matching the
/// answerer's `zone-answerer` convention.
const COMPONENT: &str = "guest-dns";

/// Largest datagram the listener reads: a DNS query fits far below this
/// (queries are tens of bytes), and a larger datagram is dropped rather than
/// buffered unbounded.
const MAX_DATAGRAM: usize = 4096;

/// The port the listener forwards the zone's A questions to: the switch
/// gateway's resolver (NET-003), as the default subnet spells it.
const DNS_PORT: u16 = 53;

/// The listener's address and port — the one pair the guest's own classifier
/// render names too: the table the render loads steers the deny subtree's
/// DNS-port lookups onto the listener this module binds, so the pair lives
/// here, where the bind is, and the render reads it from here rather than
/// either side guessing at the other. The port is the answerer's own
/// (NET-141), free inside a guest where the in-VM daemon starts no
/// box-zone answerer.
pub const LISTENER_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const LISTENER_PORT: u16 = ANSWERER_PORT;

/// How long a forwarded question waits for the gateway's answer before the
/// exchange is dropped: a resolver stack that asked will retry on its own
/// schedule, so the listener holds no state for a slow upstream beyond this.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Starts the guest's DNS listener on the answerer's port at the guest's
/// loopback, for the daemon's lifetime, forwarding the zone's A questions to
/// `subnet`'s gateway.
///
/// Called by the guest's boot after the classifier is up (the table steers
/// the lookups; the listener answers them), and only inside a VM-backed
/// guest, where the port is the listener's by design — on the host the
/// box-zone answerer holds it. A bind that fails is logged and left: the
/// guest's table still loads and still denies, and every lookup fails loudly
/// in the log instead of silently on the wire.
pub async fn start(subnet: SwitchSubnet) {
    let addr = SocketAddr::new(LISTENER_ADDRESS.into(), LISTENER_PORT);
    let gateway = SocketAddr::new(subnet.dns_server().into(), DNS_PORT);
    let socket = match bind_answerer(addr).await {
        Ok(socket) => socket,
        Err(failure) => {
            tracing::error!(
                component = COMPONENT,
                remedy = %failure.remedy,
                "the guest's DNS listener could not bind {addr}: {}",
                failure.reason
            );
            return;
        }
    };
    tracing::info!(
        component = COMPONENT,
        %addr,
        status = "listening",
        "the guest's DNS listener is serving; a deny-all box's lookups refuse \
         outside the zone and forward the zone's A questions to {gateway}"
    );
    // The serve task runs for the daemon's lifetime; its handle is dropped
    // on purpose — nothing ever aborts it, because nothing ever rebinds. The
    // socket is shared with the forward tasks, each of which sends its
    // reply from the listener's own address, so the loop's socket is an
    // `Arc` the spawned sends borrow.
    drop(crate::traced::spawn(async move {
        if let Err(error) = serve(Arc::new(socket), gateway).await {
            tracing::error!(
                component = COMPONENT,
                %error,
                "the guest's DNS listener receive loop exited"
            );
        }
    }));
}

/// Serves the listener on a bound socket: one datagram per turn, each either
/// answered here, forwarded to the gateway, or dropped — an oversized
/// datagram, something that does not parse as a standard query, or a
/// forwarded reply that never came. A reply that cannot be sent is logged
/// and skipped: a peer that vanished mid-exchange must not take the listener
/// down.
async fn serve(socket: Arc<UdpSocket>, gateway: SocketAddr) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let datagram = &buf[..len];
        let query = match parse(datagram) {
            Some(query) => query,
            None => continue,
        };
        let verdict = decide(&query);
        let reply = match verdict {
            Decision::Answer(rcode) => answer(&query, rcode),
            Decision::Forward => {
                // The forward runs as its own task so a slow upstream holds
                // no other lookup's turn: the relay's discipline, applied to a
                // listener that has one socket for every peer. The reply is
                // sent from a clone, so the loop's receive is never taken.
                let listener = socket.clone();
                let datagram = datagram.to_vec();
                drop(crate::traced::spawn(async move {
                    forward(listener, gateway, datagram, peer).await;
                }));
                continue;
            }
        };
        if let Some(reply) = reply
            && let Err(error) = socket.send_to(&reply, peer).await
        {
            tracing::debug!(
                component = COMPONENT,
                %peer,
                %error,
                "could not send the guest listener's reply"
            );
        }
    }
}

/// What the listener does with one parsed query.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Reply `rcode` here, nothing forwarded.
    Answer(ResponseCode),
    /// Send the query's datagram to the gateway unmodified.
    Forward,
}

/// Parses one datagram into a standard DNS query, or `None` — the listener's
/// parse discipline, mirroring the relay's ([`super::dns_gate`]): a datagram
/// that is oversized, does not parse, or is not a query is dropped rather than
/// answered with an invented reply.
fn parse(datagram: &[u8]) -> Option<Message> {
    if datagram.len() > MAX_DATAGRAM {
        tracing::debug!(
            component = COMPONENT,
            n = datagram.len(),
            "dropping an oversized DNS query at the guest listener"
        );
        return None;
    }
    let query = match Message::from_vec(datagram) {
        Ok(query) => query,
        Err(error) => {
            tracing::debug!(
                component = COMPONENT,
                %error,
                "dropping an unparseable DNS query at the guest listener"
            );
            return None;
        }
    };
    if query.metadata.message_type != MessageType::Query {
        return None;
    }
    Some(query)
}

/// The verdict for one parsed query, mirroring the gate's [`decide`] minus the
/// NXDOMAIN leg: every question is read, not only the first, so a name
/// behind the first cannot ride a query the first one let through. A box
/// whose table steers lookups here is deny-all by construction, so the gate's
/// deny_all guard is the caller: any question naming something outside the
/// switch's own zone match is refused — the apex and a zone suffix not in
/// exact lowercase among them, both of which the gateway would send
/// upstream. What is left is in-zone, and refused empty (NET-136, NET-006)
/// unless every question is a type-A question for a name the switch answers
/// itself (NET-141) — the zone's A records, which the listener forwards to
/// the gateway alone.
fn decide(query: &Message) -> Decision {
    let questions = || query.queries.iter();
    // REFUSED (NET-141): answered here, so no resolver beyond the guest —
    // not even the gateway's — ever sees the name.
    if questions().any(|q| !answered_on_the_switch(q.name())) {
        return Decision::Answer(ResponseCode::Refused);
    }
    // NODATA (NET-136, NET-006): an AAAA, HTTPS or SVCB question, or a zone
    // name's question of any type but A — the switch's resolver answers a
    // zone A itself and sends every other type on to the host's resolvers,
    // which a deny-all box must not reach.
    let nodata = questions().find(|q| {
        let rtype = q.query_type();
        matches!(
            rtype,
            RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
        ) || (rtype != RecordType::A && answered_on_the_switch(q.name()))
    });
    match nodata {
        Some(_) => Decision::Answer(ResponseCode::NoError),
        // Every question is an in-zone A question for a name the switch's
        // resolver answers itself: the gateway's to answer (NET-003).
        None => Decision::Forward,
    }
}

/// The reply the listener writes back for `query` instead of forwarding it:
/// `rcode`, every question echoed back, no answers, and the query's id, so
/// the box's resolver stack matches the reply to its own query. The log line
/// names `name` and `rtype`, the question that decided `rcode`.
fn answer(query: &Message, rcode: ResponseCode) -> Option<Vec<u8>> {
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata = Metadata::response_from_request(&query.metadata);
    reply.metadata.response_code = rcode;
    reply.add_queries(query.queries.clone());
    let question = query.queries.first();
    let name = question.map_or_else(String::new, |q| q.name().to_string());
    tracing::debug!(
        component = COMPONENT,
        name = %name,
        query_type = ?question.map_or(RecordType::A, |q| q.query_type()),
        answer = ?rcode,
        "answered a lookup at the guest listener instead of forwarding it"
    );
    reply.to_vec().ok()
}

/// Forwards one query's datagram to the gateway verbatim and relays the
/// gateway's reply verbatim: the listener holds no opinion about the wire
/// format beyond the verdicts above, so an EDNS option or an unknown
/// record type the verdict let through survives the trip. A reply that
/// never comes — the timeout, a socket error — is dropped: the box's
/// resolver stack retries on its own schedule.
async fn forward(
    listener: Arc<UdpSocket>,
    gateway: SocketAddr,
    datagram: Vec<u8>,
    peer: SocketAddr,
) {
    let forward_socket =
        match UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await {
            Ok(socket) => socket,
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %error,
                    "could not open a socket to forward a lookup to {gateway}"
                );
                return;
            }
        };
    if let Err(error) = forward_socket.send_to(&datagram, gateway).await {
        tracing::debug!(
            component = COMPONENT,
            %error,
            "could not forward a lookup to {gateway}"
        );
        return;
    }
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let reply =
        match tokio::time::timeout(FORWARD_TIMEOUT, forward_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => buf[..len].to_vec(),
            Ok(Err(error)) => {
                tracing::debug!(
                    component = COMPONENT,
                    %error,
                    "the gateway {gateway} would not take a forwarded lookup"
                );
                return;
            }
            Err(_) => {
                tracing::debug!(
                    component = COMPONENT,
                    "a forwarded lookup to {gateway} timed out unanswered"
                );
                return;
            }
        };
    if let Err(error) = listener.send_to(&reply, peer).await {
        tracing::debug!(
            component = COMPONENT,
            %peer,
            %error,
            "could not send the gateway's reply to a forwarded lookup"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_proto::op::{Message, Metadata, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::net::UdpSocket;

    use super::{Decision, MAX_DATAGRAM, decide, parse};

    /// The guest's listener verdict for one query message, as [`decide`]
    /// returns it, named for the assertion that reads it.
    #[track_caller]
    fn assert_decision(query: &Message, expected: Decision, why: &str) {
        assert_eq!(decide(query), expected, "{why}");
    }

    /// The default subnet's gateway, as the listener forwards to it.
    fn gateway() -> std::net::SocketAddr {
        std::net::SocketAddr::new(crate::net::SwitchSubnet::default().dns_server().into(), 53)
    }

    /// One standard query message carrying `questions`, built with
    /// `Name::from_ascii`, which keeps the case as given — the form a box's
    /// resolver stack actually sends on the wire.
    fn query_of(questions: &[(String, RecordType)]) -> Message {
        let mut query = Message::query();
        for (name, rtype) in questions {
            query.add_query(hickory_proto::op::Query::query(
                Name::from_ascii(name).expect("the test name parses"),
                *rtype,
            ));
        }
        query
    }

    /// A REFUSED verdict for an out-of-zone A question: the name the issue's
    /// field report asks a deny-all box to resolve, answered here so no
    /// resolver beyond the guest ever sees it.
    #[test]
    fn out_of_zone_a_is_refused() {
        let query = query_of(&[("example.com.".to_string(), RecordType::A)]);
        assert_decision(
            &query,
            Decision::Answer(ResponseCode::Refused),
            "a name outside the box zone is refused, not forwarded",
        );
    }

    /// REFUSED covers every record type outside the zone: the carve-out the
    /// interim design admitted (the gateway on port 53) answered out-of-zone
    /// AAAA and TXT alike from off the machine.
    #[test]
    fn out_of_zone_non_a_is_refused() {
        for rtype in [RecordType::AAAA, RecordType::TXT] {
            let query = query_of(&[("example.com.".to_string(), rtype)]);
            assert_decision(
                &query,
                Decision::Answer(ResponseCode::Refused),
                "an out-of-zone question is refused regardless of type",
            );
        }
    }

    /// The apex, and a zone suffix not in exact lowercase, are refused:
    /// both name the zone in a form the switch's resolver would send
    /// upstream, so neither is the listener's to forward — deliberately
    /// narrower than the relay's NXDOMAIN leg, which answers them by name.
    #[test]
    fn apex_and_non_lowercase_suffix_are_refused() {
        for name in ["min.internal.", "x.MIN.INTERNAL."] {
            let query = query_of(&[(name.to_string(), RecordType::A)]);
            assert_decision(
                &query,
                Decision::Answer(ResponseCode::Refused),
                "{name} names the zone in a form the gateway would forward: refused",
            );
        }
    }

    /// An in-zone question that is not type A is answered NODATA: the
    /// gateway answers the zone's A records itself and sends every other
    /// type upstream, which a deny-all box must not reach. A mixed query —
    /// an A and a TXT, both in-zone — is NODATA too: every question is
    /// read, so the TXT cannot ride the A.
    #[test]
    fn zone_non_a_and_mixed_are_nodata() {
        let txt = query_of(&[("host.min.internal.".to_string(), RecordType::TXT)]);
        assert_decision(
            &txt,
            Decision::Answer(ResponseCode::NoError),
            "a zone TXT is answered empty, not forwarded",
        );
        let mixed = query_of(&[
            ("host.min.internal.".to_string(), RecordType::A),
            ("host.min.internal.".to_string(), RecordType::TXT),
        ]);
        assert_decision(
            &mixed,
            Decision::Answer(ResponseCode::NoError),
            "a query with any non-A zone question is answered empty",
        );
        // And one out-of-zone question refuses the whole query, even beside
        // an in-zone A: the verdict is per query, and every question is read.
        let ridden = query_of(&[
            ("host.min.internal.".to_string(), RecordType::A),
            ("example.com.".to_string(), RecordType::A),
        ]);
        assert_decision(
            &ridden,
            Decision::Answer(ResponseCode::Refused),
            "an out-of-zone question refuses the query it rides in",
        );
    }

    /// An in-zone A question is forwarded — and its datagram reaches the
    /// gateway verbatim, and the gateway's reply reaches the box: the
    /// exchange a deny-all box's `getent ahostsv4 host.min.internal` makes,
    /// answered by the node's DNS layer (NET-003) through this listener.
    #[tokio::test]
    async fn zone_a_forwards_to_the_gateway_and_relays_the_reply() {
        // A stand-in gateway on an OS-assigned loopback port, standing in
        // for the default switch's gateway: it records the datagram it was
        // handed and answers with one of its own.
        let standin = UdpSocket::bind(std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            0,
        ))
        .await
        .expect("a stand-in gateway binds a loopback port");
        let gateway = standin.local_addr().expect("the stand-in names its port");

        // The listener, served over the same loopback discipline the boot
        // uses, pointed at the stand-in.
        let listener = UdpSocket::bind(std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            0,
        ))
        .await
        .expect("the test listener binds a loopback port");
        let relay = listener.local_addr().expect("the listener names its port");
        let served = crate::traced::spawn(super::serve(listener.into(), gateway));

        // One in-zone A query, sent as a datagram from a stand-in box.
        let query = query_of(&[("host.min.internal.".to_string(), RecordType::A)]);
        let datagram = query.to_vec().expect("the query encodes");
        let box_socket = UdpSocket::bind(std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            0,
        ))
        .await
        .expect("a stand-in box binds a loopback port");
        box_socket
            .send_to(&datagram, relay)
            .await
            .expect("the box's lookup reaches the listener");

        // The gateway sees the query's datagram verbatim — id, questions,
        // everything the box sent.
        let mut buf = vec![0u8; super::MAX_DATAGRAM];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), standin.recv_from(&mut buf))
            .await
            .expect("the gateway is asked")
            .expect("the forwarded datagram arrives");
        assert_eq!(&buf[..len], &datagram[..], "the datagram is verbatim");
        let forwarded = Message::from_vec(&buf[..len]).expect("the forwarded query parses");
        assert_eq!(forwarded.metadata.id, query.metadata.id);

        // The gateway's reply is relayed back to the box verbatim.
        let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
        reply.metadata = Metadata::response_from_request(&query.metadata);
        reply.metadata.response_code = ResponseCode::NoError;
        let reply_bytes = reply.to_vec().expect("the reply encodes");
        standin
            .send_to(&reply_bytes, from)
            .await
            .expect("the gateway answers");
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), box_socket.recv_from(&mut buf))
            .await
            .expect("the box is answered")
            .expect("the relayed reply arrives");
        assert_eq!(&buf[..len], &reply_bytes[..], "the reply is verbatim");

        served.abort();
    }

    /// A datagram that is not a standard query is dropped — no reply, and
    /// nothing forwarded: the listener never invents an answer for a payload
    /// it cannot parse.
    #[tokio::test]
    async fn non_dns_payload_is_dropped() {
        let listener = UdpSocket::bind(std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            0,
        ))
        .await
        .expect("the test listener binds a loopback port");
        let relay = listener.local_addr().expect("the listener names its port");
        let gateway = gateway();
        let served = crate::traced::spawn(super::serve(listener.into(), gateway));

        let box_socket = UdpSocket::bind(std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            0,
        ))
        .await
        .expect("a stand-in box binds a loopback port");
        let payload = b"not a dns query at all".to_vec();
        box_socket
            .send_to(&payload, relay)
            .await
            .expect("the payload reaches the listener");

        // No reply ever comes: nothing answers a payload that does not parse.
        // The probe returns the length of anything that does arrive, so an
        // `Ok` here is a reply that never should have come.
        let mut buf = vec![0u8; super::MAX_DATAGRAM];
        let received = tokio::time::timeout(
            Duration::from_millis(250),
            Box::pin(async {
                loop {
                    match box_socket.recv_from(&mut buf).await {
                        Ok((len, _)) if len > 0 => return Some(len),
                        Ok(_) => continue,
                        Err(_) => return None,
                    }
                }
            }),
        )
        .await;
        assert!(
            matches!(received, Err(_) | Ok(None)),
            "the listener never answers a non-DNS payload: {received:?}"
        );
        served.abort();
    }

    /// The listener's zone match is the switch's own (NET-141): in-zone A
    /// names below the apex forward, and the match is
    /// [`answered_on_the_switch`] verbatim, case included — a name whose
    /// zone suffix is not the exact lowercase form the switch answers is
    /// not the switch's to answer, so the listener refuses it rather than
    /// forward what the gateway would send upstream.
    #[test]
    fn zone_match_is_the_switchs_own() {
        let query = query_of(&[
            ("host.min.internal.".to_string(), RecordType::A),
            ("apex.min.internal.".to_string(), RecordType::A),
        ]);
        assert_decision(
            &query,
            Decision::Forward,
            "in-zone A names below the apex forward",
        );
        let cased = query_of(&[("host.MIN.internal.".to_string(), RecordType::A)]);
        assert_decision(
            &cased,
            Decision::Answer(ResponseCode::Refused),
            "a zone suffix not in the exact lowercase form is refused",
        );
    }

    /// An oversized datagram is dropped by [`parse`] without a reply: the
    /// listener buffers nothing unbounded.
    #[test]
    fn oversized_datagram_is_dropped_by_parse() {
        assert!(parse(&[0u8; MAX_DATAGRAM + 1]).is_none());
    }
}
