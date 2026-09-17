---
id: EHE
title: Enrolled box host egress: the gateway association, the policy feed, and the pin
owner: norrietaylor
epic: gominimal/inbox#646
arch: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
updated: 2026-09-16
---

# EHE — Enrolled box host egress: the gateway association, the policy feed, and the pin

## Context

An un-enrolled box host enforces each box's declared egress in its own
host-side helpers ([NET](https://github.com/gominimal/minimal/pull/1380)). Once
a host is enrolled, the architecture moves the escape-surviving floor outside
the host: every box host's egress transits an Egress Gateway that lives outside
its escape boundary, takes its policy from a signed feed, clamps each
association to the host's allocated address blocks, and records honestly, per
host, whether the fabric pins egress to it ([design §1, §4, §5.1, and §7.2 to
§7.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
[architecture
D8](https://github.com/gominimal/arch/blob/main/architecture.md)). This
document binds the box host's side: the daemon that holds the association and
routes egress into it with box source addresses preserved, consumes the feed,
asserts the host's pin, refuses a box that exceeds the host's ceiling, takes
its address blocks from the control plane, keeps local names valid under
enrolment, and stays fully functional with no inbound reachability. The gateway
itself, the feed's issuance, allocation, and the node attributes are the
gateway component's and the identity plane's
([NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md)).

It is written from the same epic as NET and was cut from it (local-first
ordering, 2026-09-15): every requirement here carries a precondition, the host
being enrolled or holding a gateway association, that a local host does not
have. NET is its prerequisite: the per-box source-addressed rules, the
two-identity classifier, and DNS-pinned admission that a host applies locally
(NET-060 to NET-085) are what the association carries to the gateway. EHE-001
and EHE-002 implement the enrolment clause of NET's first story: the local
names carry over when the host enrols, and tenant-zone names are listed first.

After this ships, a box on an enrolled cloud VM, pod, or managed-platform host
reaches exactly its declared egress at the gateway; an escapee with root on the
host reaches only the union of resident boxes' declared egress plus the
baseline set; a host in a private subnet with no public address receives policy
and is reachable through the relay tier; and policy can keep secret-bearing
boxes off hosts whose pin is not enforced.

**Success:** on an enrolled host with a gateway association, a box's allowed
destination completes at the gateway and a denied one is dropped; a process
with root on the host spoofing another box's address reaches nothing outside
the resident union plus the baseline set; and a box whose egress exceeds the
host's ceiling fails at creation naming the rule.

**First slice:** the host consumes a signed policy feed, rejecting sequence
regression and persisting the high-water (EHE-008, EHE-009), and routes all
egress into its gateway association with each own-address box's source
preserved (EHE-003, EHE-004), against a gateway that applies the feed.

## Users and stories

**Roles:** platform engineer running box hosts on cloud VMs, platform engineer running box hosts as pods, platform engineer writing policy, platform engineer, platform engineer standing up a box host in a private subnet, platform engineer running box hosts for several teams

- AS A platform engineer running box hosts on cloud VMs, I WANT the host's fabric rule to admit only its Egress Gateway on both address families, with the gateway enforcing each box's declared egress from the signed policy feed, SO THAT my compliance story does not depend on container isolation holding.
- AS A platform engineer running box hosts as pods, I WANT a default-deny egress NetworkPolicy plus allow-to-gateway to be the entire fabric pin, SO THAT I need no FQDN-capable CNI.
- AS A platform engineer writing policy, I WANT every box host to carry `egress_pin` (pinned, pinned_site, advisory, none), asserted by the provider or admin, SO THAT boxes holding brokered secrets can be kept off hosts whose egress floor is not externally enforced.
- AS A platform engineer, I WANT to set a static egress ceiling on a host that every box's rules must fit inside, SO THAT a box that would exceed the host's bound fails at creation, not at first packet.
- AS A platform engineer standing up a box host in a private subnet, I WANT policy delivery, the relay path, and mesh to work with zero inbound reachability, SO THAT I never open an inbound port or assign a public IP to a box host.
- AS A platform engineer running box hosts for several teams, I WANT box and host addresses allocated per tenant from a plan that cannot collide with my RFC 1918 networks and can be renumbered without breaking identity or audit, SO THAT two teams' hosts never collide and a renumbering never invalidates a certificate or an audit trail.

## Requirements

- **EHE-001** WHILE the host is enrolled THE SYSTEM SHALL keep every `*.min.internal` name resolvable on the machine.
  tier:     T0
  verify:   cargo nextest run -p minimald min_internal_survives_enrolment
  <!-- S1a/AC3; prose 4; state-driven; formerly NET-005 -->

- **EHE-002** WHILE the host is enrolled THE SYSTEM SHALL list tenant-zone names before local names in `min net dns` and in box listings.
  tier:     T0
  verify:   cargo nextest run -p minimal dns_listing_prefers_tenant_zone_when_enrolled
  <!-- S1a/AC3; prose 4; state-driven; formerly NET-008 -->

- **EHE-003** WHERE the host holds a gateway association THE SYSTEM SHALL route all egress into the association.
  tier:     T0
  verify:   cargo nextest run -p minimald gateway_attached_routes_all_egress
  <!-- S10b/AC1; prose 55; optional-feature; formerly NET-086 -->

- **EHE-004** WHERE the host holds a gateway association THE SYSTEM SHALL preserve each own-address box's source address into the association without NAT.
  tier:     T0
  verify:   cargo nextest run -p minimald own_ip_source_preserved_into_association
  <!-- S10b/AC1; prose 55; optional-feature; formerly NET-087 -->

- **EHE-005** WHERE the host holds a gateway association THE SYSTEM SHALL source node-netns flows from the node-plane address and host-address cohort flows from the cohort address.
  tier:     T0
  verify:   cargo nextest run -p minimald node_netns_flows_snat_two_addresses
  <!-- S10b/AC1-2; prose 55, 56; optional-feature; formerly NET-088 -->

- **EHE-006** WHERE the host holds a gateway association, IF a process with root on the host spoofs another box's address THEN THE SYSTEM SHALL confine its reach, at the gateway, to the union of resident boxes' declared egress plus the baseline set.
  tier:     T0
  verify:   cargo nextest run -p minimald escape_bounded_at_gateway
  <!-- S10b/AC1; prose 55; feature+unwanted; formerly NET-089 -->

- **EHE-007** WHERE the host holds a gateway association THE SYSTEM SHALL take its baseline set from the deployment configuration.
  tier:     T0
  verify:   cargo nextest run -p minimald baseline_set_from_deployment_config
  <!-- S10b/AC2; prose 56; optional-feature; formerly NET-090 -->

- **EHE-008** WHERE the host holds a gateway association THE SYSTEM SHALL consume the signed policy feed and reject any sequence regression.
  tier:     T2
  verify:   cargo nextest run -p minimald feed_seq_regression_rejected
  property: for every incoming sequence number and every persisted high-water, a feed whose sequence is not greater than the high-water is rejected
  harness:  kani_feed_seq_regression_rejected, exhaustive to an unwind bound of 1 over two 64-bit sequence values; requires the accept/reject decision to be a pure function over the two values, separate from fetch and persistence
  <!-- S10b/AC3; prose 57; optional-feature; formerly NET-091 -->

- **EHE-009** WHERE the host holds a gateway association THE SYSTEM SHALL persist the feed high-water and, on start, refuse to serve until it reloads it or fetches a fresh feed.
  tier:     T0
  verify:   cargo nextest run -p minimald feed_fail_closed_on_start
  <!-- S10b/AC3; prose 57; optional-feature; formerly NET-092 -->

- **EHE-010** WHERE the host is enrolled, WHEN the `min` client enrols a VM-backed laptop host as its provider THE SYSTEM SHALL assert `egress_pin = pinned`.
  tier:     T0
  verify:   cargo nextest run -p minimal localvm_provider_asserts_pinned
  <!-- S11a/AC1; prose 58; feature+event; formerly NET-093 -->

- **EHE-011** WHERE the host is enrolled, WHEN the `min` client enrols a shared Linux host THE SYSTEM SHALL assert an `egress_pin` of `advisory` or `none`.
  tier:     T0
  verify:   cargo nextest run -p minimal shared_linux_asserts_advisory_or_none
  <!-- S11a/AC1; prose 58; feature+event; formerly NET-094 -->

- **EHE-012** WHERE the host is enrolled, IF creation of a box is refused for the host's pin THEN THE SYSTEM SHALL surface the audited error to the user with the pin named.
  tier:     T0
  verify:   cargo nextest run -p minimal min_surfaces_pin_refusal
  <!-- S11a/AC2; prose 59; feature+unwanted; formerly NET-095 -->

- **EHE-013** WHERE the host is enrolled and records a ceiling, IF a box's egress exceeds it THEN THE SYSTEM SHALL fail creation naming the offending rule.
  tier:     T0
  verify:   cargo nextest run -p minimal ceiling_violation_names_rule
  <!-- S11b/AC1; prose 60; feature+unwanted; formerly NET-096 -->

- **EHE-014** WHERE the host is enrolled with no public address and default-deny inbound THE SYSTEM SHALL receive its policy feed.
  tier:     T0
  verify:   cargo nextest run -p minimald outbound_only_host_receives_feed
  <!-- S15/AC1; prose 61; optional-feature; formerly NET-097 -->

- **EHE-015** WHERE the host is enrolled with no public address and default-deny inbound THE SYSTEM SHALL be reachable through the relay tier from a client on another network.
  tier:     T0
  verify:   cargo nextest run -p minimald outbound_only_host_reachable_via_relay
  <!-- S15/AC1; prose 61; optional-feature; formerly NET-098 -->

- **EHE-016** WHERE only TCP/443 egress exists THE SYSTEM SHALL run the gateway association as WireGuard over WebSocket.
  tier:     T0
  verify:   cargo nextest run -p minimald association_falls_back_to_wss
  <!-- S15/AC2; prose 62; optional-feature; formerly NET-099 -->

- **EHE-017** WHERE the host is enrolled THE SYSTEM SHALL accept its address blocks from the control plane and assign box addresses within them.
  tier:     T0
  verify:   cargo nextest run -p minimald enrolled_host_assigns_within_blocks
  <!-- S17/AC1; prose 64; optional-feature; formerly NET-100 -->

- **EHE-018** WHERE the host is enrolled THE SYSTEM SHALL report box address assignments on the heartbeat.
  tier:     T0
  verify:   cargo nextest run -p minimald assignments_reported_on_heartbeat
  <!-- S17/AC1; prose 64; optional-feature; formerly NET-101 -->

- **EHE-019** WHEN a host is renumbered THE SYSTEM SHALL keep every certificate, mesh identity, and audit correlation valid.
  tier:     T0
  verify:   cargo nextest run -p minimald renumber_preserves_identity
  <!-- S17/AC2; prose 65; event-driven; formerly NET-103 -->

## Non-goals

- Everything a box host does with no identity plane: names, the hostname proxy,
  network modes, the un-enrolled dynamic-ingress path, egress rules and their
  local enforcement, the VM stack, and self-allocation from the default plan
  (NET-102): [NET](https://github.com/gominimal/minimal/pull/1380).
- The Egress Gateway itself: its contract is the architecture of record
  ([design
  §4](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md));
  its implementation is the gateway component. This document binds the box
  host's obligations toward it.
- Feed issuance, address allocation, the node attributes that gate scheduling,
  and gateway registration on the identity plane:
  [NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md)
  and [Gatehouse
  §6.11](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).
- Host enrolment, the node record's creation, host listing, and revocation: the
  host-enrolment work (gominimal/inbox#648). Every requirement here assumes an
  enrolled host it does not enrol.
- Public exposure through the gateway and the enrolled dynamic-ingress path:
  [GWI](https://github.com/gominimal/minimal/pull/{GWI_PR}).
- Mesh join and the remote forward, and the gateway's forwarding role for mesh
  and attach traffic on a pinned host ([design
  §4.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)):
  [MRF](https://github.com/gominimal/minimal/pull/{MRF_PR}) for the laptop's
  side; the gateway component for the forwarding role.
- An operator recipe for pods as box hosts (default-deny NetworkPolicy plus
  allow-to-gateway, Kata as the recommended runtime): the Box Provider API's
  operator documentation ([design
  §7.3](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)),
  once a provider implements the pod style. The story is transcribed here
  because the host's obligations under that pin are this document's; no
  requirement here binds a NetworkPolicy.
- The association a grant-holding host maintains with its Box Egress Proxy
  endpoint ([design
  §5.6](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
  schema in gominimal/arch#63): the broker documents (gominimal/inbox#625).
- The relay tier and the daemon's mesh ingress:
  [MMI](https://github.com/gominimal/minimal/pull/1356). EHE-015 assumes a
  relay tier it does not build.
- Documentation naming the exact outbound destinations a box host needs: a
  deliverable of the plan for the outbound-only slice.

## Design reasoning

**Cut from NET by precondition.** Local-first ordering (2026-09-15) made the
un-enrolled local host the near-term target and left the enrolled host's
obligations to be bound separately. Keeping them in one document scoped by
WHERE was the previous shape; it was replaced because it made local slices wait
on an association contract the architecture still marks as a working shape. The
requirements moved unchanged in text and tier; their former NET IDs are
recorded beside each one so the plan and the sibling documents can follow them.

**Every enrolled style, scoped by WHERE.** Requirements name the box host and
are scoped `WHERE the host holds a gateway association` or `WHERE the host is
enrolled`. One document per deployment style was considered and rejected: the
architecture maps every style to one contract ([design
§7](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md))
and the host's obligations do not differ by style; what differs is who programs
the pin, which is the provider's obligation ([Box Provider API
§6.1](https://github.com/gominimal/arch/blob/main/specs/box-provider/box-provider-api.md)),
not this document's.

**The pin is asserted, not measured.** EHE-010 and EHE-011 have the `min`
client assert `pinned` for a VM-backed laptop host and `advisory` or `none` for
a shared Linux host, from the style mapping ([design
§7](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).
The alternative, the host probing its own fabric, was rejected because the
attribute is provider- or admin-asserted by design ([design
§4.4](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md))
and a host inside the escape boundary cannot attest to what is outside it.

**The escape bound at the gateway is a system test.** EHE-006 stays T0 with a
root-on-host spoofer; its universal is the residency clamp the gateway
enforces, not a decision the host owns, so no harness here can exhaust it.

**Tiers.** Feed regression (EHE-008) is T2: the accept-or-reject decision over
an incoming sequence and a persisted high-water is a pure function over two
64-bit values, separable from fetch and persistence, and the tier constrains
the daemon to keep it so. Everything else is T0 with a named test against a
feed fixture or a gateway stub. T3 was refused: the effect shells are an
association, sockets, and a control-plane round trip, which fail the
no-concurrency constraint, and the repository has no Lean project.

**Cross-cutting decisions live in the architecture.** The two-address
node-netns split, feed semantics with the residency clamp, the ceiling and the
honesty attribute, the provisioning handshake, and lifecycle under snapshot and
restore are [design §4.1, §4.3, §4.4, §5.2, and
§5.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
the feed's fields are [Gatehouse
§6.11](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).
This document binds the box host's observable behaviour under them and restates
none of them.

**Generality:** every requirement names the box host or the `min` client and
holds for every enrolled style; a second provider or platform fits by
programming the pin ([design
§7](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md))
and asserting it honestly. What breaks on a style with no external enforcement
point is honesty, not the document: such a host asserts `advisory` or `none`
(EHE-011) and policy keeps secret-bearing boxes off it.

## Security considerations

- **Invariant:** THE SYSTEM SHALL bound the reach of any process on the host,
  root included, at the gateway, to the union of resident boxes' declared
  egress plus the baseline set.
  enforced by: every own-address box's source preserved into the association
  and the gateway's residency clamp over the host's blocks
  ([design §4.3 rule 0 and §8](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md))
  covered by: EHE-004, EHE-006
- **Invariant:** THE SYSTEM SHALL accept no policy feed whose sequence number
  does not exceed the persisted high-water, and serve none before the
  high-water is reloaded or a fresh feed fetched.
  enforced by: the feed consumer's accept decision and persisted high-water
  covered by: EHE-008, EHE-009
- **Invariant:** THE SYSTEM SHALL assert no `egress_pin` stronger than the
  deployment style's fabric enforces.
  enforced by: the pin is asserted from the style mapping, never probed
  covered by: EHE-010, EHE-011
- **Invariant:** THE SYSTEM SHALL create no box whose egress exceeds the
  host's recorded ceiling.
  enforced by: the ceiling check at creation
  covered by: EHE-013

## Open questions

- [NEEDS CLARIFICATION (CRITICAL): what is the node-to-gateway association
  contract: the registration shape, the heartbeat member that carries it, and
  the feed's normative field set? EHE-003 to EHE-009 and EHE-014 to EHE-016
  bind behaviour against a contract the architecture marks as a working shape
  ([design
  §4.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
  [Gatehouse
  §6.11](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md)).]
- [NEEDS CLARIFICATION (MEDIUM): does an enrolled VM-backed laptop host hold a
  gateway association at all, or only the Box Egress Proxy association? [Design
  §7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)
  makes the gateway association optional for a laptop and feed consumption
  there a later increment (§11); EHE-010 asserts `pinned` for it either way,
  and EHE-003 to EHE-009 apply only while an association is held.]
