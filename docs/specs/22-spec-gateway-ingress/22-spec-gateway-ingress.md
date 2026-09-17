---
id: GWI
title: Gateway ingress: public exposure and enrolled dynamic ingress
owner: norrietaylor
epic: gominimal/inbox#646
arch: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
updated: 2026-09-16
---

# GWI — Gateway ingress: public exposure and enrolled dynamic ingress

## Context

A box's port reaches the public Internet only where the deployment offers that
capability and only as an explicitly authorized act ([requirements
UC10](https://github.com/gominimal/arch/blob/main/specs/networking/networking-requirements.md)).
The deployment's gateway translates its public address and port to the box's
over the host's existing association, and an exposure exists only as a feed
entry created under the `ExposeIngress` decision ([design
§6](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
[Gatehouse
§6.11](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md);
[NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md)).
This document binds the box host's and the CLI's side: the clean refusal on a
host that cannot expose, the authorization gate, listing and audit, teardown,
delivery of feed-carried ingress entries to the in-box listener, the
fabric-native variant, and the enrolled path of `min net expose` over the box's
identity socket.

It was cut from [NET](https://github.com/gominimal/minimal/pull/1380)
(local-first ordering, 2026-09-15): public exposure needs a gateway association
or a provider capability that no local host has. NET is its prerequisite: the
un-enrolled `min net expose` path and the allow, deny, ask, and
no-partial-mapping decisions (NET-043 to NET-047) are the same request shape
and the same decisions this document's enrolled path carries to the feed write,
and the parity rule (NET-069 to NET-071) governs every delivered connection.
GWI-008 implements the enrolled clause of NET's in-box publish story.

After this ships, `min net expose --public <port>` publishes where the
deployment can and refuses clearly where it cannot, an unauthenticated party
reaches an authorized port through the deployment's gateway, and the host
itself opens no inbound port.

**Success:** on a gateway-attached host, an authorized `min net expose --public
<port>` is reachable by an unauthenticated party at the gateway's public
address, is listed in `min session policy`, and is gone within 5 seconds of the
box's removal; on a host with no association the same command fails with one
message and changes nothing.

**First slice:** the refusal on every host that has no gateway association and
no fabric-native ingress (GWI-001), which runs end to end on a stock install
today.

## Users and stories

**Roles:** developer who needs a webhook or demo URL reachable by an unauthenticated party, developer on a CloudVM or Cloudflare box host

- AS A developer who needs a webhook or demo URL reachable by an unauthenticated party, I WANT `min net expose --public <port>` to publish the port where the deployment can, and refuse clearly where it cannot, SO THAT public exposure is a deliberate act and I am never left guessing whether it happened.
- AS A developer on a CloudVM or Cloudflare box host, I WANT my authorized public port served by the deployment's gateway over the host's existing association, SO THAT the host itself opens no inbound port.

## Requirements

- **GWI-001** IF `min net expose --public <port>` is run on a host with no gateway association and no fabric-native ingress THEN THE SYSTEM SHALL fail with "public exposure is not available on this host" and change nothing.
  tier:     T0
  verify:   cargo nextest run -p minimal expose_public_unavailable_fails_cleanly
  <!-- S3a/AC1; prose 18; unwanted; formerly NET-028 -->

- **GWI-002** WHERE public exposure is available THE SYSTEM SHALL create a public exposure only after an ExposeIngress authorization.
  tier:     T0
  verify:   cargo nextest run -p minimald public_exposure_requires_authorization
  <!-- S3a/AC2; prose 19; optional-feature; formerly NET-029 -->

- **GWI-003** WHERE public exposure is available THE SYSTEM SHALL list each live public exposure in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimal policy_lists_public_exposure
  <!-- S3a/AC2; prose 19; optional-feature; formerly NET-030 -->

- **GWI-004** WHERE public exposure is available THE SYSTEM SHALL audit each public exposure.
  tier:     T0
  verify:   cargo nextest run -p minimald public_exposure_audited
  <!-- S3a/AC2; prose 19; optional-feature; formerly NET-031 -->

- **GWI-005** WHEN a box or its exposure entry is removed THE SYSTEM SHALL tear its public exposure down within 5 seconds.
  tier:     T0
  verify:   cargo nextest run -p minimald exposure_torn_down_on_removal
  <!-- S3a/AC3; prose 20; event-driven; bound decided at checkpoint 2; formerly NET-032 -->

- **GWI-006** WHERE the host holds a gateway association, WHEN a feed-carried ingress entry for one of its boxes arrives THE SYSTEM SHALL deliver connections on that exposure to the in-box listener per the box's ingress rules.
  tier:     T0
  verify:   cargo nextest run -p minimald feed_ingress_entry_delivered_to_listener
  <!-- S3b/AC1; prose 21; feature+event; formerly NET-033 -->

- **GWI-007** WHERE the provider declares fabric-native gateway ingress THE SYSTEM SHALL serve the same exposure without a gateway hop.
  tier:     T0
  verify:   cargo nextest run -p minimald fabric_native_ingress_serves_exposure
  <!-- S3b/AC2; prose 22; optional-feature; formerly NET-034 -->

- **GWI-008** WHERE the host is enrolled, WHEN `min net expose <port>` is run inside a box THE SYSTEM SHALL carry the request over the box's identity socket to be authorized as ExposeIngress at the feed write.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_enrolled_rides_identity_sock
  <!-- S5/AC1; prose 28; feature+event; formerly NET-042 -->

## Non-goals

- The un-enrolled dynamic-ingress path, the decisions it shares with the
  enrolled one, and the parity rule for every hostname-routing surface:
  [NET](https://github.com/gominimal/minimal/pull/1380).
- The gateway association the exposure rides:
  [EHE](https://github.com/gominimal/minimal/pull/1418).
- The `ExposeIngress` evaluation point, the feed's ingress entries, and their
  revocation on the identity plane:
  [NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md)
  and [Gatehouse
  §6.11](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).
- The gateway's own translation of public traffic to the box: the gateway
  component.
- A provider's declaration of fabric-native gateway ingress and its port
  policy: the Box Provider API
  ([`gateway_ingress`](https://github.com/gominimal/arch/blob/main/specs/box-provider/box-provider-api.md)).
- Public exposure from a laptop or a personal tenant through Minimal-hosted
  gateways: roadmap (gominimal/arch#43). On an un-enrolled host GWI-001 is the
  whole behaviour.
- Teammate access to a box, which is not public exposure:
  [MRF](https://github.com/gominimal/minimal/pull/1420),
  [MMI](https://github.com/gominimal/minimal/pull/1356), and
  [CRA](https://github.com/gominimal/minimal/pull/1374).

## Design reasoning

**Cut from NET by precondition.** Local-first ordering (2026-09-15) left public
exposure to be bound separately from the local host's behaviour, with the
requirements moved unchanged in text and tier and their former NET IDs recorded
beside each one.

**The refusal is the first slice.** GWI-001 runs end to end on every host
today. Delivery of a feed-carried entry (GWI-006) was the other candidate and
needs an association and the feed; a deliberate act that cannot happen on a
host must say so before the capability exists there.

**Public exposures tear down within 5 seconds.** GWI-005 binds the bound; no
bound and a 60-second bound were the alternatives considered.

**One decision set, two carriers.** The enrolled request (GWI-008) carries the
same request shape as the local RPC ([design
§7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)),
so the allow, deny, and ask decisions and the no-partial-mapping rule exist
once, in NET; a separate enrolled request shape was rejected as a second
decision path to keep in step.

**Tiers.** Every requirement is T0. The one universal, that an exposure exists
only under an authorization, is decided on the identity plane, not in a
decision core the host owns; the host's tests run against a feed fixture and a
gateway stub.

**Cross-cutting decisions live in the architecture.** Gateway ingress over the
association and its v1 scope are [design
§6](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
the ingress entries and the `ExposeIngress` action are [Gatehouse §6.11 and
§7.4](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).

**Generality:** a provider fits by declaring fabric-native gateway ingress and
serving the same feed entry (GWI-007); every other requirement names the box
host or the `min` client. A deployment with neither a gateway nor the
capability breaks nothing: GWI-001 is the behaviour there.

## Security considerations

- **Invariant:** THE SYSTEM SHALL create a public exposure only under an
  `ExposeIngress` authorization.
  enforced by: exposures exist only as feed entries written under the
  decision; the enrolled request rides the box's identity socket
  covered by: GWI-002, GWI-004, GWI-008
- **Invariant:** THE SYSTEM SHALL deliver a public connection only to a port
  the box's ingress rules permit.
  enforced by: delivery per the box's ingress rules and the parity rule
  covered by: GWI-006

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): where a provider declares fabric-native
  gateway ingress with a protocol and port policy ([Box Provider
  API](https://github.com/gominimal/arch/blob/main/specs/box-provider/box-provider-api.md)),
  what does `min net expose --public` report when the requested protocol or
  port is outside that policy? GWI-001 binds the refusal on a host with no
  capability, not the refusal on a host whose capability excludes the request.]
