---
id: MRF
title: Mesh and remote forward: reaching boxes across machines
owner: norrietaylor
epic: gominimal/inbox#646
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-16
---

# MRF — Mesh and remote forward: reaching boxes across machines

## Context

A developer reaches boxes on other machines over an authenticated, encrypted
channel: `min net forward` against a remote session, and a mesh joined with the
signed-in identity that delivers peers, keys, endpoints, and relay assignment
as signed peer documents and resolves tenant-zone box names on the laptop
([Gatehouse
§6.9](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md);
[design
§4.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
[architecture
D7](https://github.com/gominimal/arch/blob/main/architecture.md)). This
document binds the `min` client's and the daemon's side on the laptop: join and
leave, the peer-document mirror, admission only against a valid binding,
reaching a remote own-address box by name, status, and the remote form of the
forward.

It was cut from [NET](https://github.com/gominimal/minimal/pull/1380)
(local-first ordering, 2026-09-15): every requirement here needs an enrolled
laptop, a joined mesh, or an established remote session. NET is its
prerequisite: the local forward (NET-104, NET-105) is what MRF-001 serves
against a remote host, and the local names and box-zone resolution (NET-011 to
NET-013, NET-072) are what tenant-zone resolution (MRF-009) extends. The daemon
as a mesh-reachable session host, its WebSocket ingress, and the relay are
[MMI](https://github.com/gominimal/minimal/pull/1356); the client core that
consumes peer documents and relay tickets is
[MCC](https://github.com/gominimal/minimal/pull/1355); the certificate attach
that establishes the remote session is
[CRA](https://github.com/gominimal/minimal/pull/1374).

After this ships, a developer joins a mesh with one command and no key file,
reaches a service in a box on another of their machines by hostname, and
forwards a remote box's port to `localhost` over the session they already have.

**Success:** on a laptop joined to a mesh with its signed-in identity,
`http://<name>.<node>.box.<td>:<port>` reaches an own-address box on a remote
host, `min net status` shows the peer with its last handshake, and `min net
mesh leave` removes the laptop within the revocation window.

**First slice:** `min net mesh join` under the signed-in identity, receiving
signed peer documents (MRF-002, MRF-003), and `min net status` showing the
peers (MRF-005), against one remote host that already serves mesh ingress.

## Users and stories

**Roles:** developer on a laptop, developer running services across two box hosts

- AS A developer on a laptop, I WANT `min net mesh join` to enrol me using my signed-in identity and receive peer configuration automatically, SO THAT I reach remote boxes by hostname without copying WireGuard keys around.
- AS A developer running services across two box hosts, I WANT a box on host A to reach a service in a box on host B that a named network grants it, by hostname, over an authenticated encrypted channel, SO THAT multi-host workflows do not need a VPN I set up by hand.

## Requirements

- **MRF-001** WHERE a remote session is established THE SYSTEM SHALL serve `min net forward` against the remote host as it does a local one.
  tier:     T0
  verify:   cargo nextest run -p minimal net_forward_remote_host
  <!-- S12/AC3; prose 67; optional-feature; formerly NET-106 -->

- **MRF-002** WHERE the host is enrolled, WHEN `min net mesh join` is run THE SYSTEM SHALL enrol the laptop under its signed-in identity with no manual key exchange.
  tier:     T0
  verify:   cargo nextest run -p minimal mesh_join_uses_signed_in_identity
  <!-- S13/AC1; prose 73; feature+event; formerly NET-112 -->

- **MRF-003** WHERE the host is enrolled, WHEN the laptop joins a mesh THE SYSTEM SHALL receive peers, keys, endpoints, and relay assignment as signed peer documents.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_join_receives_peer_documents
  <!-- S13/AC1; prose 73; feature+event; formerly NET-113 -->

- **MRF-004** WHERE the laptop has joined a mesh THE SYSTEM SHALL route a request to `<name>.<node>.box.<td>:<port>` to an own-address box on a remote host.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_reaches_remote_box_by_name
  <!-- S13/AC2; prose 74; optional-feature; formerly NET-114 -->

- **MRF-005** WHERE the laptop has joined a mesh THE SYSTEM SHALL show peers with their last handshake in `min net status`.
  tier:     T0
  verify:   cargo nextest run -p minimal net_status_shows_peers_handshake
  <!-- S13/AC3; prose 75; optional-feature; formerly NET-115 -->

- **MRF-006** WHERE the laptop has joined a mesh, WHEN `min net mesh leave` is run THE SYSTEM SHALL remove the laptop from the mesh within the revocation window.
  tier:     T0
  verify:   cargo nextest run -p minimal mesh_leave_within_revocation_window
  <!-- S13/AC3; prose 75; feature+event; formerly NET-116 -->

- **MRF-007** WHERE the host is enrolled THE SYSTEM SHALL bring up the mesh from its peer-document mirror.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_from_peer_document_mirror
  <!-- S13/slices; prose 76; optional-feature; formerly NET-117 -->

- **MRF-008** WHERE the host is enrolled THE SYSTEM SHALL admit a mesh peer only against a valid, unexpired binding and re-validate it on rekey.
  tier:     T0
  verify:   cargo nextest run -p minimald peer_admitted_only_with_valid_binding
  <!-- S13/slices; prose 76; optional-feature; formerly NET-118 -->

- **MRF-009** WHERE the laptop has joined a mesh THE SYSTEM SHALL resolve tenant-zone box names locally.
  tier:     T0
  verify:   cargo nextest run -p minimald laptop_resolves_tenant_zone_locally
  <!-- S13/slices; prose 77; optional-feature; formerly NET-119 -->

## Non-goals

- The local forward over the session's SSH channel and its close on session
  end: [NET](https://github.com/gominimal/minimal/pull/1380) (NET-104,
  NET-105).
- Box-to-box reach across hosts by named-network grant (the second story here):
  the grant model for it is an architecture ruling that has not been made; it
  returns as its own document once the ruling exists. The mesh transport it
  would ride is MRF-002 to MRF-009.
- Binding issuance, the `JoinMesh` decision, peer-document issuance, and relay
  tickets on the identity plane:
  [NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md)
  and [Gatehouse
  §6.9](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).
- The daemon's mesh ingress, its admission of peers on its own side, and the
  relay: [MMI](https://github.com/gominimal/minimal/pull/1356). See Open
  questions for the overlap with MRF-007 and MRF-008.
- The browser client and the shared client core:
  [MCC](https://github.com/gominimal/minimal/pull/1355) and
  gominimal/webapp#763.
- Establishing the remote session that MRF-001 forwards over:
  [CRA](https://github.com/gominimal/minimal/pull/1374).
- The gateway's forwarding role for mesh and attach traffic on a pinned host
  ([design
  §4.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)):
  the gateway component; the host's side of the association is
  [EHE](https://github.com/gominimal/minimal/pull/1418).

## Design reasoning

**Cut from NET by precondition.** Local-first ordering (2026-09-15) left the
cross-machine stories to be bound separately from the local host's behaviour,
with the requirements moved unchanged in text and tier and their former NET IDs
recorded beside each one.

**Mesh join is in scope; remote box-to-box is not.** The laptop mesh story
carries its own normative source for bindings and peer documents, so it is
bound here. The remote box-to-box story needs a grant model that does not exist
and stays a non-goal with that destination.

**Peer documents are configuration, never authorization.** MRF-007 and MRF-008
follow the mirror rule of [Gatehouse
§6.9](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md):
the daemon brings the mesh up from the document and admits a peer only against
a valid, unexpired binding. The daemon's own statement of the same rule on its
ingress side is [MMI](https://github.com/gominimal/minimal/pull/1356)'s; a
single statement was considered, and the overlap is recorded as an open
question rather than resolved here, because that document is under review in
parallel.

**Tiers.** Every requirement is T0. Binding validity is a universal, but it is
the identity plane's, stated in Gatehouse §6.9, not a decision core this
document owns; a property over generated bindings would belong with whichever
document ends up owning the daemon's admission, per the open question.

**Cross-cutting decisions live in the architecture.** Bindings, peer documents,
relay tickets, and address allocation are [Gatehouse
§6.9](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md);
the relay tier is [architecture
D7](https://github.com/gominimal/arch/blob/main/architecture.md); mesh and
attach under a pinned host's gateway are [design
§4.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md).

**Generality:** the client side holds for any daemon that serves mesh ingress,
native or VM-backed; a pinned remote host's path transits its gateway's
forwarding role ([design
§4.5](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)),
which changes the route and not the requirement. What breaks on a laptop that
cannot enrol is nothing here: every requirement is scoped WHERE the host is
enrolled or has joined a mesh, and the local forward stays in NET.

## Security considerations

- **Invariant:** THE SYSTEM SHALL admit a mesh peer only against a valid,
  unexpired binding.
  enforced by: the daemon validates bindings and treats peer documents as
  configuration, never authorization ([Gatehouse §6.9](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md))
  covered by: MRF-008
- **Invariant:** THE SYSTEM SHALL route a remote box name only to a peer
  admitted under a binding.
  enforced by: name resolution answers only peers present in the admitted
  peer set
  covered by: MRF-004, MRF-008, MRF-009

## Open questions

- [NEEDS CLARIFICATION (HIGH): MRF-007 and MRF-008 bind the daemon's
  peer-document mirror and binding admission on the laptop, and
  [MMI](https://github.com/gominimal/minimal/pull/1356) binds the same on a
  mesh-reachable session host (its peer-document and relay requirements); MMI's
  first open question expects its relay leg and path choice to fold into the
  networking spec. Which document owns the daemon's half, and does the relay
  leg fold here? It survives because MMI is under review in parallel and the
  gateway-relay consolidation is open in the architecture (design §12 item 1).]
- [NEEDS CLARIFICATION (MEDIUM): what is the grant model for box-to-box reach
  across hosts (provider, named network, identity)? It blocks the non-goal
  above, not any requirement here.]
- [NEEDS CLARIFICATION (MEDIUM): which channel serves `min net forward` against
  a remote host (MRF-001): the certificate connection's direct-tcpip channel,
  as the local forward uses, or the mesh tunnel?
  [CRA](https://github.com/gominimal/minimal/pull/1374) names the commands
  admitted over a certificate connection and does not name the forward.]
