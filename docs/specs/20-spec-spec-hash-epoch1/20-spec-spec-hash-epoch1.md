---
id: EPOCH
title: spec-hash epoch 1 — injective, formally verified BuildSpec encoding
owner: bryan-minimal
epic: gominimal/inbox#583
arch: https://github.com/gominimal/arch/blob/d77725b6dcca73918efb66f0e15e97120db62a0e/architecture.md#d31--the-build-spec-hash-keyspace-contract-and-epochs
updated: 2026-09-17
---

# EPOCH — spec-hash epoch 1: injective, formally verified BuildSpec encoding

## Context

The cache key is a hash of an encoding that is not prefix-free: nine
verified collision-witness classes exist — distinct specs with identical
keys, a constrained cache-poisoning primitive — and the dual defect hashes
dependency order, forcing spurious rebuilds on recipe reorder. The
encoder's shape also makes it unverifiable, blocking the formal-methods
program at its flagship theorem. Epoch 1 replaces the encoding as the one
breaking keyspace change, designed so it is the last.

The architecture fixes what every epoch spec must deliver (architecture.md
D3.1, the keyspace contract): the encoding is injective over the closure's
meaning and the key inherits it computationally; epochs ride a
domain-separated Blake3 context and the key stays 32 bytes; epoch selection
is data — each Registry Cache Index records the epoch its keys were computed
under, and a consumer computes lookup keys under the epoch its pinned index
declares, never a global "current" epoch; keyspace rotation is a migration
class; and evolution after epoch 1 is additive. This spec is epoch 1's
delivery of that contract; it cites D3.1 by its stable identifier.

**Success:** no two distinct canonical specs can share a cache key, the
property is machine-checked, and dependency reorder no longer rotates keys.

**First slice:** the pure encode/decode codec with machine-checked
round-trip and all nine witness refutations, plus pinned epoch-1 digests —
no call-site flip yet.

## Users and stories

**Roles:** security engineer; package author; verification engineer;
build-infra operator; release manager.

- AS A security engineer I WANT the cache key to be an injective function
  of the spec's meaning SO THAT collision-based cache poisoning is
  impossible by construction
- AS A package author I WANT dependency identity to be order-independent SO
  THAT reordering imports never forces a spurious rebuild
- AS A verification engineer I WANT a pure bounded codec with a decoder and
  machine-checked properties SO THAT injectivity is proved rather than
  asserted
- AS A build-infra operator I WANT the flip to change only which keys exist
  SO THAT migration is one cold rebuild, not a format migration
- AS A release manager I WANT additive evolution after this change SO THAT
  this is the last breaking keyspace change I schedule

## Requirements

- **EPOCH-001** THE SYSTEM SHALL encode canonically distinct specs to
  distinct byte strings (injectivity; collision resistance of the hash is
  the named axiom above the encoding).
  tier:     T3
  verify:   cargo nextest run -p graph epoch1_injectivity_bounded
  property: for all canonical a, b: a != b implies encode(a) != encode(b)
  harness:  kani_epoch1_injectivity_bounded, exhaustive over the bounded
    length domains of minimal#1246's verification plan
  proof:    proofs/SpecHash/Epoch1.lean#encode_injective

- **EPOCH-002** WHEN a spec's dependency edges are permuted THE SYSTEM
  SHALL produce an identical encoding.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_dep_order_irrelevant
  property: for all s, permutations p: encode(s) == encode(p(s))

- **EPOCH-003** THE SYSTEM SHALL decode every epoch-1 encoding back to the
  original spec.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_roundtrip_bounded
  property: for all bounded specs x: decode(encode(x)) == x
  harness:  kani_epoch1_roundtrip_bounded, exhaustive over the bounded
    length domains

- **EPOCH-004** THE SYSTEM SHALL encode every epoch-0 collision-witness
  pair from the defect catalog to distinct outputs.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_witness_refutations
  property: for all catalog pairs (a, b): encode(a) != encode(b)
  harness:  kani_epoch1_witness_refutations, one harness per witness class
    in the epoch-0 defect catalog (nine)

- **EPOCH-005** THE SYSTEM SHALL derive epoch-1 hashes under the
  domain-separated context and keep the hash at 32 bytes, leaving every
  downstream record format byte-unchanged.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_domain_separation_and_width

- **EPOCH-009** WHEN a Registry Cache Index is sealed THE SYSTEM SHALL
  record in it the epoch its keys were computed under, covered by the
  index's Sigstore bundle; and WHEN a consumer computes a lookup key THE
  SYSTEM SHALL compute it under the epoch declared by the index its
  registry pin resolves to, never under a global current epoch.
  tier:     T1
  verify:   cargo nextest run -p graph epoch_follows_pinned_index
  property: for all pins p, specs s: lookup_key(p, s) == hash(epoch(index(p)),
    encode_epoch(index(p))(s))

- **EPOCH-006** IF a graph contains a NaN numeric attribute THEN THE
  SYSTEM SHALL reject it at load; WHEN encoding numbers THE SYSTEM SHALL
  normalize negative zero to zero.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_number_canonicalization
  property: for all floats f in encodable specs: not is_nan(f), one
    representative per equality class

- **EPOCH-007** IF the decoder meets an unknown tag byte THEN THE SYSTEM
  SHALL hard-error; tags 0xF0–0xFF are reserved, and a new optional field
  SHALL reuse epoch 1 only when its absence means epoch-1 semantics.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_unknown_tag_rejects
  property: for all byte strings s with an unassigned tag: decode(s) errors

- **EPOCH-008** THE SYSTEM SHALL reproduce the pinned epoch-1 golden
  digests and leave the epoch-0 pin byte-identical.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_golden_pins

## Non-goals

- Changing the hash's size or algorithm: minimal#1246 interaction inventory
- Migrating historical epoch-0 artifacts: immutable history stays valid for
  old pins (minimal#1246 decision 4)
- Wire varint work: minimal#1109 set 2
- The slots feature: its own design (this spec only guarantees the name
  axis is sound)
- Landing the Lean proof: the formal-verification roadmap (EPOCH-001's
  proof line is the stated target; Kani holds the property until it lands)

## Design reasoning

Fixed-width byte-tagged TLV over varints because injectivity is then
structural — every payload length-prefixed, every list count-prefixed,
fixed-width indices — and the codec stays in the provers' sweet spot: pure,
no unsafe, no trait objects, no unbounded recursion (the spec walk stays
outside). Domain separation carries the epoch so versioning costs zero
preimage bytes and no downstream format learns anything. No conditional
emission because absence must be inexpressible by adjacent content — the
root cause of five of the nine witness classes. Deps-as-sets makes the
well-definedness half of the biconditional provable as a clean bottom-up
fold. One-time cold rebuild over dual-hash machinery: dual-publish
complexity is how one breaking change becomes three. The decision ledger
lives in minimal#1246; the audit rationale in the formal-verification path.

D3.1's four commitments map onto the requirements one-to-one: injective
over the closure's meaning — EPOCH-001, EPOCH-002 and EPOCH-004; epochs by
domain-separated context at a fixed 32 bytes, with the epoch declared by
the index and followed by consumers — EPOCH-005 and EPOCH-009; keyspace
rotation as a migration class — Rollout and the migration non-goal;
additive evolution with unknown tags a hard error — EPOCH-007. Selection by
the pinned index (EPOCH-009) rather than by a global setting is what lets
historical pins stay valid through the flip without dual-publishing: the
producing side moves together at one config-plumbed site, consumers follow
their indices. The Kani harnesses hold EPOCH-001's property until the Lean
theorem lands (T3 is the target; the harness is the evidence today).

**Generality:** a second epoch is additive by construction (reserved tags,
new derive-key context); a second hash algorithm is out of scope by
decision and would be a new epoch. The codec's proofs bind to this
encoding, not to the traversal — a second traversal source reuses them.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never assign two distinct canonical
  specs the same cache key.
  enforced by: prefix-free TLV encoding; machine-checked bounded
  injectivity and witness refutations
  covered by: EPOCH-001, EPOCH-004
- **Invariant:** THE SYSTEM SHALL never silently absorb unknown structure
  into a hash preimage.
  enforced by: strict decoding, unknown tag = hard error
  covered by: EPOCH-007
- **Invariant:** THE SYSTEM SHALL keep epoch-0 keys trusted for pinned
  history only, never re-blessing old artifacts under new keys.
  enforced by: epoch selection by the pinned index's declared epoch (never
  a global setting); no migration path
  covered by: EPOCH-005, EPOCH-009

## Rollout

- **Deploy:** the producing side (build infrastructure, remote execution,
  hosts sealing new indices) flips at one config-plumbed call site and
  ships in a release; consumers never flip — they compute keys under the
  epoch their pinned index declares (EPOCH-009). The catalog rebuilds cold
  under epoch-1 keys on the first pkgs CI cycle at that release — a full world rebuild, scheduled deliberately
  with build-infra (see build-servers#271/#272 operational lessons). Staged
  catalog rebuild on the staging cache precedes the release.
- **Rollback:** flip the producing side back to epoch 0 — epoch-0 indices,
  objects and snapshots remain valid throughout, and consumers on epoch-0
  pins never noticed; rollback is minutes, not a rebuild.
- **Blast radius:** catalog consumers during the one cold rebuild window
  (cache misses, not wrong data); nothing else — all record formats are
  byte-unchanged.

## Open questions

- [NEEDS CLARIFICATION (CRITICAL): decision 1 — are `tests` hashed?
  Changes which spec edits rotate keys. Recommendation on record (out of
  the hash, plus a write-guard assertion that test execution cannot touch
  the output tree); decider: maintainers, minimal#1246.]
- Resolved by the architecture: decision 5 (reserved-tag additive
  evolution, unknown tag a hard error, no further breaking change planned)
  is fixed by D3.1; EPOCH-007 binds it.
- [NEEDS CLARIFICATION (LOW): decision 4 migration shape — one-time cold
  rebuild (recommended) vs dual-hash; rollout-only, every requirement holds
  under both; settle at flip time with build-infra.]
