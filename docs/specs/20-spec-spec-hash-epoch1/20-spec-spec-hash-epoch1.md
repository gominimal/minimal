---
id: EPOCH
title: "spec-hash epoch 1: an injective, machine-checked BuildSpec encoding"
status: draft
owner: bryan-minimal
epic: gominimal/inbox#583
arch: https://github.com/gominimal/arch/blob/d77725b6dcca73918efb66f0e15e97120db62a0e/architecture.md#d31--the-build-spec-hash-keyspace-contract-and-epochs
updated: 2026-10-06
---

# EPOCH — spec-hash epoch 1: an injective, machine-checked BuildSpec encoding

## Context

The cache key is a hash of an encoding that is not prefix-free. Nine
collision-witness classes exist: pairs of distinct specs with identical
keys, which give a constrained cache-poisoning primitive. The dual defect
puts dependency order into the hash, so a recipe that reorders its
dependencies forces spurious rebuilds. The encoder's shape also prevents a
machine check, which blocks the formal-methods program at its flagship
theorem. Epoch 1 replaces the encoding. It is the one breaking keyspace
change, and its design makes it the last.

Architecture D3.1, the keyspace contract, fixes what every epoch spec must
deliver. The encoding is injective over the closure's meaning, and the key
inherits that property computationally. Epochs use a domain-separated
Blake3 context, and the key stays at 32 bytes. Epoch selection is data.
Each Registry Cache Index records the epoch of its keys. A consumer computes
lookup keys under the epoch that its pinned index declares, and never under
a global "current" epoch. Keyspace rotation is a migration class. After
epoch 1, evolution is additive. This spec delivers that contract for epoch 1
and cites D3.1 by its stable identifier.

This document uses these terms. A spec's **canonical form** is the set of
fields the epoch-0 encoder covers (`spec_hasher.rs`). In that form the
dependency edges form a set and every number takes its normal form
(EPOCH-002, EPOCH-006). A spec's `tests` are outside its canonical form
(EPOCH-010). Specs with different canonical forms are **canonically
distinct**. Every **bounded spec** has at most 3 elements in any list and
at most 8 bytes in any string. Its dependency depth is at most 2. Harnesses
that are exhaustive over bounded specs state nothing beyond that domain.
The **epoch-1 context** is the Blake3 `derive_key` context string
`minimal.dev spec-hash epoch 1`. The **epoch-0 defect catalog** is the list
of nine collision-witness classes in minimal#1246.

**Success:** two distinct canonical specs share a cache key only through a
Blake3 collision, and a machine checks that property. A dependency reorder
no longer rotates keys.

**First slice:** the pure encode/decode codec with its machine-checked
round-trip and the nine witness refutations, plus the pinned epoch-1
digests. No call site flips yet. A person runs `epoch1_golden_pins` and
sees the digests reproduce. The Kani lane then reports the round-trip and
the nine refutations as proved.

## Users and stories

**Roles:** security engineer and package author. Verification engineer and
build-infra operator. Release manager.

- AS A security engineer I WANT the cache key to be an injective function
  of the spec's meaning SO THAT no two distinct specs can share a key and
  cache poisoning by collision is impossible by construction
- AS A package author I WANT dependency identity to be order-independent
  (deps as sets) SO THAT reordering imports in a recipe never forces a
  spurious catalog rebuild
- AS A verification engineer I WANT the encoder to be a pure bounded codec
  with a decoder and machine-checked properties SO THAT the injectivity
  theorem is proved (Kani now, Lean later) rather than asserted
- AS A build-infra operator I WANT the epoch flip to change only which keys
  exist — same 32-byte hashes, same index/snapshot/provenance formats — SO
  THAT migration is one cold catalog rebuild, not a format migration
- AS A release manager I WANT additive evolution (reserved tags,
  absent-means-epoch-1) after this change SO THAT this is the last breaking
  keyspace change I ever schedule

## Requirements

- **EPOCH-001** THE SYSTEM SHALL encode canonically distinct specs to
  distinct byte strings.
  tier:     T3
  verify:   cargo nextest run -p graph epoch1_injectivity_bounded
  property: for all canonical a, b: a != b implies encode(a) != encode(b)
  harness:  kani_epoch1_injectivity_bounded, exhaustive over bounded specs
    (3 elements per list, 8 bytes per string, depth 2). The codec PR can
    raise the bound after measuring, and must not lower it
  proof:    proofs/SpecHash/Epoch1.lean#encode_injective

- **EPOCH-002** WHEN a permutation reorders a spec's dependency edges THE
  SYSTEM SHALL produce an identical encoding.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_dep_order_irrelevant
  property: for all s, permutations p: encode(s) == encode(p(s))

- **EPOCH-003** THE SYSTEM SHALL decode every epoch-1 encoding back to the
  original spec.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_roundtrip_bounded
  property: for all bounded specs x: decode(encode(x)) == x
  harness:  kani_epoch1_roundtrip_bounded, exhaustive over bounded specs
    (3 elements per list, 8 bytes per string, depth 2)

- **EPOCH-004** THE SYSTEM SHALL encode every epoch-0 collision-witness
  pair from the epoch-0 defect catalog to distinct outputs.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_witness_refutations
  property: for all catalog pairs (a, b): encode(a) != encode(b)
  harness:  kani_epoch1_witness_refutations, one harness per witness class
    in the epoch-0 defect catalog (nine)

- **EPOCH-005** THE SYSTEM SHALL derive epoch-1 hashes under the epoch-1
  context, at 32 bytes, with every downstream record layout unchanged.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_domain_separation_and_width
  property: for all specs s: hash_1(s) == blake3_derive_key(epoch-1 context,
    encode(s)), is 32 bytes, and every record format that embeds a SpecHash
    serializes it as it serializes an epoch-0 key

- **EPOCH-009** WHEN the system seals a Registry Cache Index THE SYSTEM
  SHALL write the epoch of its keys into the flags field of every record.
  tier:     T1
  verify:   cargo nextest run -p rcache index_records_carry_their_epoch
  property: for all sealed indices i, records r in i: flags(r) == epoch(i)
  - IF an index file holds records of two epochs, or of an epoch the
    reader does not know, THEN THE SYSTEM SHALL refuse the whole file.
    tier:   T0
    verify: cargo nextest run -p rcache index_of_mixed_or_unknown_epoch_is_refused

- **EPOCH-012** WHEN a consumer computes a lookup key THE SYSTEM SHALL use
  the epoch that the index of its registry pin declares.
  tier:     T1
  verify:   cargo nextest run -p graph epoch_follows_pinned_index
  property: for all pins p, specs s: lookup_key(p, s) == hash(epoch(index(p)),
    encode_epoch(index(p))(s))

- **EPOCH-006** WHEN the system encodes a number THE SYSTEM SHALL normalize
  negative zero to zero.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_number_canonicalization
  property: for all floats f in encodable specs: one representative per
    equality class
  - IF a graph contains a NaN numeric attribute THEN THE SYSTEM SHALL
    reject the graph at load.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_nan_rejected_at_load

- **EPOCH-007** IF the decoder meets an unknown tag byte THEN THE SYSTEM
  SHALL hard-error.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_unknown_tag_rejects
  property: no two structural tags share a byte, and for all byte strings s
    with an unassigned tag: decode(s) errors
  harness:  kani_epoch1_tags_unique_and_unknown_rejected, exhaustive over
    all 256 tag bytes with a bounded 8-byte payload
  - THE SYSTEM SHALL keep tags 0xF0 to 0xFF unassigned in epoch 1.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_reserved_tags_unassigned

- **EPOCH-008** THE SYSTEM SHALL reproduce the pinned epoch-1 golden
  digests and leave the epoch-0 pin byte-identical.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_golden_pins

- **EPOCH-010** THE SYSTEM SHALL exclude a spec's `tests` from its canonical
  form.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_tests_outside_the_hash
  - IF a test writes into the output tree THEN THE SYSTEM SHALL fail the
    test.
    tier:   T0
    verify: cargo nextest run -p orchestrator a_test_that_writes_the_output_tree_fails

- **EPOCH-011** WHEN the system computes a subset key THE SYSTEM SHALL use
  the epoch of the spec key it subsets, and SHALL length-frame every output
  name.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_subset_key_follows_its_spec
  property: for all subsets u of spec s: epoch(key(u)) == epoch(key(s)), and
    for all distinct output sets a, b of s: key(u_a) != key(u_b)

## Non-goals

- Changing the hash's size or algorithm: minimal#1246 interaction inventory
- Migrating historical epoch-0 artifacts: they stay valid for old pins
  (minimal#1246 decision 4)
- Wire varint work: minimal#1109 set 2
- The slots feature: gominimal/inbox#350. This spec only guarantees that
  the name axis is sound.
- Merging the Lean proof: minimal#1109, harness set 6. EPOCH-001's proof
  line is the stated target, and Kani holds the property until the proof
  merges.

## Design reasoning

The codec is a fixed-width, byte-tagged TLV and does not use varints. With
TLV, injectivity is structural. Every payload has a length prefix, every
list has a count prefix, and indices have a fixed width. The codec also
stays in the provers' comfort zone. It is pure, with no unsafe code, no
trait objects and no unbounded recursion, because the spec walk stays
outside it.

Domain separation carries the epoch, so versioning costs zero preimage
bytes and no downstream format changes. The codec has no conditional
emission because adjacent content must never express an absence. That
ambiguity is the root cause of five of the nine witness classes.
Deps-as-sets let a bottom-up fold prove the well-definedness half of the
biconditional. The flip is a one-time cold rebuild. Dual publishing is how
one breaking change becomes three, so the design avoids dual-hash machinery. The
decision ledger is in minimal#1246, and the audit rationale is in the
formal-verification path.

D3.1 has four commitments, and each maps to requirements:

- injective over the closure's meaning: EPOCH-001, EPOCH-002 and EPOCH-004
- epochs by domain-separated context at a fixed 32 bytes, declared by the
  index and followed by consumers: EPOCH-005, EPOCH-009 and EPOCH-012
- keyspace rotation as a migration class: the Rollout section and the
  migration non-goal
- additive evolution, with an unknown tag as a hard error: EPOCH-007

Under EPOCH-007 a new optional field reuses epoch 1 only when its absence
means epoch-1 semantics. Any other change is a new epoch.

The index records its epoch in the flags field of each record (EPOCH-009).
The index format reserved that field for format changes, and the reader
already refuses any non-zero value. So an epoch-0 index stays
byte-identical, and the record layout does not change. The Sigstore bundle
signs the sealed index bytes, so it covers the epoch too. A client older
than this change refuses an epoch-1 index and asks for an update. That
refusal fails closed, and it is correct. Such a client computes epoch-0
keys and can find nothing in an epoch-1 index. The alternative was a field in
the bundle's signed statement. Old readers ignore that field, but today's
client checks no bundle, so the consumer half (EPOCH-012) then waits on
client-side Sigstore verification.

EPOCH-012 selects the epoch through the pinned index and never through a
global setting. That keeps historical pins valid through the flip, with
no dual publishing. The producing side moves together at one
config-plumbed site, and consumers follow their indices.

Kani holds EPOCH-001's property until the Lean theorem merges. T3 is the
target, and the harness is the evidence today. T3 is also a proposal to
add a Lean project and a proof lane to this repository, which has neither.
That cost belongs to minimal#1109 and is outside the codec PR.

Well-definedness beyond dependency order is the canonical form itself.
Numbers normalize (EPOCH-006) and `tests` stay out (EPOCH-010). Editing a
test never rotates a key, and a person can re-run tests without a rebuild.
The write-guard makes that assumption real instead of hashing around it.
The subset key (EPOCH-011) follows the spec key's epoch because witness
class 9 is its collision family. A subset computed under another epoch
cannot find the index of its spec.

**Generality:** a second epoch is additive by construction, through
reserved tags and a new `derive_key` context. A second hash algorithm is
out of scope by decision and will be a new epoch. The codec's proofs bind
to this encoding and not to the traversal, so a second traversal source
reuses them.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never assign two distinct canonical
  specs the same cache key except through a Blake3 collision.
  enforced by: prefix-free TLV encoding, with machine-checked bounded
  injectivity and witness refutations
  covered by: EPOCH-001, EPOCH-004, EPOCH-011
- **Invariant:** THE SYSTEM SHALL never silently absorb unknown structure
  into a hash preimage.
  enforced by: strict decoding, unknown tag = hard error
  covered by: EPOCH-007
- **Invariant:** THE SYSTEM SHALL trust epoch-0 keys for pinned history
  only, and SHALL never re-bless old artifacts under new keys.
  enforced by: the signed epoch in the pinned index and no migration path
  covered by: EPOCH-005, EPOCH-009, EPOCH-012

## Rollout

- **Deploy:** the client that reads the epoch from an index goes out in a
  release first (EPOCH-009, EPOCH-012). An older client refuses an epoch-1
  index. Then the producing side flips at one config-plumbed call site. The
  producing side is build infrastructure, remote execution and the hosts
  that seal new indices. Consumers never flip. They follow the epoch their
  pinned index declares. The catalog rebuilds cold under epoch-1 keys on
  the first pkgs CI cycle at that release. That is a full world rebuild,
  and build-infra schedules it on purpose (build-servers#271 and #272 hold
  the operational lessons). A staged catalog rebuild on the staging cache
  comes before the release.
- **Rollback:** flip the producing side back to epoch 0. Epoch-0 indices,
  objects and snapshots stay valid throughout, and consumers on epoch-0
  pins see no change. Rollback takes minutes, and nothing rebuilds.
- **Blast radius:** catalog consumers during the one cold rebuild window
  see cache misses, and never wrong data. Record layouts do not change.

## Open questions

- Decision 1 (are `tests` hashed?), decided 2026-10-05: `tests` are outside
  the canonical form, with a write-guard. EPOCH-010 binds it.
- Decision 5 (reserved-tag additive evolution, with an unknown tag as a
  hard error and no further breaking change planned) comes from the
  architecture. D3.1 fixes it, and EPOCH-007 binds it.
- Where the index records its epoch, decided 2026-10-06: in the flags field
  of each record (EPOCH-009). Design reasoning gives the alternative.
- [NEEDS CLARIFICATION (LOW): decision 4, the migration shape. The options
  are a one-time cold rebuild (recommended) or dual hashing. It affects
  rollout only, and every requirement holds under both. Settle it at flip
  time with build-infra.]
