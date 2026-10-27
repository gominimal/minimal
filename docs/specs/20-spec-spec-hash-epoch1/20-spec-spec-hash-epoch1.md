---
id: EPOCH
title: "spec-hash epoch 1: an injective, machine-checked BuildSpec encoding"
status: draft
owner: bryan-minimal
epic: gominimal/inbox#583
arch: https://github.com/gominimal/arch/blob/d77725b6dcca73918efb66f0e15e97120db62a0e/architecture.md#d31--the-build-spec-hash-keyspace-contract-and-epochs
updated: 2026-10-14
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
(EPOCH-010). A **container's canonical form** is the set of fields
`ContainerHasher` covers (`spec_hasher.rs`, minimal#1331): its name, the
set of keys of its member packages, and its image configuration. Specs or
containers with different canonical forms are **canonically distinct**.
Every **bounded spec** has at most 3 elements in any list and at most 8
bytes in any string. Its dependency depth is at most 2. A **bounded
container** has at most 3 elements in any list, set or map, at most 8
bytes in any string, and up to 3 arbitrary 32-byte member keys: members
enter a container's canonical form as keys, so a harness ranges over the
keys and never runs the hash symbolically. Harnesses that are exhaustive
over bounded specs or containers state nothing beyond that domain.
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

- AS A security engineer I WANT the encoding to be an injective function
  of the spec's meaning SO THAT no two distinct specs can share an
  encoding, two keys agree only when Blake3 collides, and cache poisoning
  by collision is impossible by construction
- AS A package author I WANT dependency identity to be order-independent
  (deps as sets) SO THAT reordering imports in a recipe never forces a
  spurious catalog rebuild
- AS A verification engineer I WANT the encoder to be a pure bounded codec
  with a decoder and machine-checked properties SO THAT the injectivity
  theorem is proved (Kani now, Lean later) rather than asserted
- AS A build-infra operator I WANT the epoch flip to change only which keys
  exist — same 32-byte hashes, same index/snapshot/provenance formats — SO
  THAT migration is one cold catalog rebuild, not a format migration
- AS A security engineer I WANT the Container Spec Hash to carry the same
  guarantee as the package key SO THAT an OCI Archive fetched by key is as
  safe from substitution as a package tarball (D3.1, AT2)
- AS A release manager I WANT additive evolution (reserved tags,
  absent-means-epoch-1) after this change SO THAT no existing key ever
  changes again and the only keyspace change I schedule is a new epoch
  (D3.1)

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
  canonical form of the spec it encodes.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_roundtrip_bounded
  property: for all bounded specs x: decode(encode(x)) == canon(x), and
    canon(canon(x)) == canon(x)
  harness:  kani_epoch1_roundtrip_bounded, exhaustive over bounded specs
    (3 elements per list, 8 bytes per string, depth 2)
  - THE SYSTEM SHALL decode every epoch-1 container encoding back to the
    canonical form of the container it encodes.
    tier:   T2
    verify: cargo nextest run -p graph epoch1_container_roundtrip_bounded
    property: for all bounded containers c: decode(encode(c)) == canon(c)
    harness: kani_epoch1_container_roundtrip_bounded, exhaustive over
      bounded containers

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
  verify:   cargo nextest run -p rcache epoch_follows_pinned_index
  property: for all pins p, specs s: lookup_key(p, s) == hash(epoch(index(p)),
    encode_epoch(index(p))(s))
  - IF a lookup reads several indexes as one (an upstream with sideloads,
    or a per-commit snapshot with the root index as its fallback) AND two
    of them declare different epochs THEN THE SYSTEM SHALL refuse the
    lookup and name both indexes.
    tier:   T0
    verify: cargo nextest run -p rcache union_of_two_epochs_is_refused
  - WHERE an index holds no record THE SYSTEM SHALL treat it as declaring
    no epoch: it constrains no union it is part of, and a lookup whose
    every index is empty is a miss with no key computed, since there is no
    epoch to compute one under and nothing it could match.
    tier:   T0
    verify: cargo nextest run -p rcache empty_index_declares_no_epoch

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
    all 256 tag bytes with a bounded 8-byte payload, in spec and in
    container position
  - THE SYSTEM SHALL keep tags 0xF0 to 0xFF unassigned in epoch 1. A later
    optional field takes one with absent-means-epoch-1 semantics: a closure
    that does not set the field encodes, and keys, byte-identically to
    epoch 1 without it.
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
    for all distinct output sets a, b of s: encode(u_a) != encode(u_b)

- **EPOCH-013** THE SYSTEM SHALL encode canonically distinct containers to
  distinct byte strings.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_container_injectivity_bounded
  property: for all canonical containers a, b: a != b implies
    encode(a) != encode(b)
  harness:  kani_epoch1_container_injectivity_bounded, exhaustive over
    bounded containers (3 elements per list, set or map, 8 bytes per
    string)
  - THE SYSTEM SHALL encode the epoch-0 container witness (minimal#1331:
    `env_vars` `{Av: B}` against `{A: vB}`) to distinct outputs.
    tier:   T1
    verify: cargo nextest run -p graph epoch1_container_witness_refuted
    property: encode({Av: B}) != encode({A: vB})

- **EPOCH-014** WHEN the system computes a container key THE SYSTEM SHALL
  enter each member package by its key under the container's epoch, as a
  set.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_container_members_by_key_as_set
  property: for all containers c, permutations p of c's members:
    encode(c) == encode(p(c)); and for all members m of c: the member bytes
    of encode(c) are hash_e(m) for the epoch e of c's key
  - IF a member's key is not of the container's epoch THEN THE SYSTEM SHALL
    refuse to seal the container and name the member. A key carries no
    epoch in its bytes; the member's epoch is the one the index record its
    key was read from declares (EPOCH-009), and the sealer hands the hasher
    each member key with that epoch.
    tier:   T0
    verify: cargo nextest run -p rcache container_with_a_member_of_another_epoch_is_refused

- **EPOCH-015** WHEN the system computes a container key THE SYSTEM SHALL
  derive it under the epoch-1 context from the container's canonical
  encoding, 32 bytes wide, as EPOCH-005 derives a spec key.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_container_key_derivation
  property: for all containers c: key(c) == blake3_derive_key(epoch-1
    context, encode(c)), and len(key(c)) == 32

## Non-goals

- Changing the hash's size or algorithm: minimal#1246 interaction inventory
- Migrating historical epoch-0 artifacts: they stay valid for old pins
  (minimal#1246 decision 4)
- Wire varint work: minimal#1109 set 2
- The slots feature: gominimal/inbox#350. This spec only guarantees that
  the name axis is sound.
- Publishing OCI Archives to the Registry Build Cache with their index
  records, Container Provenance and Container SBOM: build-servers#371. This
  spec fixes the container key those records use, and nothing more.
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

- injective over the closure's meaning: EPOCH-001, EPOCH-002, EPOCH-004
  and EPOCH-013
- epochs by domain-separated context at a fixed 32 bytes, declared by the
  index and followed by consumers: EPOCH-005, EPOCH-009, EPOCH-012,
  EPOCH-014 and EPOCH-015
- keyspace rotation as a migration class: the Rollout section and the
  migration non-goal
- additive evolution, with an unknown tag as a hard error: EPOCH-007

Under EPOCH-007 additive evolution (D3.1) is a promise about keys, not
about readers. A new optional field takes a reserved tag and is absent
from every closure that does not set it, so every existing key is
unchanged and no catalog rebuilds. A decoder older than the field
hard-errors on an encoding that carries it; that reaches `decode()` alone,
which nothing on the key path calls (the decoder exists for EPOCH-003's
round-trip), so a reader older than the data it meets is a tooling-version
error, never a keyspace change. A change that cannot be expressed as an
absent-means-epoch-1 field is a new epoch.

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

The container key (EPOCH-013, EPOCH-014, EPOCH-015) is the same codec with
container tags; EPOCH-003's and EPOCH-007's container sub-bullets cover the
container round-trip and the unknown-tag rejection in container position,
with their own harnesses. `ContainerHasher` chooses its encoder at its own call site,
so the flip must move that site together with `SpecHasher` and
`SubsetHasher`, or containers stay on epoch 0 with the witness minimal#1331
pinned. A container is a declaration over packages. Its members enter by
key, and a key carries its epoch through the context, so a container key is
well-defined only when every member key is of the container's epoch, which
EPOCH-014's refusal makes a requirement rather than an inference from
EPOCH-009: a member may well sit in another index of another epoch. Today no index holds a container record
(build-servers#371), so the container keyspace has nothing to rotate.

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
  covered by: EPOCH-001, EPOCH-004, EPOCH-011, EPOCH-013
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
  pinned index declares. The container call site flips with the producing
  side (EPOCH-014). The catalog rebuilds cold under epoch-1 keys on
  the first pkgs CI cycle at that release. That is a full world rebuild,
  and build-infra schedules it on purpose (build-servers#271 and #272 hold
  the operational lessons). A staged catalog rebuild on the staging cache
  comes before the release.
- **Rollback:** a flip like any other, backwards: the producing side
  returns to epoch 0 and seals no epoch-1 index after it. Epoch-0 indices,
  objects and snapshots stay valid throughout, and a pin whose every index
  declares epoch 0 sees no change. A per-commit snapshot sealed after the
  rollback beside a root index still on epoch 1 is a mixed union, which
  EPOCH-012 refuses, so the root index rolls back with the producers (or
  the fallback is withheld for the window). Rollback takes minutes, and
  nothing rebuilds.
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
- Decision 4, the migration shape, decided: a one-time cold rebuild, as
  the Rollout section prescribes. Dual hashing (keeping epoch-0 keys live
  beside epoch-1 keys) was rejected: it doubles every index and makes the
  epoch a per-record question for the whole overlap, which EPOCH-009's
  one-epoch-per-index rule exists to avoid.
