---
epic: gominimal/inbox#583
arch: gominimal/arch (formal-verification path; spec-process proof tiers)
---

# 13-spec-spec-hash-epoch1: injective, formally verified BuildSpec encoding

## Context

The cache key is a Blake3 hash of a hand-rolled byte encoding that is not
prefix-free: nine cargo-verified collision-witness classes exist (distinct
specs, identical keys — a constrained cache-poisoning primitive), and the
dual defect hashes dependency *order*, forcing spurious rebuilds on recipe
reorder. The encoder's shape (in-band ASCII markers, conditional emission,
platform-width integers) also makes it unverifiable — blocking the formal
program at its flagship theorem. Epoch 1 replaces the encoding behind the
existing `SpecEncoder` seam as the one breaking keyspace change, designed
(reserved-tag additive evolution) so it is the last.

Success criteria fold in the epic: injective + well-defined encoding,
machine-checked from day one, zero downstream format changes, one-time cold
catalog rebuild as the whole migration.

**First slice** (runs end to end): the pure `encode_epoch1`/`decode` codec
module + Kani harnesses (round-trip, all nine witness refutations, tag
uniqueness) + epoch-1 golden pins — no call-site flip yet (minimal#1246's
codec-first ordering).

## Users and stories

- As a **security engineer**, I want the cache key to be an injective
  function of the spec's meaning, so that no two distinct specs share a key
  and collision-based cache poisoning is impossible by construction.
- As a **package author**, I want dependency identity to be
  order-independent, so that reordering imports never forces a spurious
  rebuild.
- As a **verification engineer**, I want a pure bounded codec with a decoder
  and machine-checked properties, so that injectivity is proved (Kani now,
  Lean later) rather than asserted.
- As a **build-infra operator**, I want the flip to change only which keys
  exist — same 32-byte hashes, same formats — so migration is one cold
  rebuild, not a format migration.
- As a **release manager**, I want additive evolution after this change, so
  that this is the last breaking keyspace change I schedule.

## Requirements

- **EPOCH-001** WHEN two canonically distinct specs are encoded THE SYSTEM
  SHALL produce distinct byte strings (encoding injectivity; Blake3
  collision resistance is the assumed axiom above it).
  - tier: T2
  - verify: just test-one epoch1_injectivity_bounded
  - property: for all a, b: a != b implies encode(a) != encode(b)
  - harness: kani_epoch1_injectivity_bounded
  - proof: proofs/SpecHash/Epoch1.lean#encode_injective   # T3 target, stated not gated

- **EPOCH-002** WHEN a spec's dependency edges are permuted THE SYSTEM SHALL
  produce an identical encoding (edges canonically sorted by
  (kind, index, subset); deps-as-sets).
  - tier: T1
  - verify: just test-one epoch1_dep_order_irrelevant
  - property: for all s, permutations p: encode(s) == encode(p(s))

- **EPOCH-003** WHEN any epoch-1 encoding is decoded THE SYSTEM SHALL
  return the original spec (the decoder exists for verification; no
  production caller is required).
  - tier: T2
  - verify: just test-one epoch1_roundtrip
  - property: for all bounded specs x: decode(encode(x)) == x
  - harness: kani_epoch1_roundtrip_bounded

- **EPOCH-004** WHEN each epoch-0 collision-witness pair from the defect
  catalog is encoded under epoch 1 THE SYSTEM SHALL produce distinct
  outputs for every pair.
  - tier: T2
  - verify: just test-one epoch1_refutes_epoch0_witnesses
  - property: for all catalog pairs (a, b): encode(a) != encode(b)
  - harness: kani_epoch1_witness_refutations

- **EPOCH-005** WHEN computing any epoch-1 hash THE SYSTEM SHALL derive it
  under the domain-separated context ("minimal.dev spec-hash epoch 1") and
  SHALL keep `SpecHash` at 32 bytes, leaving index records, snapshots,
  closures, provenance subjects, events, and object names byte-format
  unchanged.
  - tier: T0
  - verify: just test-one epoch1_domain_separation_and_width

  @EPOCH-005
  Scenario: epoch is carried by key derivation, not by format
    Given the same spec encoded under epoch 0 and epoch 1
    When both hashes are computed
    Then both are 32 bytes, the values differ, and every downstream record
      format accepts either

- **EPOCH-006** WHEN a graph containing a NaN numeric attribute is loaded
  THE SYSTEM SHALL reject it at load, and WHEN encoding numbers THE SYSTEM
  SHALL normalize `-0.0` to `0.0`.
  - tier: T1
  - verify: just test-one epoch1_number_canonicalization
  - property: for all floats f in encodable specs: not is_nan(f) and
    bits(normalize(f)) has one representative per equality class

- **EPOCH-007** WHEN the decoder meets an unknown tag byte THE SYSTEM SHALL
  hard-error; tags 0xF0–0xFF are reserved, and a new optional field SHALL
  reuse epoch 1 (no epoch bump) only when its absence means epoch-1
  semantics.
  - tier: T1
  - verify: just test-one epoch1_unknown_tag_rejects
  - property: for all byte strings s with an unassigned tag: decode(s) errors

- **EPOCH-008** WHEN the epoch-1 golden fixtures are hashed THE SYSTEM
  SHALL reproduce the pinned digests, and the epoch-0 `LegacyEncoder` pin
  SHALL remain byte-identical.
  - tier: T0
  - verify: just test-one epoch1_golden_pins

  @EPOCH-008
  Scenario: both epochs are pinned
    Given the golden fixture set
    When epoch-0 and epoch-1 digests are computed
    Then each matches its pinned value exactly

## Non-goals

Changing `SpecHash`'s size or algorithm. Migrating historical epoch-0
artifacts (immutable history stays valid for old pins). wire.rs varint work
(minimal#1109 set 2). The slots feature (this spec only guarantees the name
axis is sound). Landing the Lean proof (EPOCH-001's `proof:` line is the
stated T3 target; Kani holds the property until it lands).

## Design reasoning

Fixed-width byte-tagged TLV over varints because injectivity is then
structural (every payload length-prefixed, every list count-prefixed,
u32-LE indices) and the codec stays in Kani/Lean's sweet spot: pure, no
unsafe, no trait objects, no unbounded recursion (the spec walk stays
outside). Domain separation carries the epoch so versioning costs zero
preimage bytes and no downstream format learns anything. No conditional
emission because absence must be inexpressible by adjacent content — the
root cause of five of the nine witness classes. Deps-as-sets is the
long-standing maintainer position and makes the well-definedness half of
the biconditional provable as a clean bottom-up fold. One-time cold rebuild
over dual-hash machinery: dual-publish complexity is how one breaking
change becomes three. Full alternatives and the decision ledger live in
minimal#1246; the audit rationale in the arch formal-verification path.

## Security considerations

- The central claim is security-load-bearing and machine-checked:
  encoding injectivity (EPOCH-001/004) removes the cache-poisoning-by-
  collision primitive; the theorem is conditional on the named axiom
  (Blake3 collision resistance) and the trust boundary is explicit.
- Strict decoding (EPOCH-007) is the anti-smuggling invariant: unknown
  structure can never be silently absorbed into a hash preimage.
- The verification lane is advisory in CI (per the #1217 convention) but
  the witness-refutation suite (EPOCH-004) is a required check: a change
  that reintroduces any catalogued collision class must not merge.
- Epoch-0 keys remain trusted for pinned history only; nothing re-signs or
  re-blesses old artifacts under new keys.

## Open questions

- **CRITICAL:** D1 — are `tests` hashed? At least one plausible answer
  changes which spec edits rotate keys (observable behaviour).
  Recommendation on record (out of the hash, plus a write-guard assertion
  that test execution cannot touch the output tree); decider: maintainers,
  in minimal#1246.
- **CRITICAL:** D5 confirmation — reserved-tag additive evolution means a
  future optional field with absent≠epoch-1 semantics forces an epoch bump;
  plausible alternative (strict epoch-per-change) changes EPOCH-007's
  contract. Recommendation on record (reserved-tag additive); decider:
  maintainers, in minimal#1246.
- D4 migration shape (accepted-recommendation: one-time cold catalog
  rebuild) — both plausible answers satisfy every requirement above;
  rollout-only, non-critical, settle at flip time with build-infra.

## Rollout

The epoch flip is config-plumbed at one call site and ships in a release;
the catalog rebuilds cold under epoch-1 keys on the first pkgs CI cycle at
that release (a world rebuild — schedule it deliberately, see
build-servers#271/#272 for the operational lessons). Old pins continue
reading epoch-0 objects; no artifact migration. Test plan: the full
verification suite above plus one staged catalog rebuild on the staging
cache before the release carrying the flip.
