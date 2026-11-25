---
id: EPOCH
title: "spec-hash epoch 1: an injective, machine-checked BuildSpec encoding"
status: draft
owner: bryan-minimal
epic: gominimal/inbox#583
arch: https://github.com/gominimal/arch/blob/15b603e6afb8dd2ebf6fc15f2ec1cac1fb57a0ec/architecture.md#d31--the-build-spec-hash-keyspace-contract-and-epochs
arch_sha: "15b603e6afb8dd2ebf6fc15f2ec1cac1fb57a0ec"
updated: 2026-11-24
---

# EPOCH — spec-hash epoch 1: an injective, machine-checked BuildSpec encoding

## Context

The cache key is a hash of an encoding that is not prefix-free. Nine
collision-witness classes exist. Seven are a pair of distinct specs with
identical keys, which gives a constrained cache-poisoning primitive; two
(7 and 8) are the converse, one spec with more than one key. The
same defect puts dependency order into the hash, so a recipe that reorders
its dependencies forces spurious rebuilds. The encoder's shape also
prevents a machine check, which blocks the formal-methods program at its
flagship theorem. Epoch 1 replaces the encoding. It is the one breaking
keyspace change, and its design makes it the last.

Architecture D3.1, the keyspace contract, fixes what every epoch spec must
deliver. The encoding is injective over the closure's meaning, and the key
inherits that property computationally. Epochs use a domain-separated
Blake3 context, and the key stays at 32 bytes. Epoch selection is data.
Each Registry Cache Index records the epoch of its keys. A consumer computes
lookup keys under the epoch that its pinned index declares, and never under
a global "current" epoch. Keyspace rotation is a migration class. After
epoch 1, evolution is additive. This spec delivers that contract for epoch 1
and cites D3.1 by its stable identifier.

This document uses these terms. A spec's **canonical form** is the spec
field list of the epoch-1 encoding below. The list holds the fields the
epoch-0 encoder covers and no others. In that form the dependency edges form
a set and every number takes its normal form (EPOCH-002, EPOCH-006). A
spec's `tests` are outside its canonical form (EPOCH-010). An **edge** of a
spec is identified by the epoch-1 key of the dependency it names and by the
dependency's kind. An edge that names a subset also has the set of output
names it selects. Inside a cycle no member has a key before the others, so
there an edge names its target by the target's member digest instead
(EPOCH-026). A spec's edges enter its encoding as a set ordered by
those bytes, so neither the order a recipe lists them in nor a repeated
listing is part of the canonical form. A **container's canonical form** is
the container field list below. Its members enter it as the set of their
keys. A **subset's canonical form** is the subset field list below: its
components as a set ordered by their bytes, each with its output names as
a set. Specs, subsets or containers with
different canonical forms are **canonically distinct**. A **bounded spec**
has at most 3 elements in any list, set or map, its edges included. It has
at most 8 bytes in any string, and each edge key is an arbitrary 32-byte
value. A **bounded container** has at most 3
elements in any list, set or map, at most 8 bytes in any string, and up to 3
arbitrary 32-byte member keys. A **bounded subset** has up to 3
components, each an arbitrary 32-byte spec key with up to 3 output names
of at most 8 bytes. Edges, members and components enter an encoding as
keys, and an edge inside a cycle as its target's member digest.
So a harness ranges over the key bytes, never runs the hash symbolically,
and has no dependency depth to bound. Harnesses that are exhaustive over
bounded specs, subsets, containers or cycle records state nothing beyond
that domain.

A **cycle** is a set of specs in which each spec depends on each other one,
directly or through other specs, by build-input and runtime-dependency
edges. A spec with such an edge to itself is on a cycle too. A
replace-on-cycle edge never makes a cycle. A spec on a cycle is a
**member** of it. An edge whose target is a member of the same cycle is
**inside** the cycle, a self edge included, and every other edge
**leaves** it. Two specs **mean the same** when unfolding their edges gives
the same tree: their canonical fields are identical, and their edges pair
up by kind and output set with edges to specs that mean the same. A
member's **member digest** is the hash of its canonical fields and of the
edges that leave its cycle (EPOCH-026). A **cycle record** is the set of
its members' entries. An entry is a member digest and that member's edges
inside the cycle, each as its kind, its output set and the member digest of
its target. A **canonical cycle record** holds each of those sets ordered
by its bytes, and cycle records with different canonical forms are
canonically distinct. A **bounded cycle record** has up to 3 entries, each
an arbitrary 32-byte member digest with up to 3 inside edges, and each edge
has up to 3 output names of at most 8 bytes and an arbitrary 32-byte
target digest. A member that has build steps has two builds. Its **first
build** is used only to make the builds of its cycle, and its **final
build** is the built package its key finds (gominimal/arch#183, build §7).
A spec's **`replace_on_cycle` spec** is the spec its replace-on-cycle
edge names, inline or by reference.
The **epoch-1 context** is the Blake3 `derive_key` context string
`minimal.dev spec-hash epoch 1`.

D3.1 leaves three things to each epoch's spec: the field enumeration, the
normal forms and the tag layout. This section gives them for the **epoch-1
encoding**.

- **Spec fields.** These are the canonical form of a spec:
  - `name`, a string.
  - `prebuilt`, a flag.
  - `cmds`, a list of commands, each a list of argument strings.
  - `build_args`, a map from name to value.
  - The build inputs that are not edges, in the order the spec lists them.
    A web source is its `url` and `sha256`. A local source is its
    `filename` and `file_hash`. Each source also has its `extract` flag and
    an optional `strip_prefix`. A local input is its `filename` and
    `file_hash`.
  - `outputs`, a map from output name to output. An output is its kind
    (library, data or binary), its glob, and the flag of that kind
    (`allow_data`, `allow_executable` or `allow_missing_interpreter`).
  - `target`, its architecture and OS. The encoding always emits it, the
    default target included.
  - `abstract_deps`, a map from name to attribute value. An attribute value
    is a flag, a string, a number, or an enum variant's name with its value.
    It can also be a list or a map of attribute values.
  - The edges, as a set. An edge's kind is build input, runtime dependency
    or replace-on-cycle.
- **Outside a spec's canonical form:** `tests` (EPOCH-010), the attributes
  defined on the spec (`attrs`) and its origin (`from`). The diagnostic
  fields are also outside: `url_pos`, `sha256_pos`, `full_path` and the
  positions of strings. Epoch 0 leaves all of these out too.
- **Subset fields.** A subset is a set of components. Each component
  holds the epoch-1 key of a spec and the set of output names the subset
  takes from that spec.
- **Container fields.** These are the canonical form of a container:
  - `name`, a string.
  - The member packages, as the set of their keys (EPOCH-014).
  - `entrypoint` and `cmd`, each an optional list of strings.
  - `arch`, `working_dir`, `user` and `stop_signal`, each an optional
    string.
  - `env_vars`, `labels` and `config`, each a map from string to string.
  - `exposed_ports` and `volumes`, each a set of strings. A port enters as
    `port/proto`.
- **Normal forms.** For specs these are EPOCH-002 and EPOCH-006 and
  nothing more. A spec's other lists and maps keep the order the spec
  declares, and that order is part of the spec's canonical form, as it
  is in epoch 0: two recipes that list the same `build_args` in a
  different order are two specs with two keys. The injectivity claim is
  over that form, declared order included; normalizing these maps is a
  later epoch's change (Non-goals). The encoder orders a container's maps
  by key and sorts its sets, as epoch 0 does.
- **Layout.** The encoding is a byte-tagged TLV. Each field is a one-byte
  tag and then its payload; the first tag names the kind encoded, a spec, a
  subset or a container (EPOCH-022). Every string has a `u32` little-endian length
  prefix. Every list, set or map has a `u32` little-endian count prefix.
  A length or count the prefix cannot hold is refused, never truncated
  (EPOCH-001's sub-bullet), so the prefix is the whole of a value's
  framing. Keys take their 32 bytes, and flags take one byte. An optional value
  takes a present tag or an absent tag. The encoding emits every field the
  seal assigns, so an absence among them is always a tag (witness class 5).
  The one exception is a field added after the seal under a reserved tag
  (EPOCH-021): it is emitted only when set, after every sealed field, in
  ascending tag order, as a tag and its framed payload. Injectivity holds
  because the sealed fields have a fixed, fully framed layout that ends at a
  position the decoder knows, and each reserved tag appears at most once
  after it, so a closure that sets the field and one that does not differ in
  the bytes that follow the sealed fields. The encoder sorts a set by the
  bytes of its elements and drops repeats.
- **What the codec module fixes.** The tag byte values, the field order and
  the byte layout of a number are those of the epoch-1 codec module in
  `crates/graph`. No tag is in the reserve 0xF0 to 0xFF (EPOCH-007). The
  module and the golden digests that EPOCH-008 pins are normative for those
  bytes. That meets D3.1. This spec fixes the fields, their normal forms and
  their framing, which are what injectivity rests on. The pins fix the
  remaining bytes at the seal, and after the seal those bytes never change.
  A second client follows this definition and checks its keys against the
  pins.

The **epoch-0 defect catalog** is these nine collision-witness classes of
the epoch-0 encoder. Seven are a pair of distinct specs with one key; two
(7 and 8) are the converse, one spec with more than one key:

1. the unframed junction of `name` and `cmds`, so `name="foo", cmds=[["bar"]]`
   and `name="foobar", cmds=[]` share a key.
2. `cmds` collapsing at both levels, so `[["a","b"]]`, `[["ab"]]` and
   `[["a"],["b"]]` share a key.
3. in-band ASCII markers that adjacent content can forge.
4. subset outputs joined on a comma with a trailing marker, so an output
   name that contains a comma forges the list structure.
5. conditional emission, where a flag emitted only when set makes absence
   indistinguishable from adjacent content.
6. attribute lists and maps without length framing, so an empty list is
   indistinguishable from nothing and values migrate between containers.
7. platform-width indices, so a 32-bit client computes different keys for
   the same graph.
8. raw `f64` bytes, so negative zero and zero, and NaN payloads, make equal
   specs hash differently.
9. the subset hasher, which shares the family through an unframed hex
   parent key and tagged output names.

**Success:** two distinct canonical specs share a cache key only through a
Blake3 collision. A machine checks the injectivity of the encoding under
the key over bounded specs (EPOCH-001). A dependency reorder no longer
rotates keys.

**First slice:** the pure encode/decode codec with its machine-checked
round-trip and the witness refutations, plus the pinned epoch-1 digests.
No call site flips yet. A person runs `epoch1_golden_pins` and sees the
digests reproduce. The Kani lane then reports the round-trip and eight
refutations as proved, one for each class that has a witness to run
(classes 1 to 6, 8 and 9). Class 7 has no harness: it is refuted by the
layout, which holds no index and no reference (EPOCH-004).

## Users and stories

**Roles:** security engineer and package author. Verification engineer and
build-infra operator. Release manager.

- AS A security engineer I WANT the encoding to be an injective function
  of the spec's meaning SO THAT two keys agree only when Blake3 collides
  and cache poisoning by collision is impossible by construction
- AS A package author I WANT dependency identity to be order-independent
  (deps as sets) SO THAT reordering imports in a recipe never forces a
  spurious catalog rebuild
- AS A verification engineer I WANT the encoder to be a pure bounded codec
  with a decoder and machine-checked properties SO THAT the injectivity
  theorem is proved (Kani now, Lean later) rather than asserted
- AS A build-infra operator I WANT the epoch flip to change only which keys
  exist — same 32-byte hashes, same index/snapshot/provenance formats — SO
  THAT migration is one cold catalog rebuild, not a format migration
- AS A security engineer I WANT the Container Spec Hash to give the same
  guarantee as the package key SO THAT an OCI Archive fetched by key is as
  safe from substitution as a package tarball (D3.1, AT2)
- AS A release manager I WANT additive evolution (reserved tags,
  absent-means-epoch-1) after this change SO THAT no existing key ever
  changes again and the only keyspace change I schedule is a new epoch
  (D3.1)

## Requirements

- **EPOCH-001** THE SYSTEM SHALL encode canonically distinct specs to
  distinct byte strings.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_injectivity_bounded
  property: for all canonical a, b: a != b implies encode(a) != encode(b)
  harness:  kani_epoch1_injectivity_bounded, exhaustive over bounded specs
    (3 elements per list, set or map, 8 bytes per string, each edge key an
    arbitrary 32-byte value), unwind 33 (the 32-byte edge-key loop, as
    EPOCH-013's member keys. Strings and lists need less). The bound is
    the starting point. The codec PR measures the harness and records the
    bound it ran at
  - IF a string's byte length or a list's, set's or map's element count
    does not fit in the `u32` prefix THEN THE SYSTEM SHALL refuse the
    encoding with an error that names the field, so no two distinct values
    share a truncated prefix.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_overlong_value_is_refused

- **EPOCH-002** WHEN a permutation reorders a spec's edges, or an edge is
  listed more than once, THE SYSTEM SHALL produce an identical encoding.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_dep_order_irrelevant
  property: for all s, permutations p, edges e of s: encode(s) == encode(p(s))
    == encode(s with e listed again)

- **EPOCH-003** THE SYSTEM SHALL decode every epoch-1 encoding back to the
  canonical form of the spec it encodes.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_roundtrip_bounded
  property: for all bounded specs x: decode(encode(x)) == canon(x), and
    canon(canon(x)) == canon(x)
  harness:  kani_epoch1_roundtrip_bounded, exhaustive over bounded specs
    (3 elements per list, set or map, 8 bytes per string, each edge key an
    arbitrary 32-byte value), unwind 33 (the 32-byte edge-key loop)

- **EPOCH-004** THE SYSTEM SHALL refute every class of the epoch-0 defect
  catalog: the witness pair of each distinct-spec class (1 to 6 and 9)
  encodes to distinct outputs, and the witness of each one-spec class
  encodes to one output: for negative zero and zero (8, by EPOCH-006), and
  for class 7 by construction, since the epoch-1 encoding has no index or
  reference field at all (an edge enters as its 32-byte key, every length
  and count prefix is a `u32`), so no field of it has a platform width.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_witness_refutations
  property: for all distinct-spec witness pairs (a, b): encode(a) !=
    encode(b); for class 8's witness pair (z, -z): encode(z) == encode(-z);
    for class 7, the layout's field list holds no index and no reference
    (read from the layout, not run)
  harness:  kani_epoch1_witness_refutations, one harness per witness class
    with a witness to run (eight: 1 to 6, 8 and 9), each over its concrete
    witness, unwind 9 for classes 1 to 6 and 8 (their witnesses' strings
    are at most 8 bytes) and unwind 33 for class 9 (its witness pair
    carries a 32-byte parent key, the same loop EPOCH-001 bounds); class 7
    has no harness, since there is no width to vary

- **EPOCH-005** THE SYSTEM SHALL derive an epoch-1 spec key under the
  epoch-1 context, 32 bytes wide. A spec on no cycle is keyed from its own
  encoding; a member of a cycle is keyed with its cycle (EPOCH-026).
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_domain_separation_and_width
  property: for all specs s on no cycle: hash_1(s) ==
    blake3_derive_key(epoch-1 context, encode(s)), and len(hash_1(s)) == 32

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
    all 256 tag bytes with a bounded 8-byte payload, in spec, subset,
    container and cycle record position (the decoder of EPOCH-028), unwind
    9 (the payload loop)
  - THE SYSTEM SHALL assign no tag in 0xF0 to 0xFF at the epoch-1 seal;
    that range is the reserve an additive optional field (EPOCH-021) draws
    its tag from after the seal, and the test pins the seal's assignment,
    not the reserve's emptiness for all time.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_reserved_tags_unassigned

- **EPOCH-008** THE SYSTEM SHALL reproduce the pinned epoch-1 golden
  digests.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_golden_pins

- **EPOCH-009** WHEN the system seals a Registry Cache Index THE SYSTEM
  SHALL write the epoch of its keys into the flags field of every record.
  tier:     T1
  verify:   cargo nextest run -p rcache index_records_carry_their_epoch
  property: for all sealed indices i, records r in i: flags(r) == epoch(i)
  - IF an index file holds records of two epochs, or of an epoch the
    reader does not know, THEN THE SYSTEM SHALL refuse the whole file.
    tier:   T2
    verify: cargo nextest run -p rcache index_of_mixed_or_unknown_epoch_is_refused
    property: for all files f: read(f) succeeds only when every record's
      flags is one known epoch and all records share it; a record whose
      flags is not a known epoch fails at the flags field before the sha256
      bytes (the record is key, flags, sha256)
    harness: kani_index_file_one_epoch_or_refused, exhaustive over files of
      two records with symbolic flags (one epoch accepted; two known epochs
      refused; an unknown epoch refused at the flags field), unwind 3 (the
      two-record loop). The index reader's existing one-record harness
      `nonzero_flags_always_rejected` (`crates/rcache/src/index_file.rs`)
      becomes `unknown_epoch_always_rejected` and covers the per-record half

- **EPOCH-010** THE SYSTEM SHALL exclude a spec's `tests` from its canonical
  form.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_tests_outside_the_hash
  - THE SYSTEM SHALL run a spec's standalone tests against a read-only
    view of its **output tree**, the files the build produced under its
    declared outputs as the orchestrator captured them into the store, the
    bytes the spec's key names. The view is read-only by the sandbox's
    mount of those files, outside the test's own process, so no standalone
    test can turn it off; the standalone test sandbox mounts its rootfs
    this way today. A `build_test` test is not covered by this
    requirement: nothing runs one yet, and its guard is the first open
    question.
    tier:   T0
    verify: cargo nextest run -p orchestrator a_test_sees_the_output_tree_read_only
  - IF a test writes into the output tree THEN THE SYSTEM SHALL fail the
    test, and the captured outputs SHALL be the bytes they were before the
    test ran. This boundary is what makes leaving `tests` out of the key
    safe: a test that could change the output tree would give two outputs
    under one key.
    tier:   T0
    verify: cargo nextest run -p orchestrator a_test_that_writes_the_output_tree_fails

- **EPOCH-011** WHEN the system computes a subset key THE SYSTEM SHALL use
  the epoch of the spec key it subsets.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_subset_key_follows_its_spec
  property: for all subsets u of spec s: key(u) is derived under the same
    context and encoding as key(s) (a key carries no epoch in its bytes,
    EPOCH-014, so the test holds the epoch by construction and checks the
    derivation, never reads it back from a key)

- **EPOCH-012** WHEN a consumer computes a lookup key, of a spec, a subset
  or a container, THE SYSTEM SHALL use the epoch that the index of its
  registry pin declares.
  tier:     T1
  verify:   cargo nextest run -p rcache epoch_follows_pinned_index
  property: for all pins p whose index holds a record, specs, subsets or
    containers s:
    lookup_key(p, s) == hash(epoch(index(p)), encode_epoch(index(p))(s))
  - IF a lookup reads several indexes as one (an upstream with its
    sideloads) AND two of them declare different epochs THEN THE SYSTEM
    SHALL refuse the lookup and name both indexes. A per-commit snapshot
    and the root index it falls back to are the next rule's case, not this
    one's: that pair is never read as one when the epochs differ.
    tier:   T0
    verify: cargo nextest run -p rcache union_of_two_epochs_is_refused
  - WHILE a per-commit snapshot and the root index it falls back to declare
    different epochs THE SYSTEM SHALL withhold the fallback and answer a
    lookup from the snapshot alone, so the lookup is a miss and never a
    refusal.
    tier:   T0
    verify: cargo nextest run -p rcache root_fallback_withheld_across_epochs
  - WHERE an index holds no record THE SYSTEM SHALL treat it as declaring
    no epoch. It constrains no union it is part of, and a lookup whose
    every index is empty is a miss with no key computed, since there is no
    epoch to compute one under and nothing it could match.
    tier:   T0
    verify: cargo nextest run -p rcache empty_index_declares_no_epoch

- **EPOCH-013** THE SYSTEM SHALL encode canonically distinct containers to
  distinct byte strings.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_container_injectivity_bounded
  property: for all canonical containers a, b: a != b implies
    encode(a) != encode(b)
  harness:  kani_epoch1_container_injectivity_bounded, exhaustive over
    bounded containers (3 elements per list, set or map, 8 bytes per
    string, up to 3 member keys), unwind 33 (the 32-byte member-key
    loop; lists and strings need less)
  - THE SYSTEM SHALL encode the epoch-0 container witness, `env_vars`
    `{Av: B}` against `{A: vB}`, to distinct outputs.
    tier:   T1
    verify: cargo nextest run -p graph epoch1_container_witness_refuted
    property: encode({Av: B}) != encode({A: vB})

- **EPOCH-014** WHEN the system computes a container key THE SYSTEM SHALL
  enter each member package by the key that the same graph computes for
  that member under the container's epoch. On the producing side a
  container's epoch is the one it is configured to seal at: the same value
  that selects the spec and subset encoders, epoch 1 once the flip has
  moved it (EPOCH-015 derives the key under the epoch-1 context). A
  consumer that computes a container key to look one up takes the epoch
  that the index of its registry pin declares (EPOCH-012), never the
  producing side's setting, and enters the member keys under that epoch
  too. A key carries no epoch in its bytes, so the hasher never reads a
  member key from an index record; every member key it enters is of the
  container's epoch by construction.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_container_members_by_key
  property: for all containers c, members m of c: the member bytes of
    encode(c) are hash_e(m) for the container's epoch e

- **EPOCH-015** WHEN the system computes a container key for a container
  whose epoch is 1 (EPOCH-014) THE SYSTEM SHALL derive it under the epoch-1
  context from the container's canonical encoding, 32 bytes wide, as
  EPOCH-005 derives a spec key.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_container_key_derivation
  property: for all containers c: key(c) == blake3_derive_key(epoch-1
    context, encode(c)), and len(key(c)) == 32

- **EPOCH-016** THE SYSTEM SHALL decode every epoch-1 container encoding
  back to the canonical form of the container it encodes.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_container_roundtrip_bounded
  property: for all bounded containers c: decode(encode(c)) == canon(c)
  harness:  kani_epoch1_container_roundtrip_bounded, exhaustive over
    bounded containers, unwind 33

- **EPOCH-017** WHEN the system encodes a subset THE SYSTEM SHALL
  length-frame every output name.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_subset_output_names_framed
  property: for all distinct output sets a, b of a spec s:
    encode(u_a) != encode(u_b)

- **EPOCH-018** THE SYSTEM SHALL leave the pinned epoch-0 golden digest
  byte-identical.
  tier:     T0
  verify:   cargo nextest run -p graph epoch0_golden_pin_unchanged

- **EPOCH-019** THE SYSTEM SHALL serialize an epoch-1 key exactly as it
  serializes an epoch-0 key in each format that embeds a SpecHash. The
  formats are those of the epic's acceptance criterion 4: index records,
  snapshots, closures, provenance subjects, events and object names.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_record_layouts_unchanged

- **EPOCH-020** WHEN a permutation reorders a container's members THE
  SYSTEM SHALL produce an identical encoding.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_container_member_order_irrelevant
  property: for all containers c, permutations p of c's members:
    encode(c) == encode(p(c))

- **EPOCH-021** WHERE an optional field is added to epoch 1 under a
  reserved tag THE SYSTEM SHALL encode a closure that does not set the
  field byte-identically to epoch 1 without the field. The test adds a
  test-only optional field under a tag from the reserve 0xF0 to 0xFF
  (EPOCH-007) and compares a closure that does not set it with the same
  closure under the sealed encoder. The field exists only in the test
  build, so the seal's tag assignment does not change.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_absent_field_is_byte_identical

- **EPOCH-022** THE SYSTEM SHALL begin the encoding of each kind it keys,
  a spec, a subset and a container, with a tag of that kind's own, so no
  two kinds' encodings are the same byte string and no key of one kind is
  a key of another under the one epoch-1 context. Epoch 0 leads with
  `build spec`, `subset` and `container`; epoch 1 keeps one leading tag per
  kind, and the three injectivity requirements (EPOCH-001, EPOCH-013,
  EPOCH-023) then compose across kinds.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_kinds_lead_with_distinct_tags
  property: for all specs s, subsets u, containers c: lead(encode(s)),
    lead(encode(u)) and lead(encode(c)) are pairwise distinct, so no two
    of encode(s), encode(u), encode(c) are equal

- **EPOCH-023** THE SYSTEM SHALL encode canonically distinct subsets to
  distinct byte strings.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_subset_injectivity_bounded
  property: for all canonical subsets a, b: a != b implies
    encode(a) != encode(b), whether they differ in a component's spec key,
    in a component's output names or in their sets of components
  harness:  kani_epoch1_subset_injectivity_bounded, exhaustive over
    bounded subsets (up to 3 components, each an arbitrary 32-byte spec
    key with up to 3 output names of at most 8 bytes), unwind 33 (the
    32-byte spec-key loop; output names need less)

- **EPOCH-024** THE SYSTEM SHALL decode every epoch-1 subset encoding back
  to the canonical form of the subset it encodes.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_subset_roundtrip_bounded
  property: for all bounded subsets u: decode(encode(u)) == canon(u)
  harness:  kani_epoch1_subset_roundtrip_bounded, exhaustive over bounded
    subsets, unwind 33

- **EPOCH-025** WHEN the system keys a graph THE SYSTEM SHALL first make
  specs that mean the same one node, so equivalent closures give one
  preimage and one meaning has one key.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_equal_meaning_is_one_node

- **EPOCH-026** WHEN the system keys a member of a cycle THE SYSTEM SHALL
  key the cycle as one unit. The member digest is derived under the epoch-1
  context from the member's canonical fields and its edges that leave the
  cycle, each as its kind, its output set and its target's key. The cycle
  key is derived under the epoch-1 context from the cycle's canonical
  record. The member's key is derived under the epoch-1 context from the
  cycle key and the member digest, 32 bytes wide. No root, traversal order,
  index or recipe order enters any of the three.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_cycle_member_key_derivation
  property: for all cycles C, members m of C: digest(m) ==
    blake3_derive_key(epoch-1 context, encode_digest(m)), key(m) ==
    blake3_derive_key(epoch-1 context, encode_member(blake3_derive_key(
    epoch-1 context, encode(record(C))), digest(m))), and len(key(m)) == 32
  - IF two members of one cycle have the same member digest after the
    merge (EPOCH-025) THEN THE SYSTEM SHALL refuse the graph with an error
    that names both members and where each is declared.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_cycle_tie_is_refused

- **EPOCH-027** THE SYSTEM SHALL encode canonically distinct cycle records
  to distinct byte strings.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_cycle_injectivity_bounded
  property: for all canonical cycle records a, b: a != b implies
    encode(a) != encode(b)
  harness:  kani_epoch1_cycle_injectivity_bounded, exhaustive over bounded
    cycle records (up to 3 entries, each an arbitrary 32-byte member digest
    with up to 3 inside edges, each edge with up to 3 output names of at
    most 8 bytes and an arbitrary 32-byte target digest), unwind 33 (the
    32-byte digest loop; output names need less)

- **EPOCH-028** THE SYSTEM SHALL decode every epoch-1 cycle record
  encoding back to the canonical form of the cycle record it encodes.
  tier:     T2
  verify:   cargo nextest run -p graph epoch1_cycle_roundtrip_bounded
  property: for all bounded cycle records r: decode(encode(r)) == canon(r)
  harness:  kani_epoch1_cycle_roundtrip_bounded, exhaustive over bounded
    cycle records, unwind 33

- **EPOCH-029** WHEN a permutation reorders the specs of a graph or the
  edge list of a spec, or the computation starts from a different spec,
  THE SYSTEM SHALL produce an identical key for every spec of the graph,
  each member of a cycle included.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_cycle_keys_ignore_order_and_root
  property: for all graphs g, permutations p of g's specs and of each
    spec's edge list, specs r and r' of g, specs s of g:
    key_{g,r}(s) == key_{p(g),r}(s) == key_{g,r'}(s)

- **EPOCH-030** THE SYSTEM SHALL begin the encoding of a member digest, a
  cycle record, a member key and a first-build key each with a tag of its
  own, distinct from each other and from the three leading tags of
  EPOCH-022, so no value of one of these kinds is a value of another kind
  under the one epoch-1 context.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_cycle_kinds_lead_with_distinct_tags
  property: the leading tags of the encodings of a spec, a subset, a
    container, a member digest, a cycle record, a member key and a
    first-build key are pairwise distinct

- **EPOCH-031** WHEN the system makes the first build of a member THE
  SYSTEM SHALL give it, for each dependency on a member of the same cycle,
  that member's `replace_on_cycle` spec, or that member's first build where
  it has no `replace_on_cycle` spec. The rule holds at each depth of the
  closure of the build box and for a member that depends on itself.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_first_build_takes_replace_on_cycle_specs
  - WHERE a member has no build steps THE SYSTEM SHALL build it once and
    use that build as both its first build and its final build.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_member_without_build_steps_builds_once

- **EPOCH-032** WHEN the system makes the final build of a member THE
  SYSTEM SHALL give it the first build of each dependency on a member of
  the same cycle, itself included, and never a final build of a member of
  that cycle.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_final_build_takes_first_builds

- **EPOCH-033** WHEN the system stores or finds the first build of a member
  THE SYSTEM SHALL use the member's first-build key, derived under the
  epoch-1 context from the member's key alone, 32 bytes wide, and distinct
  from the member's key.
  tier:     T1
  verify:   cargo nextest run -p graph epoch1_first_build_key_derivation
  property: for all members m: first_key(m) == blake3_derive_key(epoch-1
    context, encode_first(key(m))), len(first_key(m)) == 32, and
    encode_first(key(m)) leads with the first-build tag (EPOCH-030), so
    first_key(m) != key(m) except through a Blake3 collision

- **EPOCH-034** THE SYSTEM SHALL put a first build in no box but the build
  box of a member of its own cycle.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_first_build_held_only_by_its_cycle
  - THE SYSTEM SHALL seal no Registry Cache Index record for a first
    build, so no catalog lists it and no lookup by a spec key finds it.
    tier:   T0
    verify: cargo nextest run -p rcache a_first_build_is_never_indexed

- **EPOCH-035** WHEN the system loads an inline `replace_on_cycle` spec THE
  SYSTEM SHALL take each of its dependencies on a package to mean that
  package's `replace_on_cycle` spec, for the inline spec's key and for its
  build.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_inline_spec_deps_are_replace_on_cycle_specs
  - IF an inline `replace_on_cycle` spec names a package that has no
    `replace_on_cycle` spec THEN THE SYSTEM SHALL refuse the graph at load
    with an error that names that package.
    tier:   T0
    verify: cargo nextest run -p graph epoch1_inline_spec_naming_a_package_without_one_is_refused

- **EPOCH-036** IF a package of a cycle names an output of a package of the
  same cycle, and that package's `replace_on_cycle` spec does not have the
  output, THEN THE SYSTEM SHALL refuse the graph at load with an error that
  names the missing output, the package whose `replace_on_cycle` spec
  lacks it and the package that names it.
  tier:     T0
  verify:   cargo nextest run -p graph epoch1_missing_replace_on_cycle_output_is_refused

## Non-goals

- Changing the hash's size or algorithm: the interaction inventory in the
  epoch-0 defect catalog issue, minimal#1246
- Migrating historical epoch-0 artifacts: they stay valid for old pins
  (minimal#1246, decision 4)
- Wire varint work: the decode harness, minimal#3260
- Normalizing the order of a spec's `build_args`, `outputs` and
  `abstract_deps`: epoch 0 keys on their declared order and so does this
  epoch, whose scope is the nine witness classes. Sorting them by key, as
  the container encoding does, would be a new canonical form for every
  spec and belongs to an epoch of its own.
- The slots feature: gominimal/inbox#350. This spec only guarantees that
  the name axis is sound.
- Publishing OCI Archives to the Registry Build Cache with their index
  records, Container Provenance and Container SBOM: build-servers#371. This
  spec fixes the container key those records use, and nothing more.
- The Lean proof of EPOCH-001: minimal#3261. Kani holds the property at
  T2, and the theorem is an open question below.
- Signing the epoch an index declares: the index's Sigstore bundle covers
  the sealed bytes, and client-side bundle verification is minimal#2736.
- Gating the signing of release attestations on epoch 1, and retiring
  epoch 0 by a minimum accepted epoch in the trust root:
  gominimal/arch#157. This spec defines the encoding those attestations
  key on.
- The provenance of a first build, its mark in the `resolvedDependencies`
  of a final build, and the release gate's acceptance of a first build by
  its provenance with no Package VSA: gominimal/build-servers, under
  gominimal/arch#183 (decisions D-29). This spec fixes the key those
  records name a first build by (EPOCH-033).
- Counting which members of the package graph's cycle build with the
  `replace_on_cycle` specs alone, and changing the packages that do not:
  gominimal/pkgs, under gominimal/arch#183 (OQ-54). EPOCH-031 is the rule
  that count measures against.

## Design reasoning

The codec is a fixed-width, byte-tagged TLV and does not use varints. With
TLV, injectivity is structural. Every payload has a length prefix and every
list has a count prefix. A key is 32 bytes, every prefix is a `u32`, and
nothing in an encoding is an index into anything. So a 32-bit client encodes
the same bytes as a 64-bit one. The codec also stays in the provers' comfort zone. It is pure, with no
unsafe code, no trait objects and no unbounded recursion, because the spec
walk stays outside it.

Domain separation carries the epoch, so versioning costs zero preimage
bytes and no downstream format changes. The sealed fields have no
conditional emission because adjacent content must never express an
absence. That ambiguity is the root cause of five of the nine witness
classes. The one kind of field emitted only when set is an optional field
added after the seal (EPOCH-021). It comes after every sealed field, as a
reserved tag and its framed payload, so a closure that sets it and one
that does not differ by a tagged field and never by what adjacent bytes
mean.

An edge is the dependency's key and kind, and a spec's edges enter as a
set ordered by those bytes (EPOCH-002). That is what lets a bottom-up fold
prove the well-definedness half of the biconditional. A dependency's key is
fixed before any spec that names it is encoded, and two listings of the
same dependency are one edge. The epoch-0 encoder numbered dependencies in
discovery order, which is a property of a traversal and not of the spec.

The flip is a one-time cold rebuild. Dual publishing turns one breaking
change into three, so the design has no dual-hash machinery. The decision
ledger is in the epoch-0 defect catalog issue, and the audit rationale is
in the formal-verification path.

D3.1 has four commitments, and each maps to requirements:

- injective over the closure's meaning: EPOCH-001, EPOCH-002, EPOCH-004,
  EPOCH-013, EPOCH-023, on a cycle EPOCH-025, EPOCH-027 and EPOCH-029,
  and, across kinds, EPOCH-022 and EPOCH-030
- epochs by domain-separated context at a fixed 32 bytes, declared by the
  index and followed by consumers: EPOCH-005, EPOCH-009, EPOCH-012,
  EPOCH-014, EPOCH-015, EPOCH-019, EPOCH-026 and EPOCH-033
- keyspace rotation as a migration class: the Rollout section and the
  migration non-goal
- additive evolution, with an unknown tag as a hard error: EPOCH-007 and
  EPOCH-021

Under EPOCH-007 and EPOCH-021, additive evolution (D3.1) is a promise about
keys and not about readers. A new optional field takes a reserved tag and is
absent from every closure that does not set it. Every existing key is
unchanged, and no catalog rebuilds. A decoder older than the field
hard-errors on an encoding that carries it. That reaches `decode()` alone,
which nothing on the key path calls, because the decoder exists for
EPOCH-003's round-trip. So a reader older than the data it meets is a
tooling-version error and never a keyspace change. A change that no
absent-means-epoch-1 field can express is a new epoch.

The index records its epoch in the flags field of each record (EPOCH-009).
The index format reserved that field for format changes, and the reader
already refuses any non-zero value. The harness `nonzero_flags_always_rejected`
proves that gate today, and EPOCH-009's refusal is the same gate with the
known epochs admitted. So an epoch-0 index stays byte-identical, and the
record layout does not change. The Sigstore bundle signs the sealed index
bytes, so it covers the epoch too. A client older than this change refuses
an epoch-1 index and asks for an update. That refusal fails closed, and it
is correct. Such a client computes epoch-0 keys and can find nothing in an
epoch-1 index. The alternative was a field in the bundle's signed statement.
Old readers ignore that field, but today's client checks no bundle, so the
consumer half (EPOCH-012) then waits on client-side Sigstore verification.

EPOCH-012 selects the epoch through the pinned index and never through a
global setting. That keeps historical pins valid through the flip, with
no dual publishing. The producing side has three encoder call
sites (spec, subset, container) behind one config value, and they move
together; consumers follow their indices. An index that
declares a lower epoch than the one a pin's commit was sealed with is not a
downgrade the keyspace permits. It is an index substitution. A pin names a
commit, and the commit names its index object. Replacing that object is
the threat the index's Sigstore bundle answers, outside this spec. Epoch 0
stays accepted for the pins that produced it (D3.1), so this spec sets no
floor. The root-index fallback is withheld across epochs (EPOCH-012) rather
than refused. The flip's first snapshot lands before the root index
reseals, and a consumer in that window should see a miss it can rebuild
from, not a refusal it cannot.

Kani holds EPOCH-001's property at T2. The Lean theorem would raise it to
T3, and the spec claims that tier only once the theorem exists. The proof
is also a proposal to add a Lean project and a proof lane to this
repository, which has neither. That cost belongs to the formal-verification
epic and not to the codec PR. The harness bounds in
this spec are starting points. The codec PR measures each harness and
records the bound it ran at, so the bound a reader sees is one a
machine ran.

Well-definedness beyond dependency order is the canonical form itself.
Numbers normalize (EPOCH-006) and `tests` stay out (EPOCH-010). Editing a
test never rotates a key, and a person can re-run tests without a rebuild.
The write-guard makes that assumption real instead of hashing around it.
The subset key (EPOCH-011) follows the spec key's epoch because witness
class 9 is its collision family. Its output names are length-framed
(EPOCH-017) because witness class 4 is. EPOCH-023 and EPOCH-024 hold the
subset's injectivity and round-trip over bounded subsets, as EPOCH-013 and
EPOCH-016 do for containers, so class 9 is refuted over the whole bounded
domain and not only on its witness pair (EPOCH-004). A subset computed
under another epoch cannot find the index of its spec.

The container key (EPOCH-013, EPOCH-014, EPOCH-015, EPOCH-020) is the same
codec with container tags. EPOCH-016 and EPOCH-007's container harness
cover the container round-trip and the unknown-tag rejection in container
position. The container encoder chooses its encoder at its own call site.
The flip must move that site together with the spec and subset sites, or
containers stay on epoch 0 with the container witness pinned. A container
is a declaration over packages. Its members enter by key. A container key
is well-defined only when every member key is of the container's epoch.
The hasher computes each member key from the graph, under the same encoder
choice that keys the container (EPOCH-014), so that holds by construction
and needs no check. A member with no record under the container's epoch
in an index is a cache miss, and the member rebuilds, as any miss does.
Before the flip a container key is an epoch-0 key.
Today no index holds a container record, so the container keyspace has
nothing to rotate. The epoch-0 container witness (EPOCH-013) is a property
of the epoch-0 encoding and not of a stored key.

This spec binds four decisions from the epoch-0 defect catalog's ledger.
`tests` stay outside the canonical form with a write-guard (EPOCH-010).
Reserved-tag additive evolution, with an unknown tag as a hard error, comes
from the architecture (EPOCH-007, EPOCH-021). The index records its epoch in
each record's flags field (EPOCH-009), with the signed-statement
alternative above. The migration is a one-time cold rebuild, as the
Rollout section prescribes. Dual hashing, keeping epoch-0 keys live beside
epoch-1 keys, doubles every index. It also makes the epoch a per-record
question for the whole overlap, which EPOCH-009's one-epoch-per-index rule
exists to avoid.

An edge enters a spec's encoding as its target's key, and on a cycle no
member has a key before the others. Epoch 0 numbered specs in the order a
walk found them, which put the root of the walk into the hash. The
architecture keeps cycles in the hash ("The hash covers the closure of
specs as today, cycles included", gominimal/arch#183, build §7) and asks
this spec for "the encoding of a cycle as one unit" with no root in it
(decisions D-29). EPOCH-026 splits what a member is from how the members
connect. The member digest holds the member's own fields and the edges
that leave the cycle, whose keys exist already because the system keys
the graph from the bottom up. The cycle record holds every member's
digest and its edges inside the cycle, which name their targets by
digest. A member's key binds the cycle key to its own digest. Nothing in
any of the three is a position, so reordering the graph or starting from
another spec gives the same bytes (EPOCH-029). A change to one member
changes the key of every member and of every spec above the cycle, as
epoch 0 does. The cycle record is a set of entries, as a container is a
set of members, so its injectivity and round-trip harnesses take the
container's form (EPOCH-027, EPOCH-028). Each of the new encodings leads
with a tag of its own (EPOCH-030), so no encoding of a member digest or a
cycle record is the encoding of a spec, and the injectivity requirements compose
across all seven kinds as they do across three under EPOCH-022.

The merge comes first (EPOCH-025) because D3.1 asks for one preimage per
meaning. Without it, a copy of a member that sits outside the cycle gets a
second key, and a closure that holds both would trip the architecture's
refusal of two builds of one package (D-29) falsely. After the merge, two
members with one digest differ only in their edges inside the cycle, and
those edges name targets by digest, so the encoding has nothing to order
the two by. The name is a canonical field, so such a pair is two specs of
one name on one cycle, which the architecture refuses in a closure
anyway. The refusal names where each is declared because the two names
are equal.

A member is built twice so that the inputs of each build are a function of
the specs (D-29). The owner ruled on what stands in during a first build:
"each package of the cycle that has a `replace_on_cycle` spec is that spec,
and a package with none comes as its first build" (comment on
gominimal/arch#183, 2026-11-19). A final build takes the first builds and
never a final build of its cycle (EPOCH-032). So the root of a walk, the
order of the builds and the content of a store never change what a build
takes, and a store can keep one built package per key. The rejected
alternative, a dependency's own first build where it is ready earlier, is
what today's planner does. Under it an edge that one package adds can
change the inputs of other members' first builds. The chosen rule costs
something instead: each member must build with its cycle's
`replace_on_cycle` specs alone, and nobody has counted yet how many do
(OQ-54 of gominimal/arch#183).

A first build is a second build of the member's spec with other inputs, so
it cannot be stored under the member's key. Its key is derived from the
member's key under a leading tag of its own (EPOCH-033), so it changes
exactly when the member's key does and equals no catalog key. The owner
ruled that "a first build has a key that is derived from the hash, the
catalog does not list it, and only a build box of its cycle holds it"
(2026-11-19), and EPOCH-034 holds both halves on this side. No client box
installs a first build, so it needs no index record.

An inline `replace_on_cycle` spec is used only in a first build, and there
every package of the cycle that has a `replace_on_cycle` spec is that spec.
So in an inline spec a dependency on a package means that package's
`replace_on_cycle` spec (EPOCH-035), and the loader refuses a name with no
such spec. An inline spec's key then covers what it is built with, and the
inline specs are keyed among themselves: they change only when an inline
spec changes, never with a recipe of the cycle. A `replace_on_cycle` spec
"has each output that a package of its cycle names" (owner ruling,
2026-11-19). In a first build a name like `{ pkg = "gcc", outputs =
["libgcc"] }` selects that output of the `replace_on_cycle` spec, so
EPOCH-036 is the loader's ordinary refusal of an output that does not
exist, applied where the name lands. The spec needs no other output of its
package, and its output kinds need not agree with the package's, because
it is a spec of its own.

The release-attestation scheme of gominimal/arch#157 signs only at epoch 1
or later. So no signature covers a key with epoch 0's known collisions.
That gate belongs to the verification scheme, and this spec only supplies
the encoding it relies on.

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
  covered by: EPOCH-001, EPOCH-004, EPOCH-011, EPOCH-013, EPOCH-017,
    EPOCH-022, EPOCH-023, EPOCH-027, EPOCH-030
- **Invariant:** THE SYSTEM SHALL never let the root of a walk, the order
  of the builds or the content of a store change what a build of a cycle
  member takes.
  enforced by: the two-build rule, under which a first build takes the
    `replace_on_cycle` specs and a final build takes the first builds, and
    first builds stored under keys of their own
  covered by: EPOCH-029, EPOCH-031, EPOCH-032, EPOCH-033, EPOCH-034
- **Invariant:** THE SYSTEM SHALL never silently absorb unknown structure
  into a hash preimage.
  enforced by: the encoder, which emits only the tags of its epoch for the
    fields of the canonical form and nothing else. Strict decoding, where
    an unknown tag is a hard error, guards the tooling that reads encodings
    back, since nothing on the key path decodes
  covered by: EPOCH-001, EPOCH-007
- **Invariant:** THE SYSTEM SHALL trust epoch-0 keys for pinned history
  only, and SHALL never re-bless old artifacts under new keys.
  enforced by: the epoch each index record declares (EPOCH-009), which
    every consumer reads for its lookup keys (EPOCH-012), and the absence
    of any migration path. Today's client checks no Sigstore bundle, so the
    signature over that declaration is future work and not an enforcement
  covered by: EPOCH-005, EPOCH-009, EPOCH-012

## Rollout

- **Deploy:** the client that reads the epoch from an index goes out in a
  release first (EPOCH-009, EPOCH-012). An older client refuses an epoch-1
  index. Then the producing side flips: one config value moves the three
  encoder call sites (spec, subset, container) together, so no container
  or subset stays on epoch 0 behind a flipped spec site (EPOCH-014). The
  producing side is build infrastructure, remote execution and the hosts
  that seal new indices. Consumers never flip. They follow the epoch their
  pinned index declares. The root index reseals under epoch 1 in the same cycle
  that seals the first epoch-1 snapshot. Until it does, the snapshot's
  root-index fallback is withheld (EPOCH-012). No lookup unions the two
  epochs, and for a client at or after the reading release the flip shows
  misses and never refusals, with one exception the flip itself can force
  while producers are mid-flip: a lookup over an upstream index and
  sideloads on different epochs is refused (EPOCH-012). It ends when the
  sideloads reseal under epoch 1, which the producing side does in the
  same cycle as the root index: one config value, one flip. A container's
  member keys are computed under the container's epoch (EPOCH-014), so a
  member not yet sealed under epoch 1 is a miss that rebuilds. A client
  before the reading release refuses the
  first epoch-1 index as any unknown epoch (EPOCH-009), which is why the
  reading release ships first and the flip waits until the fleet is on
  it. The catalog
  rebuilds cold under epoch-1 keys on the first package CI cycle
  at that release. That is a full world rebuild, and build-infra schedules
  it on purpose. A staged catalog rebuild on the staging cache comes before
  the release.
- **Rollback:** a flip like any other, backwards. The producing side
  returns to epoch 0 and seals no epoch-1 index after it. Epoch-0 indices,
  objects and snapshots stay valid throughout, and a pin whose every index
  declares epoch 0 sees no change. A per-commit snapshot sealed after the
  rollback beside a root index still on epoch 1 is a cross-epoch pair. The
  fallback is withheld for the window (EPOCH-012), and the root index
  rolls back with the producers. Rollback takes minutes and schedules no
  catalog rebuild. An entry that exists only under an epoch-1 key misses on
  an epoch-0 pin and rebuilds on its own, as any miss does.
- **Blast radius:** catalog consumers during the one cold rebuild window
  see cache misses, and never wrong data. Record layouts do not change.

## Open questions

- [NEEDS CLARIFICATION (HIGH): the mechanism of EPOCH-010's write guard for a
  `build_test` test. A standalone test already runs in a test sandbox whose
  rootfs, the outputs it depends on included, is mounted read-only, so the
  guard is the mount. A `build_test` test is declared and nothing runs it
  yet: the checker skips it and the test operation refuses it. Whether it
  runs in the build sandbox after the outputs are captured, against a
  read-only remount of them, or in a test sandbox of its own like a
  standalone test, depends on how the orchestrator runs a `build_test` in
  the sandbox. Either way the guard is the sandbox's, never the test's.
  This closes before `epoch1_tests_outside_the_hash` is written.]
- [NEEDS CLARIFICATION (MEDIUM): the Lean theorem for EPOCH-001. Which
  project and proof lane carry it, and when. EPOCH-001 moves to T3 with a
  `proof:` line once the theorem exists.]
- [NEEDS CLARIFICATION (LOW): the measured harness bounds. The unwind
  bounds in this spec are starting points. The codec PR records the bounds
  its harnesses ran at.]
- [NEEDS CLARIFICATION (HIGH): which packages a reference as
  `replace_on_cycle` can name. The architecture leaves it to this spec:
  "No MPR spec has a reference as its `replace_on_cycle` (§9, row 11), and
  the epoch-1 spec says which packages such a reference can name"
  (gominimal/arch#183, build §7). The owner's list for this spec includes
  "what a reference as `replace_on_cycle` can name" (comment of
  2026-11-19, item 7). Neither source gives the rule, and EPOCH-035 covers
  the inline form only. This closes before the loader accepts a reference
  in that position.]
- [NEEDS CLARIFICATION (MEDIUM): which runtime dependencies a
  `replace_on_cycle` spec brings into a first-build box. Build §7 says
  "The rule applies at each depth of the closure of the build box", and
  EPOCH-031 carries that sentence. The question "in a first-build box, does
  a spec'd dependency bring its spec's `runtime_deps` or the real
  package's?" is asked on gominimal/arch#183 (the OQ-54 comment) and not
  yet answered.]
- [NEEDS CLARIFICATION (MEDIUM): whether this spec carries the loader's
  refusal of a cycle that has no order of first builds. Build §7 has it:
  "If a loop of dependencies has a package with build steps and no package
  with a `replace_on_cycle` spec, no order of first builds exists. The
  loader refuses it and names the packages of the loop." The owner's list
  for this spec names "the two refusals of the loader", which EPOCH-035 and
  EPOCH-036 carry, and does not name this one.]
- [NEEDS CLARIFICATION (LOW): how a first build finds a member with no
  build steps. Build §7 says "A package with no build steps has one build,
  which serves as the two" (EPOCH-031). Whether that build is stored under
  its first-build key as well as its spec key, or a first build looks it up
  by its spec key, is not stated.]
- [NEEDS CLARIFICATION (LOW): whether the member-digest encoding has a
  bounded harness of its own. It holds the spec field list with only the
  edges that leave the cycle, under its own leading tag (EPOCH-030).
  EPOCH-001's harness runs over the spec encoding only.]
- [NEEDS CLARIFICATION (LOW): which spec carries the architecture's second
  defence: "the release gate and `min` refuse a closure that holds two
  builds of one package" (decisions D-29). It is not on the owner's list
  for this spec.]
