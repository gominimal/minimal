---
id: SBOM
title: box SBOM + CycloneDX Blueprint
owner: bryan-minimal
epic: gominimal/inbox#582
arch: https://github.com/gominimal/arch/blob/3dab1097cda11652ad24282969ed8dfe61d0d497/architecture.md
arch_sha: "3dab1097cda11652ad24282969ed8dfe61d0d497"
updated: 2026-10-19
---

# SBOM — box SBOM + CycloneDX Blueprint

## Context

Minimal owns the complete declared story of a box — its expanded Box Spec
(BOX-068), closure and pins — but cannot export it in the formats the world
consumes. Security scanners want an SBOM; compliance wants documents whose
digests are evidence rather than assertion; build infrastructure wants
per-package SBOMs at publish chained to the signed per-commit closure;
developers granting agent boxes want the posture story reviewable before
granting it; `min box list --using <pkg>` (architecture, Command tree) needs
a box's component set to answer from, and the box CLI spec (BCLI, minimal#1991)
defers that flag to this spec's epic.

A **box** is any entry the Box Spec expands: a session, task, agent or
service (BOX-046 reads the typed tables as `[boxes.<name>]`). Every box has
an expanded spec the daemon stores (BOX-068), and that spec, never the entry
or the running box, is what this spec's documents describe.

**Success:** a box yields schema-valid supply-chain documents whose
component digests chain to the signed catalog closure or carry a declared
digest gap, and whose regeneration is byte-identical.

A **catalog pin** is the triple {repo, commit, closure object} the epic
defines; every document is emitted under one, and "the pin" below always means
it.

A document for a box is a **composition**, not a re-derivation: the
**per-package document** published beside the package's artifact (SBOM-013
names it) is the unit, and a box's document is an envelope of
composition-level facts over references to those units, resolved through the
box's pin. A component has a **digest gap** when the pinned closure
references no per-package document for it, which is the ordinary case for a
package built locally or non-redistributable by policy, and the gap names
which: `built-locally` or `non-redistributable`. SBOM-004 and SBOM-011 use
that one definition. A document the closure references but that cannot be
fetched is not a gap; it is SBOM-012's failure. Until build-servers#185 pins
the document digest in the closure (Non-goals), *references* is decided by
the closure entry alone: a component whose entry maps its Build Spec Hash to
a cache artifact digest references the document SBOM-013 names from that
hash, and a component whose entry is `built-locally` or `non-redistributable`
has no artifact, no document, and the gap. No probe of the cache takes part
in that decision, so SBOM-001's determinism holds, and a referenced document
the cache does not have (a 404 as much as a timeout) is SBOM-012's failure.

A box's **posture** is what its expanded Box Spec declares it may reach,
read, write, inherit or expose: `[network]` (mode, `[network.egress]`,
`ingress`, `dynamic_ingress`, `quic443`, `[network.bep]`), `[secrets]`
references, `[env_vars]` and `[loadouts.vars]` with their `inherit` flags,
`[[file_imports]]`, `[[file_exports]]`, `[[github_imports]]`, `volumes`,
`[[loadouts]]` with their patches and lifecycle hooks, `[machine]` and
`[execution]`, `[io]`, `lifetime`, `[nesting]` and `[otel]`. Each axis is
**enforced** (the daemon or host refuses what it does not allow),
**declared** (accepted and recorded, enforcement unowned or in flight; BOX-076
warns once at creation), or **in flight** (its spec is open: NET, BRES, BVOL,
BEP). The Blueprint carries that label per axis (SBOM-006).

**First slice:** publish emits a per-package document for one catalog
package under SBOM-013's names, beside its artifact; a fixture box then emits
validated CycloneDX 1.5 and minimal-valid SPDX 2.3 over it, byte-stable
across regenerations. CycloneDX 1.5 is the SBOM format because it is the one
scanners read today; the 2.0 draft is used for the Blueprint only.

## Users and stories

**Roles:** security engineer; compliance reviewer / downstream consumer;
developer running agent boxes; build-infra operator; auditor.

- AS A security engineer I WANT a CycloneDX SBOM of any box SO THAT
  existing scanners and policy tooling can evaluate what Minimal boxes
  contain
- AS A compliance reviewer I WANT component digests that verifiably chain to
  the signed per-commit catalog closure SO THAT the document is evidence,
  not assertion
- AS A developer running agent boxes I WANT a Blueprint of a box's declared
  posture SO THAT I can review what an agent box may do before granting it,
  and see which of its boundaries are enforced today
- AS A build-infra operator I WANT the same SBOM model emitted per-package at
  publish time SO THAT catalog artifacts ship with supply-chain documents
  without a second implementation
- AS AN auditor I WANT deterministic regeneration SO THAT two parties can
  independently produce and compare the same document
- AS A developer I WANT `min box list --using <pkg>[@<ver>]` to answer from
  the same component set the box's SBOM carries SO THAT the list and the
  document never disagree about what a box contains

## Requirements

- **SBOM-001** WHEN the same catalog pin and identical declared inputs are
  emitted twice THE SYSTEM SHALL produce byte-identical documents, deriving
  serials, namespaces, and timestamps from content and pin, never from wall
  clock or randomness.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_regeneration_deterministic
  property: for all pin, inputs, and independent emissions a, b under
    (pin, inputs): bytes(a) == bytes(b)
  - IF the cache's contents differ between two emissions under the same pin,
    every object the pinned closure references remaining fetchable, THEN THE
    SYSTEM SHALL still produce byte-identical documents, the composition
    being a function of the pin and its closure rather than of what the
    cache happens to hold. (An unfetchable referenced object is SBOM-012's
    failure, and fails the same way on every emission.)
    tier:   T0
    verify: cargo nextest run -p sbom sbom_determinism_independent_of_cache_state

- **SBOM-002** WHEN a document is emitted as CycloneDX THE SYSTEM SHALL
  produce output that validates against the vendored CycloneDX 1.5 schema.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_cdx_schema_conformance
  property: for all compositions c: cdx_schema_valid(emit_cdx(c))

- **SBOM-003** WHEN a document is emitted as SPDX THE SYSTEM SHALL produce
  minimal-valid SPDX 2.3.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_spdx_validity
  property: for all compositions c: spdx_valid(emit_spdx(c))

- **SBOM-004** THE SYSTEM SHALL attach to every component either an
  artifact digest resolvable through the signed closure object, or its
  digest gap (Context: the closure references no per-package document for
  it, `built-locally` or `non-redistributable`) — never neither and never
  both.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_digest_or_gap_total
  property: for all components k: has_sha256(k) xor has_digest_gap(k),
    and has_sha256(k) implies resolves(sha256(k), closure(pin))

- **SBOM-005** THE SYSTEM SHALL include every package present in the
  environment as a component, with launcher-injected packages carrying
  `minimal:added-by=launcher`.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_launcher_packages_present
  property: for all environments e: components(emit(e)) superset packages(e),
    and for all k in launcher_injected(e): added_by(component(k)) == launcher

- **SBOM-006** WHEN a document is emitted as a CycloneDX 2.0 Blueprint THE
  SYSTEM SHALL validate against the vendored draft schema and SHALL emit
  axes the Box Spec cannot declare as schema-TODO properties, never as
  fabricated values.
  tier:     T1
  verify:   cargo nextest run -p sbom blueprint_schema_conformance
  property: for all compositions c: bp_schema_valid(emit_bp(c)),
    fabricated_axes(emit_bp(c)) is empty, and undeclarable_axes(c) subset
    schema_todo_properties(emit_bp(c))
  - THE SYSTEM SHALL label every posture axis it emits `enforced`,
    `declared` or `in-flight` (Context), from a table the model crate
    carries per Box Spec section, so a Blueprint never presents a boundary
    nothing enforces as one that does.
    tier:   T1
    verify: cargo nextest run -p sbom blueprint_axes_carry_enforcement_label
    property: for all axes x in emit_bp(c): label(x) == enforcement(section(x))
  - THE SYSTEM SHALL emit the Blueprint from the box's stored expanded spec
    (BOX-068) and SHALL carry the spec's posture-projection digest (BOX-071)
    as a document property, so a Blueprint binds to the posture Gatehouse
    admitted the box under.
    tier:   T1
    verify: cargo nextest run -p sbom blueprint_carries_posture_digest
    property: posture_digest(emit_bp(c)) == projection_digest(expanded_spec(c))

- **SBOM-007** WHEN a box SBOM is emitted under a pin whose commit
  carries a sealed attribution manifest THE SYSTEM SHALL emit component
  licenses equal to the manifest's license entries for that pin.
  tier:     T0
  verify: cargo nextest run -p sbom sbom_licenses_match_attribution

- **SBOM-008** THE SYSTEM SHALL record environment-variable assets by name
  and provenance only, SHALL record every other credential-bearing posture
  field by reference — `[secrets]` as name and `source` kind, never the
  value; `[[github_imports]]`, `[[file_imports]]`, egress destinations and
  the `[otel]` endpoint as their location with any userinfo, token-bearing
  query parameter or header value removed — and SHALL never embed a
  variable value, a secret value, or a credential carried by one of those
  fields in any document.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_credentials_never_embedded_in_any_serializer
  property: for all compositions c, serializers s in {cdx, spdx, blueprint}:
    every environment asset in parse_s(emit_s(c)) carries only name and
    provenance fields, every secret carries only name and source kind, every
    location field carries no userinfo and no token-bearing parameter, for
    all credentials v in credentials(c): v not in ir(c), and no string
    anywhere in parse_s(emit_s(c)) equals or contains v

- **SBOM-009** WHEN a component has a per-package document (SBOM-013)
  resolvable through the box's pin THE SYSTEM SHALL take the component's
  build-time facts — its build closure's components and their digests, and
  the build environment — from that document, and its metadata — name,
  version, `purl`, and licenses where the pin carries no attribution
  manifest — from the graph at the pin (minimal#700 D9; under a sealed
  attribution manifest SBOM-007 is the one source of licenses);
  and SHALL reference the document from the component by the tarball's
  sha256 and the statement digest SBOM-013 defines, never embed it whole.
  tier:     T0
  verify:   cargo nextest run -p sbom sbom_component_detail_from_document_and_graph

- **SBOM-010** THE SYSTEM SHALL derive composition-level facts — launcher
  injection, posture axes, and environment assets — from the environment's
  own declaration, never from a component document, which cannot carry
  them.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_envelope_facts_are_environment_derived
  property: for all environments e: envelope(emit(e)) == declared_facts(e)

- **SBOM-011** IF a component has no per-package document referenced by
  the pinned closure — a declared gap: `built-locally` or
  `non-redistributable` — THEN THE SYSTEM SHALL emit that component
  carrying that digest gap, never omitting it. (A document the closure
  *does* reference but that cannot be fetched is not a gap; it is
  SBOM-012's failure.)
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_unreferenced_component_carries_its_gap
  property: for all environments e, k in packages(e): unreferenced(k,
    closure(pin(e))) implies k in components(emit(e)) and has_digest_gap(k)

- **SBOM-012** IF the pinned index or a referenced per-package document
  cannot be fetched THEN THE SYSTEM SHALL fail naming the pin, the
  unresolved object, and the remediation, never emitting a document whose
  component set is silently incomplete.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_unfetchable_reference_fails_loudly
  property: for all attempts a: unfetchable_reference(a) implies not
    emitted(a) and error(a) names (pin, unresolved object, remediation)

- **SBOM-013** WHEN the system resolves a component's per-package document
  THE SYSTEM SHALL read `<spec_hash>.sbom.intoto.jsonl` beside the package's
  artifact in the Registry Build Cache: a DSSE envelope over an in-toto v1
  Statement whose single `subject` is the package tarball (`<sha256>.zst`,
  the digest the signed closure maps the Build Spec Hash to), whose
  `predicateType` is `https://cyclonedx.org/bom`, and whose predicate is the
  package's CycloneDX 1.5 document covering the transitive build closure by
  built-artifact digest (the architecture's Package SBOM: the software built
  *and* the build environment). The **document digest** is the sha256 of the
  statement bytes. Its Sigstore bundle, when published, is
  `<spec_hash>.sbom.sigstore.json`, a DSSE over byte-identical statement
  bytes, and its state in the sealed map follows the provenance bundle's
  (spec PKV, minimal#1586, PKV-017). Producing both is build infrastructure's
  (Non-goals); the names and the statement shape are this spec's contract,
  and PKV-011 verifies the bundle under them.
  tier:     T1
  verify:   cargo nextest run -p sbom per_package_document_names_and_statement_shape
  property: for all resolved documents d of component k: subject(d) ==
    {name: tarball(k), sha256: closure(pin)[spec_hash(k)]}, predicateType(d)
    == cyclonedx_bom, and statement_bytes(envelope(d)) ==
    statement_bytes(bundle(d)) where the bundle exists
  - IF the statement's subject digest differs from the closure's entry for
    the component THEN THE SYSTEM SHALL treat the document as unresolved
    (SBOM-012's failure, naming both digests), never as that component's.
    tier:   T0
    verify: cargo nextest run -p sbom per_package_document_subject_must_match_closure
  - WHEN the document's bundle is published THE SYSTEM SHALL verify it with
    PKV-011's checks first, then check the subject, and only then read any
    other field of the document, and IF the bundle fails THEN THE SYSTEM
    SHALL treat the document as unresolved (SBOM-012's failure, naming the
    check); WHILE the producer publishes no bundle for the document THE
    SYSTEM SHALL read the document and mark the component `unverified`, as
    PKV marks an entry whose source has no verified bundle.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_bundle_verified_before_read
    property: read(d) ⇒ (bundle(d) = ∅ ∧ unverified(component(d))) ∨ verified(bundle(d)); checks(d) = [bundle, subject, rest] in that order
  - THE SYSTEM SHALL emit the `unverified` mark on the component in every
    serializer — CycloneDX: a `minimal:verification` property with the value
    `unverified`; SPDX: an annotation of the same text on the package;
    Blueprint: `verification = "unverified"` on the component — so a reader
    tells data read without a verified bundle from data read with one, and
    never from the document's silence.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_unverified_mark_emitted_by_every_serializer
    property: for all serializers s, components k: unverified(k) ⇔ marked_unverified(parse_s(emit_s(c)), k)
  - WHERE `--require-bundles` is given THE SYSTEM SHALL treat a document
    with no published bundle as unresolved (SBOM-012's failure, naming the
    missing bundle) instead of reading it. Read-and-mark stays the default
    while no producer publishes bundles (build-servers#185); whether the
    default flips once they do is an open question below.
    tier:   T0
    verify: cargo nextest run -p sbom sbom_require_bundles_fails_on_an_absent_bundle

- **SBOM-014** WHEN `min box list --using <pkg>[@<ver>]` filters boxes THE
  SYSTEM SHALL answer from the component set this spec's composition emits
  for each box (SBOM-005), so the list and the box's SBOM never disagree.
  tier:     T0
  verify:   cargo nextest run -p minimal box_list_using_answers_from_the_sbom_components

## Non-goals

- Live-box/observed mode: minimal#700 slice 6 (declared-spec only here)
- Full SPDX profile depth: minimal#700 D10 (minimal-valid only here)
- Usage/link-tier axis: model field reserved, minimal#700 refs
- Converging legacy `mfile::Task` onto box primitives: BOX-046 on main reads
  `[tasks.<name>]` as a box entry, which is that destination
- Network-zone enforcement: the Box Spec and networking requirements (zones are declared
  and caveated here)
- Signing composed box documents: they are derivations over signed
  per-package inputs and carry those bundles by reference — signing policy
  lives with the attestation cutover, gominimal/build-servers#86
- Producing the per-package document and its bundle at publish:
  gominimal/build-servers#185 (#333 asks for the same object); this spec
  names them (SBOM-013) so the producer and this reader agree.
- Pinning the document digest in the signed closure, which is what makes a
  per-package document *sealed* under a pin rather than bound through its
  subject: build-servers#185, step one. Until it lands the chain runs bundle
  identity, then the tarball digest, then the closure.
- Enforcing the declared-only posture axes (file imports and exports, GitHub
  imports, `[otel]`, the VPN mesh): their owners (inbox#678, NET, MRF); the
  Blueprint labels them `declared` until then.

## Design reasoning

The build/workflow story minimal emits is CycloneDX **formulation**
(schema-stable since 1.5); "Blueprint" — the 2.0 draft threat-modeling
schema — carries the posture story. The naming distinction is deliberate to
avoid a semantic clash in a public CLI. Declared-spec-first because minimal
persists no execution ledger today: the declared model is cheap and honest;
observed capture is a real subsystem deferred to its own slice. One lean
model crate serves both the CLI and build-infra per-package emission — the
second consumer is why the model takes no CLI or daemon dependencies. A
content-derived catalog pin replaces random serials and wall-clock so
documents chain to a Sigstore-verifiable object and regeneration is
reproducible. Decisions and alternatives live in minimal#700 (D1-D11). The `verify:`
pointers name the model crate `sbom`; the name follows the crate when the
emitter question below settles.

Where the command lives is the architecture's to say, not this spec's. The
command tree reserves `sbom` under `pkg` (a package's own document, the
input this spec composes over) and `container`; the `box` noun has no such
verb, and the CycloneDX Blueprint is the same "declared posture" that `min
box spec <entry>` renders as TOML, JSON or YAML. gominimal/arch#66 asks for
the ruling, and this spec names no command until it lands. The evidence now
favours a payload command, `min box sbom <box>`, with the Blueprint a mode
of it: design principle 4 makes `pkg sbom` a payload command that writes
only the payload to stdout and takes no `-o`; BCLI-021 fixes `box spec`'s
formats as `toml|json|yaml` and BCLI-033 requires every machine-output
object to carry a `min/v1/<type>` schema and, for `spec`, the per-value
layer BOX-161 reports, which a CycloneDX document cannot carry. One meaning
per verb (principle 2) then keeps `spec` as Minimal's own rendering and
`sbom` as the outside-schema document, as `pkg sbom` and `container sbom`
are. The requirements bind either answer.

SBOM-009 through SBOM-014 answer review questions raised in the spec's
review (minimal#1304) rather than an acceptance criterion: the epic predates
the choice between eager whole-box emission and composition, and its
criteria do not reach it.
Composition by reference rather than eager whole-environment emission: the
per-package document is the unit publish already has the inputs for, one
document serves every environment containing that package, and a composed
document inherits corrected component data — a revised patch ledger, a new
advisory disposition — without regenerating anything. The cost is that
resolution can miss, which is why SBOM-011 and SBOM-012 are requirements
rather than error handling: a document that silently drops a component is
worse than one that refuses to emit. Non-redistributable packages and
locally-built ones are permanently outside the cache by design, so the gap
arm is the ordinary path, not a failure mode.

One CycloneDX emitter exists in the org with consumers around it.
`minimal-supply-chain`'s `sbom.rs` emits CycloneDX 1.5 from recipe metadata,
with a random serial and a wall-clock timestamp, and carries a `build_scan`
that hashes built output which no producer uses yet; `pkgmgr-rs`'s `pkgmgr
sbom` is a caller of it, not a second emitter; the Go `minimal-sbom` is
retired (its migration guide lives in minimal-supply-chain); and the
webapp's SBOM tab generates its own unsigned document from source-tarball
digests. The model crate here subsumes `minimal-supply-chain::sbom` by the
facade minimal#433 laid out (the code moves, a re-export keeps `pkgmgr-rs`
compiling, the API is refined after), so one implementation serves `min`,
publish and the webapp, which becomes a consumer that falls back to its own
generator only until signed per-package documents exist
(build-servers#333). The random serial and timestamp go in the move:
SBOM-001 forbids them.

**Generality:** a second document format fits behind the serializer seam
(SPDX proves it in the first slice); a second consumer (build infra) is a
design input, not an afterthought. What does not generalize: posture
vocabulary is bound to the Box Spec — a second box model would need its own
axis mapping, which is acceptable because the vocabulary follows the spec
that defines the box.

Emitted vocabulary is the Box Spec's, verbatim, as architecture.md's
`box.toml` and the BOX spec define it (Context lists the tables): `[network]
mode = none | host_ip | own_ip` (BOX-079; the legacy spellings are accepted
for one release and never emitted), egress in its nested `[network.egress]`
form (BOX-157), `[secrets]` as references with their `source`, `[env_vars]`
with the `inherit` flag as provenance, and so on. The meaning of the network
modes is the networking spec (NET, `docs/specs/18-spec-box-networking`).
Earlier drafts followed the pre-architecture Sandbox Spec (whose
`network.type = none | host_ip | no_ip` already diverged), which is what D11
in minimal#700 was guarding against; with the architecture binding, a Box
Spec rename is an arch change and rolls this spec's golden fixtures in the
same PR rather than surprising them. The enforcement label (SBOM-006) is
what keeps the Blueprint honest while much of the posture is declared and
not yet enforced: a reader sees `[[file_imports]]` as a declared boundary,
not an enforced one, until its owner lands.

In Blueprint terms the box, the host, the client, the project subtree, each
named volume, the upstream registry and the egress proxy are zones, with the
box's trust boundary set by `[network] mode`; packages, secret references,
environment variables, imported and exported files, volumes and loadout
patches are assets; egress and ingress lists, credentialed flows through the
egress proxy, file and volume transfers and the `[otel]` exporter are flows;
the entrypoint, lifecycle hooks, `lifetime`, `restart`, `timeout`,
`pty_enabled`, `exec_enabled`, `dynamic_ingress` and `dynamic_providers` are
behaviors. Runtime outcomes (dynamic ingress decisions, public exposure),
host-asserted facts (the egress pin, whether `[machine]` limits are enforced)
and client-side consent rules (the three `*-file-rules` and
`[secret-store-rules]` tables, which never enter the spec) are undeclarable
from the spec and stay schema-TODO.

## Security considerations

- **Invariant:** THE SYSTEM SHALL include every package present in the
  environment in its SBOM.
  enforced by: closure-walk emission with launcher-injection tagging, never
  filtering
  covered by: SBOM-005
- **Invariant:** THE SYSTEM SHALL emit no fabricated posture values, and no
  posture axis as enforced that is not.
  enforced by: schema-TODO properties for undeclarable axes; the enforcement
  label per axis
  covered by: SBOM-006
- **Invariant:** THE SYSTEM SHALL embed no environment-variable values in
  any document.
  enforced by: name+provenance asset model; values never enter the IR
  covered by: SBOM-008
- **Invariant:** THE SYSTEM SHALL represent every unverifiable digest as an
  explicit gap rather than an omission or a guess.
  enforced by: the digest-or-gap total mapping over the signed closure
  covered by: SBOM-004
- **Invariant:** THE SYSTEM SHALL never emit a document whose component set
  is incomplete without saying so.
  enforced by: components with no referenced document become declared
  gaps; unfetchable references abort the emission
  covered by: SBOM-011, SBOM-012
- **Invariant:** THE SYSTEM SHALL never attribute a per-package document to
  a component whose closure digest it does not name as its subject.
  enforced by: the bundle check, then the subject check, before any other
  field of the document is read (SBOM-013)
  covered by: SBOM-013

## Open questions

- [NEEDS CLARIFICATION (HIGH): the command home and the Blueprint's place.
  The architecture reserves `sbom` under `pkg` and `container` only; a box
  document needs a verb under `box`. Proposed, with the evidence in Design
  reasoning: `min box sbom <box>`, a payload command like `pkg sbom`, with
  the Blueprint a mode of it (`--blueprint`) rather than an output format of
  `min box spec`, whose `-o` formats and `min/v1/spec` schema a CycloneDX
  document cannot satisfy. Ruling requested as gominimal/arch#66; the spec
  names no command until it lands. The earlier worry that "blueprint"
  already means the Box Spec in the architecture's vocabulary no longer
  holds: the current text uses the word once, for the document itself.]
- [NEEDS CLARIFICATION (HIGH): is a composed environment document signed in
  its own right, or a verifiable derivation over signed per-package inputs
  it references? Recommendation on record: a derivation — it needs no
  per-environment signing infrastructure and stays valid as inputs are
  re-signed. Decide with the attestation cutover, build-servers#86.]
- [NEEDS CLARIFICATION (MEDIUM): the sealed map's state name for a published
  SBOM bundle and the closure's `sbom_digest` field, which build-servers#185
  step one adds. SBOM-013 binds the object names and the statement shape
  now; the state name follows the provenance bundle's (`bundled`) unless the
  producer rules otherwise. Settle on build-servers#185 before the first
  slice's golden fixtures.]
- [NEEDS CLARIFICATION (MEDIUM): once build-servers#185 publishes a bundle
  for every package, does reading an unbundled per-package document fail by
  default (today's `--require-bundles` behaviour), with the read-and-mark
  path behind an opt-in? Proposed: yes, in the first release after every
  pinned closure the public registry serves carries bundles; until then a
  fail-closed default would make every SBOM fail. Settle on build-servers#185.]
- [NEEDS CLARIFICATION (LOW): SPDX `created` timestamp source (proposal:
  pinned commit's committer timestamp); both answers satisfy SBOM-001;
  settle in first-slice review.]
