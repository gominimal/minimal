---
id: SBOM
title: session/task SBOM + CycloneDX Blueprint
status: draft
owner: bryan-minimal
epic: gominimal/inbox#582
arch: none
updated: 2026-09-03
---

# SBOM — session/task SBOM + CycloneDX Blueprint

## Context

Minimal owns the complete declared story of a session or task — composition,
closure, pins — but cannot export it in the formats the world consumes.
Security scanners want an SBOM; compliance wants documents whose digests are
evidence rather than assertion; build infrastructure wants per-package SBOMs
at publish chained to the signed per-commit closure; developers granting
agent sessions want the posture story reviewable before granting it.

**Success:** a session or task+loadout yields schema-valid supply-chain
documents whose component digests chain to the signed catalog closure, and
whose regeneration is byte-identical.

A document for an environment is a **composition**, not a re-derivation:
the per-package document sealed at publish is the unit, and an environment's
document is an envelope of composition-level facts over references to those
units, resolved through the environment's pin. Packages the cache does not
carry — built locally, or non-redistributable by policy — are the ordinary
case, not the exception, and appear as declared gaps.

**First slice:** publish emits a per-package document for one catalog
package, sealed beside its artifact; a fixture composition then emits
validated CycloneDX 1.5 and minimal-valid SPDX 2.3 over it, byte-stable
across regenerations.

## Users and stories

**Roles:** security engineer; compliance reviewer / downstream consumer;
developer running agent sessions; build-infra operator; auditor.

- AS A security engineer I WANT a CycloneDX SBOM of any task or session SO
  THAT existing scanners and policy tooling can evaluate what Minimal
  environments contain
- AS A compliance reviewer I WANT component digests that verifiably chain to
  the signed per-commit catalog closure SO THAT the document is evidence,
  not assertion
- AS A developer running agent sessions I WANT a Blueprint of a session's
  declared posture SO THAT I can review what an agent environment may do
  before granting it
- AS A build-infra operator I WANT the same model emitted per-package at
  publish time SO THAT catalog artifacts ship supply-chain documents without
  a second implementation, and every environment document composes from them
  rather than re-deriving component detail
- AS AN auditor I WANT deterministic regeneration SO THAT two parties can
  independently produce and compare the same document

## Requirements

- **SBOM-001** WHEN the same catalog pin and identical declared inputs are
  emitted twice THE SYSTEM SHALL produce byte-identical documents, deriving
  serials, namespaces, and timestamps from content and pin, never from wall
  clock or randomness.
  tier:     T1
  verify:   just test-one sbom_regeneration_deterministic
  property: for all pin, inputs: emit(pin, inputs) == emit(pin, inputs)
  - IF the cache's contents differ between two emissions under the same pin
    THEN THE SYSTEM SHALL still produce byte-identical documents, the
    composition being a function of the pin and its closure rather than of
    what the cache happens to hold.
    tier:   T0
    verify: just test-one sbom_determinism_independent_of_cache_state

- **SBOM-002** WHEN a document is emitted as CycloneDX THE SYSTEM SHALL
  produce output that validates against the vendored CycloneDX 1.5 schema.
  tier:     T1
  verify:   just test-one sbom_cdx_schema_conformance
  property: for all compositions c: cdx_schema_valid(emit_cdx(c))

- **SBOM-003** WHEN a document is emitted as SPDX THE SYSTEM SHALL produce
  minimal-valid SPDX 2.3.
  tier:     T1
  verify:   just test-one sbom_spdx_validity
  property: for all compositions c: spdx_valid(emit_spdx(c))

- **SBOM-004** THE SYSTEM SHALL attach to every component either an
  artifact digest resolvable through the signed closure object, or an
  explicit digest gap of `built-locally` or `non-redistributable` — never
  neither and never both.
  tier:     T1
  verify:   just test-one sbom_digest_or_gap_total
  property: for all components k: has_sha256(k) xor has_digest_gap(k)

- **SBOM-005** THE SYSTEM SHALL include every package present in the
  environment as a component, with launcher-injected packages carrying
  `minimal:added-by=launcher`.
  tier:     T1
  verify:   just test-one sbom_launcher_packages_present
  property: for all environments e: components(emit(e)) superset packages(e)

- **SBOM-006** WHEN a document is emitted as a CycloneDX 2.0 Blueprint THE
  SYSTEM SHALL validate against the vendored draft schema and SHALL emit
  axes the session model cannot declare as schema-TODO properties, never as
  fabricated values.
  tier:     T1
  verify:   just test-one blueprint_schema_conformance
  property: for all compositions c: bp_schema_valid(emit_bp(c)) and
    fabricated_axes(emit_bp(c)) is empty

- **SBOM-007** WHEN a session SBOM is emitted under a pin whose commit
  carries a sealed attribution manifest THE SYSTEM SHALL emit component
  licenses equal to the manifest's license entries for that pin.
  tier:     T0
  verify: just test-one sbom_licenses_match_attribution

- **SBOM-008** THE SYSTEM SHALL record environment-variable assets by name
  and provenance only, and SHALL never embed variable values in any
  document.
  tier:     T1
  verify:   just test-one blueprint_env_values_never_embedded
  property: for all compositions c, vars v: values(v) intersect
    bytes(emit(c)) is empty

- **SBOM-009** WHEN emitting a document for an environment whose components
  are published under its pin THE SYSTEM SHALL compose component detail by
  reference to the per-package documents resolved through that pin's
  closure, rather than re-deriving it from recipe metadata.
  tier:     T0
  verify:   just test-one sbom_composes_from_per_package_documents

- **SBOM-010** THE SYSTEM SHALL derive composition-level facts — launcher
  injection, posture axes, and environment assets — from the environment's
  own declaration, never from a component document, which cannot carry
  them.
  tier:     T1
  verify:   just test-one sbom_envelope_facts_are_environment_derived
  property: for all environments e: envelope(emit(e)) == declared_facts(e)

- **SBOM-011** IF a component has no per-package document resolvable
  through the pinned closure THEN THE SYSTEM SHALL emit that component
  carrying its declared digest gap, never omitting it.
  tier:     T1
  verify:   just test-one sbom_unresolvable_component_becomes_a_gap
  property: for all environments e: components(emit(e)) superset packages(e)

- **SBOM-012** IF the pinned index or a referenced per-package document
  cannot be fetched THEN THE SYSTEM SHALL fail naming the pin, the
  unresolved object, and the remediation, never emitting a document whose
  component set is silently incomplete.
  tier:     T0
  verify:   just test-one sbom_unfetchable_reference_fails_loudly

## Non-goals

- Live-session/observed mode: minimal#700 slice 6 (declared-spec only here)
- Full SPDX profile depth: minimal#700 D10 (minimal-valid only here)
- Usage/link-tier axis: model field reserved, minimal#700 refs
- Converging legacy `mfile::Task` onto sessions primitives: minimal#700 D6
- Network-zone enforcement: the sessions/sandbox spec (zones are declared
  and caveated here)
- Signing composed environment documents: they are derivations over signed
  per-package inputs and carry those bundles by reference — signing policy
  lives with the attestation cutover, gominimal/build-servers#86

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
reproducible. Decisions and alternatives live in minimal#700 (D1-D11).

**Generality:** a second document format fits behind the serializer seam
(SPDX proves it in the first slice); a second consumer (build infra) is a
design input, not an afterthought. What does not generalize: posture
vocabulary is bound to the Sandbox Spec — a second sandbox model would need
its own axis mapping, which is acceptable because the vocabulary follows
the spec that defines the sandbox.

## Security considerations

- **Invariant:** THE SYSTEM SHALL include every package present in the
  environment in its SBOM.
  enforced by: closure-walk emission with launcher-injection tagging, never
  filtering
  covered by: SBOM-005
- **Invariant:** THE SYSTEM SHALL emit no fabricated posture values.
  enforced by: schema-TODO properties for undeclarable axes
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
  enforced by: unresolvable components become declared gaps; unfetchable
  references abort the emission
  covered by: SBOM-011, SBOM-012

## Open questions

- [NEEDS CLARIFICATION (CRITICAL): D4 — `--format cdx-blueprint` naming vs
  "blueprint" already meaning minimal.toml in user docs; renames the CLI
  surface. Recommendation on record in minimal#700; decide before the
  format flag ships.]
- [NEEDS CLARIFICATION (CRITICAL): D11 — Sandbox-Spec vocabulary conflicts;
  answers change every emitted document's vocabulary; settle before golden
  fixtures land.]
- [NEEDS CLARIFICATION (HIGH): is a composed environment document signed in
  its own right, or a verifiable derivation over signed per-package inputs
  it references? Recommendation on record: a derivation — it needs no
  per-environment signing infrastructure and stays valid as inputs are
  re-signed. Decide with the attestation cutover, build-servers#86.]
- [NEEDS CLARIFICATION (HIGH): which existing emitter does the model crate
  subsume — `minimal-supply-chain::sbom`, `pkgmgr-rs`'s `commands::sbom`,
  or `attest-sbom`? Answering it late means a fourth implementation.]
- [NEEDS CLARIFICATION (LOW): SPDX `created` timestamp source (proposal:
  pinned commit's committer timestamp); both answers satisfy SBOM-001;
  settle in first-slice review.]
