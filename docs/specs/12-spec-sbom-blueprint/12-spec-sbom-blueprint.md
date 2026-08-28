---
id: SBOM
title: session/task SBOM + CycloneDX Blueprint
status: draft
owner: bryan-minimal
epic: gominimal/inbox#582
arch: none
updated: 2026-08-27
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

**First slice:** a fixture composition emits validated CycloneDX 1.5 and
minimal-valid SPDX 2.3 documents, byte-stable across regenerations.

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
  a second implementation
- AS AN auditor I WANT deterministic regeneration SO THAT two parties can
  independently produce and compare the same document

## Requirements

- **SBOM-001** WHEN the same catalog pin and identical declared inputs are
  emitted twice THE SYSTEM SHALL produce byte-identical documents, deriving
  serials, namespaces, and timestamps from content and pin, never from wall
  clock or randomness.
  verify:   just test-one sbom_regeneration_deterministic
  property: for all pin, inputs: emit(pin, inputs) == emit(pin, inputs)

- **SBOM-002** WHEN a document is emitted as CycloneDX THE SYSTEM SHALL
  produce output that validates against the vendored CycloneDX 1.5 schema.
  verify:   just test-one sbom_cdx_schema_conformance
  property: for all compositions c: cdx_schema_valid(emit_cdx(c))

- **SBOM-003** WHEN a document is emitted as SPDX THE SYSTEM SHALL produce
  minimal-valid SPDX 2.3.
  verify:   just test-one sbom_spdx_validity
  property: for all compositions c: spdx_valid(emit_spdx(c))

- **SBOM-004** THE SYSTEM SHALL attach to every component either an
  artifact digest resolvable through the signed closure object, or an
  explicit digest gap of `built-locally` or `non-redistributable` — never
  neither and never both.
  verify:   just test-one sbom_digest_or_gap_total
  property: for all components k: has_sha256(k) xor has_digest_gap(k)

- **SBOM-005** THE SYSTEM SHALL include every package present in the
  environment as a component, with launcher-injected packages carrying
  `minimal:added-by=launcher`.
  verify:   just test-one sbom_launcher_packages_present
  property: for all environments e: components(emit(e)) superset packages(e)

- **SBOM-006** WHEN a document is emitted as a CycloneDX 2.0 Blueprint THE
  SYSTEM SHALL validate against the vendored draft schema and SHALL emit
  axes the session model cannot declare as schema-TODO properties, never as
  fabricated values.
  verify:   just test-one blueprint_schema_conformance
  property: for all compositions c: bp_schema_valid(emit_bp(c)) and
    fabricated_axes(emit_bp(c)) is empty

- **SBOM-007** WHEN a session SBOM is emitted under a pin whose commit
  carries a sealed attribution manifest THE SYSTEM SHALL emit component
  licenses equal to the manifest's license entries for that pin.
  verify: just test-one sbom_licenses_match_attribution

- **SBOM-008** THE SYSTEM SHALL record environment-variable assets by name
  and provenance only, and SHALL never embed variable values in any
  document.
  verify:   just test-one blueprint_env_values_never_embedded
  property: for all compositions c, vars v: values(v) intersect
    bytes(emit(c)) is empty

## Non-goals

- Live-session/observed mode: minimal#700 slice 6 (declared-spec only here)
- Full SPDX profile depth: minimal#700 D10 (minimal-valid only here)
- Usage/link-tier axis: model field reserved, minimal#700 refs
- Converging legacy `mfile::Task` onto sessions primitives: minimal#700 D6
- Network-zone enforcement: the sessions/sandbox spec (zones are declared
  and caveated here)

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
reproducible. Decisions and alternatives live in minimal#700 (D1–D11).

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

## Open questions

- [NEEDS CLARIFICATION (CRITICAL): D4 — `--format cdx-blueprint` naming vs
  "blueprint" already meaning minimal.toml in user docs; renames the CLI
  surface. Recommendation on record in minimal#700; decide before the
  format flag ships.]
- [NEEDS CLARIFICATION (CRITICAL): D11 — Sandbox-Spec vocabulary conflicts;
  answers change every emitted document's vocabulary; settle before golden
  fixtures land.]
- [NEEDS CLARIFICATION (LOW): SPDX `created` timestamp source (proposal:
  pinned commit's committer timestamp); both answers satisfy SBOM-001;
  settle in first-slice review.]
