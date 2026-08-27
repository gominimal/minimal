---
epic: gominimal/inbox#582
arch: gominimal/arch (CycloneDX Blueprints design synthesis; SBOM/Blueprint implementation plan)
---

# 12-spec-sbom-blueprint: session/task SBOM + CycloneDX Blueprint

## Context

Minimal owns, in-process, the complete declared story of a session or task —
composition, closure, pins — but cannot export it in the formats the world
consumes. Security scanners want an SBOM; compliance wants supply-chain
documents whose digests are evidence rather than assertion; build infra wants
per-package SBOMs at publish chained to the signed per-commit closure
(build-servers#86/#185); developers granting agent sessions want the posture
story (what crosses the sandbox boundary) reviewable before granting it.

Success criteria fold in the epic's outcome: one lean model (`crates/sbom`,
serde-only deps) serving two consumers — the `min sbom` CLI and build-infra
per-package emission — with CycloneDX 1.5 + minimal-valid SPDX 2.3 behind one
serializer seam, and a CycloneDX 2.0 draft Blueprint posture format.

**First slice** (runs end to end): `crates/sbom` + neutral IR + both
serializers + `SerialPolicy::ContentDerived` + `CatalogPin` + golden fixtures
and schema-conformance tests — platform-neutral, no CLI/daemon changes
(minimal#700 PR-1).

## Users and stories

- As a **security engineer**, I want a CycloneDX SBOM of any task or session,
  so that existing scanners and policy tooling can evaluate what Minimal
  environments contain.
- As a **compliance reviewer / downstream consumer**, I want component digests
  that verifiably chain to the signed per-commit catalog closure, so that the
  document is evidence, not assertion.
- As a **developer running agent sessions**, I want a Blueprint of a session's
  declared posture (env inherits, patches, hooks, zones), so that I can review
  what an agent environment may do before granting it.
- As a **build-infra operator**, I want the same model emitted per-package at
  publish time, so that catalog artifacts ship supply-chain documents without
  a second implementation.
- As an **auditor**, I want deterministic regeneration, so that two parties
  can independently produce and compare the same document.

## Requirements

- **SBOM-001** WHEN `min sbom` is invoked twice with the same `CatalogPin`
  and identical declared inputs THE SYSTEM SHALL emit byte-identical
  documents, deriving serials, namespaces, and timestamps from content and
  pin, never from wall clock or randomness.
  - tier: T1
  - verify: just test-one sbom_regeneration_deterministic
  - property: for all pin, inputs: emit(pin, inputs) == emit(pin, inputs)

- **SBOM-002** WHEN a document is emitted with `--format cdx` THE SYSTEM
  SHALL produce output that validates against the vendored CycloneDX 1.5
  schema.
  - tier: T1
  - verify: just test-one sbom_cdx_schema_conformance
  - property: for all compositions c: cdx_schema_valid(emit_cdx(c))

- **SBOM-003** WHEN a document is emitted with `--format spdx` THE SYSTEM
  SHALL produce minimal-valid SPDX 2.3.
  - tier: T1
  - verify: just test-one sbom_spdx_validity
  - property: for all compositions c: spdx_valid(emit_spdx(c))

- **SBOM-004** WHEN emitting any component THE SYSTEM SHALL attach either an
  `artifact_sha256` resolvable through the signed closure object, or an
  explicit `digest_gap` of `built-locally` or `non-redistributable` — never
  neither and never both.
  - tier: T1
  - verify: just test-one sbom_digest_or_gap_total
  - property: for all components k: has_sha256(k) xor has_digest_gap(k)

- **SBOM-005** WHEN the environment contains launcher-injected packages THE
  SYSTEM SHALL include them as components carrying
  `minimal:added-by=launcher` — an SBOM SHALL never omit a package present
  in the environment.
  - tier: T1
  - verify: just test-one sbom_launcher_packages_present
  - property: for all environments e: components(emit(e)) superset packages(e)

- **SBOM-006** WHEN a document is emitted with `--format cdx-blueprint` THE
  SYSTEM SHALL produce output validating against the vendored CycloneDX 2.0
  draft schema, and SHALL emit axes the session model cannot declare as
  schema-TODO properties, never as fabricated values.
  - tier: T1
  - verify: just test-one blueprint_schema_conformance
  - property: for all compositions c: bp_schema_valid(emit_bp(c)) and
    fabricated_axes(emit_bp(c)) == empty

- **SBOM-007** licenses cross-check with the sealed attribution manifest
  - tier: T0
  - verify: just test-one sbom_licenses_match_attribution

  @SBOM-007
  Scenario: session SBOM and attribution manifest agree on licenses
    Given a pinned commit with a sealed attribution manifest
    When a session SBOM is emitted under the same CatalogPin
    Then each component's licenses equal the manifest's license_spdx entries

- **SBOM-008** WHEN emitting environment-variable assets THE SYSTEM SHALL
  record variable names and provenance (inherited vs specified) and SHALL
  never embed variable values.
  - tier: T1
  - verify: just test-one blueprint_env_values_never_embedded
  - property: for all compositions c, vars v: values(v) intersect
    bytes(emit(c)) == empty

## Non-goals

Live-session/observed mode (declared-spec only; observed capture is its own
subsystem — minimal#700 slice 6, gated on D2). Full SPDX profile depth.
Usage/link-tier axis (model field reserved). Converging legacy `mfile::Task`
onto sessions primitives (D6). Network-zone enforcement (declared and
caveated in v1).

## Design reasoning

The artifact minimal emits for build/workflow story is CycloneDX
**formulation** (schema-stable since 1.5), while "Blueprint" — the 2.0 draft
threat-modeling schema — carries the posture story; the naming distinction is
deliberate to avoid a semantic clash in a public CLI (see the arch design
synthesis). Declared-spec-first because minimal persists no execution ledger
today: the declared model is cheap and honest, observed capture is a real
subsystem. One lean crate serves both the CLI and build-infra emission —
the second consumer is why `crates/sbom` takes no clap/daemon/rcache deps.
`CatalogPin = {repo, commit, closure_object}` replaces uuid-v4 + wall-clock
serials so documents chain to a Sigstore-verifiable object (minimal#995,
build-servers#86) and regeneration is reproducible. Decisions and
alternatives live in minimal#700 (D1–D11) and gominimal/arch.

## Security considerations

- The honesty invariants are universals and carry the security weight:
  an SBOM SHALL never omit present packages (SBOM-005) and a Blueprint SHALL
  never fabricate posture (SBOM-006) — a flattering document is worse than
  none.
- Environment-variable VALUES never enter any document (SBOM-008): inherited
  secrets stay host-side; documents carry names and provenance only.
- Digest trust chains to the signed per-commit closure; verification is
  consumer-side via the existing Sigstore path (build-servers#86). A document
  without a verifiable pin is an assertion, and `digest_gap` says so
  explicitly rather than pretending.
- Blueprint documents map a session's attack surface by design; they contain
  no secrets by SBOM-008, but distribution defaults should treat them like
  configuration, not like public marketing.

## Open questions

- **CRITICAL:** D4 — `--format cdx-blueprint` naming vs "blueprint" already
  meaning minimal.toml in user-facing docs. At least one plausible answer
  renames the CLI surface (observable behaviour). Recommendation on record
  (keep crate name, user-facing flag `cdx-blueprint`); needs the decision
  before the format flag ships (minimal#700, decide-before-slice-4).
- **CRITICAL:** D11 — Sandbox-Spec vocabulary conflicts (`network.type`,
  `file_imports/exports`, `machine.*`). Plausible answers change every
  emitted document's vocabulary; must settle before golden fixtures land or
  renames churn every checked-in BOM.
- SPDX `created` timestamp source (proposal: pinned commit's committer
  timestamp). Both candidate answers satisfy SBOM-001's content-derived
  rule; bytes differ but no requirement changes — non-critical, settle in
  PR-1 review.

## Rollout

N/A. (CLI + library work; no infrastructure deployment.)
