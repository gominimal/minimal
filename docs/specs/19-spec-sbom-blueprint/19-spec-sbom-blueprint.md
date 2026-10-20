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
box's pin. A component has a **digest gap** when its closure entry's state
is `built-locally` or `non-redistributable` (the ordinary case for a
package built locally or non-redistributable by policy), or when the box's
stored expanded spec records a non-upstream registry for it, `outside-pin`,
which the gap names; the gap names which of the three. A component with an
`artifact` entry has a digest, whether or not a per-package document
exists for it (SBOM-013 decides what its facts are). SBOM-004 and SBOM-011
use that one definition. A document the closure references but that cannot be
fetched is not a gap; it is SBOM-012's failure. Until build-servers#185 pins
the document digest in the closure (Non-goals), *references* is decided by
the closure entry alone: a component whose entry maps its Build Spec Hash to
a cache artifact digest references the document SBOM-013 names from that
hash, and a component whose entry is `built-locally` or `non-redistributable`
has no artifact, no document, and the gap; a package is `outside-pin` only
when the box's stored expanded spec (BOX-068) records a registry for it
other than `[upstream]`, and the gap names that registry reduced under
SBOM-008 (scheme, host and port). The design's Box Spec records one
upstream registry and no registry for any loadout package (architecture
lines 83 and 1074–1077), so today no package has a recorded registry and
`outside-pin` cannot occur. A name resolves against the one upstream
(architecture line 1731), so an `open` box's loadout package from another
registry takes the upstream rule: with an `artifact` entry of that name in
the closure it has that digest, and with no entry it is SBOM-004's exit 6
below. Whether the design
records that registry is asked in gominimal/arch#138 (Open questions);
the kind is defined here so that a yes needs no change to this spec.
Precedence, for when it exists: the closure entry decides first, and a
recorded registry decides only for a package the closure holds no entry
for; a package with an `artifact` entry has a digest whatever registry is
recorded, and one with a `built-locally` or `non-redistributable` entry has
that gap. Those are the only kinds a package can be. An upstream package
with no closure entry, or an entry of any other state, is neither a
digest nor a gap: the pin does not account for the package, and the
emission is SBOM-012's failure, exit code 6, naming the package (AT2). No probe of the cache takes part
in that decision, so SBOM-001's determinism holds. A referenced document is
**absent** when the cache answers an authoritative not-found for its name;
every other failure to fetch it is **unfetchable** and is SBOM-012's
failure under every pin, in three classes with the architecture's exit
codes: **unreachable**, a host that cannot be reached (a timeout, a
refused connection, no route), exits 7; **refused**, a request the cache
refuses for authentication or authorization, exits 5, naming the pin, the
object and the host; and **malformed**, every other fetch failure (a
malformed answer, a truncated object), exits 6 as a failed check. Absence
is SBOM-012's failure,
exit 6, while the pin records a bundle for the document; while it records
none, absence is SBOM-013's interim (the component keeps its artifact
digest and is marked `unverified`, reason `no-document`).

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
across regenerations against a fixture cache whose document bytes are
fixed (the slice's guarantee is SBOM-001's unconditional one over that
fixture; in production, while the pin records no bundle, SBOM-001's interim
sub-bullet is the guarantee, and the slice's output carries the `partial`
mark and the `no-bundle` reason). CycloneDX 1.5 is the SBOM format because it is the one
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
  emitted twice, the pin recording a bundle for every per-package document
  it references, THE SYSTEM SHALL produce byte-identical documents, deriving
  serials, namespaces, and timestamps from content and pin, never from wall
  clock or randomness (while the pin records no bundle, the interim
  sub-bullet below bounds how two emissions may differ).
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_regeneration_deterministic
  property: for all pin, inputs, and independent emissions a, b under
    (pin, inputs), while the pin records a bundle for every per-package
    document it references: bytes(a) == bytes(b)
  - WHILE the pin records a bundle for every per-package document it
    references, IF the cache's contents differ between two emissions under
    the same pin, every object the pinned closure references remaining
    fetchable, THEN THE
    SYSTEM SHALL still produce byte-identical documents, the composition
    being a function of the pin and its closure rather than of what the
    cache happens to hold. (An unfetchable referenced object is SBOM-012's
    failure, and fails the same way on every emission.)
    tier:   T0
    verify: cargo nextest run -p sbom sbom_determinism_independent_of_cache_state
  - WHILE the pin records no bundle for a per-package document
    (build-servers#185 not landed) the closure pins the tarball and not the
    document's bytes, so the composition is a function of the pin and of
    the document bytes it read: two emissions under one pin differ only
    where the cache's writer replaced a document under the same subject,
    and THE SYSTEM SHALL record the statement digest of the bytes it read
    on the component (SBOM-009), so such a difference is attributable to
    the document and never silent; WHILE the pin records the bundle, the
    bundle binds the bytes and the property above holds unconditionally.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_replaced_document_changes_only_its_component_and_digest
    property: bytes(a) ≠ bytes(b) ⇒ R ≠ ∅ ∧ diff(a, b) ⊆ ⋃{component(d) : d ∈ R}, where R = {d : ¬pin_records_bundle(d) ∧ read_digest_a(d) ≠ read_digest_b(d)} and a document absent on one emission reads as digest ∅

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
  it, `built-locally` or `non-redistributable`, or the stored expanded spec
  records a non-upstream registry for it, `outside-pin`) — never neither
  and never both.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_digest_or_gap_total
  property: for all components k: has_sha256(k) xor has_digest_gap(k),
    and has_sha256(k) implies resolves(sha256(k), closure(pin)); for all
    packages k with no registry recorded other than the upstream:
    k ∉ closure(pin) ∨ state(entry(closure(pin), k)) ∉ {artifact,
    built-locally, non-redistributable} ⇒ not emitted ∧ exit = 6

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
    (BOX-068) and SHALL carry two digests as document properties: the
    spec's posture-projection digest (BOX-071), which binds the projected
    axes — the Box Type (name, source, root), network, bep, the registry
    pin, loadout mode, pty, lifetime, nesting and secret grants — to the
    posture Gatehouse admitted the box
    under, and the sha256 of the stored expanded spec's canonical bytes,
    which binds every other axis the Blueprint emits (file imports and
    exports, GitHub imports, variables, volumes, `[otel]`, `[machine]`) to
    the spec the box runs under; the Blueprint names which axes each digest
    covers, so neither is read as proving more than it does.
    tier:   T1
    verify: cargo nextest run -p sbom blueprint_carries_posture_and_spec_digests
    property: posture_digest(emit_bp(c)) == projection_digest(expanded_spec(c)) ∧ spec_digest(emit_bp(c)) == sha256(canonical(expanded_spec(c)))

- **SBOM-007** WHEN a box SBOM is emitted under a pin whose commit
  carries a sealed attribution manifest THE SYSTEM SHALL emit component
  licenses equal to the manifest's license entries for that pin.
  tier:     T0
  verify: cargo nextest run -p sbom sbom_licenses_match_attribution

- **SBOM-008** THE SYSTEM SHALL record environment-variable assets by name
  and provenance only, SHALL record every other credential-bearing posture
  field by reference — `[secrets]` as name and `source` kind, never the
  value; `[[github_imports]]`, `[[file_imports]]`, egress destinations and
  the `[otel]` endpoint as a location reduced to scheme, host and port (an
  allowlist of parts: no userinfo, no path, no query, no fragment, no
  header, whatever a parameter is called; a path segment can carry a token,
  `/hooks/<token>`, so the path goes too; a `[[github_imports]]` location
  keeps its `owner/repo` path alone, which is identity, not secret) — SHALL copy from a per-package
  document (SBOM-009) only an allowlist of fields: a build-closure
  component's name, version, `purl` and digests, and a build-environment
  tool's name and version, with every location among them reduced the same
  way and no other field of the document (annotations, command lines,
  environment values, free text of any kind) ever copied, bundled or not
  — and SHALL never embed a variable value, a secret value, or a credential
  carried by one of those fields in any document.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_credentials_never_embedded_in_any_serializer
  property: for all compositions c, serializers s in {cdx, spdx, blueprint}:
    every environment asset in parse_s(emit_s(c)) carries only name and
    provenance fields, every secret carries only name and source kind, every
    location field (the posture's and the imported documents' alike) is of
    the form scheme://host[:port], or scheme://host/owner/repo for a GitHub
    import, fields(imported(d)) ⊆ {name, version, purl, digests, tool name,
    tool version} for every document d, for all credentials v in
    credentials(c) ∪ planted(d) ∪ planted_in_paths(c), where every v is at
    least 16 characters drawn so that no v is a substring of any declared
    input, package name or version of c, and planted_in_paths(c) plants one
    v as a path segment of each location kind: v not in ir(c), and no
    string anywhere in parse_s(emit_s(c)) equals or contains v
  - THE SYSTEM SHALL emit no credential a per-package document carries, in
    any of the fields it copies from it, bundled or not.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_credential_planted_in_a_per_package_document_never_emitted
  - THE SYSTEM SHALL accept a string copied from a per-package document
    (a name, version, `purl`, tool name or tool version) only when it is
    valid UTF-8 of at most 256 bytes with no control character (U+0000 to
    U+001F, U+007F) and no line or paragraph separator, and a location
    only when it is at most 2048 bytes of the same kind, and SHALL treat a
    document carrying any other value as unresolved (SBOM-012's failure,
    exit code 6, naming the field), so no document can put a control
    character, markup or an oversized value into a serializer's output;
    the serializers escape every string they emit regardless.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_document_strings_are_bounded_and_control_free
    property: for all documents d, fields f ∈ copied(d): read(d) ⇒ utf8(f) ∧ len(f) ≤ limit(f) ∧ ∀c ∈ f: ¬control(c) ∧ ¬separator(c); a planted control character, markup string or 257-byte name makes d unresolved

- **SBOM-009** WHEN a component has a per-package document (SBOM-013)
  resolvable through the box's pin THE SYSTEM SHALL take the component's
  build-time facts — its build closure's entries and their digests, and
  the build environment, recorded as that component's nested dependency
  facts and never as components of the box (the box's components are
  SBOM-005's set alone) — from that document, and its metadata — name,
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
  `non-redistributable`, or `outside-pin` where the stored expanded spec
  records a non-upstream registry for it — THEN THE SYSTEM SHALL emit that component
  carrying that digest gap, never omitting it. (A document the closure
  *does* reference but that is unfetchable is not a gap; it is SBOM-012's
  failure, as is its absence while the pin records a bundle for it; absence
  while the pin records none is SBOM-013's interim, not a gap; an upstream
  package with no entry at all is SBOM-004's exit 6, not a gap.)
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_unreferenced_component_carries_its_gap
  property: for all environments e, k in packages(e): unreferenced(k,
    closure(pin(e))) implies k in components(emit(e)) and has_digest_gap(k),
    where unreferenced(k, c) ⇔ entry(c, k) ∈ {built-locally,
    non-redistributable} ∨ (k ∉ c ∧ the stored expanded spec records a
    registry for k that is not the upstream); the design records no such
    registry today (gominimal/arch#138), so the second arm is never true
    and an `open` box's foreign loadout package with no entry is SBOM-004's
    exit 6, as every upstream package with no entry is

- **SBOM-012** IF the pinned index or a referenced per-package document
  cannot be fetched (an error other than the document's absence, which is
  SBOM-013's interim while no bundle is pinned), or a per-package document
  is unresolved under SBOM-013 (its subject digest differs from the
  closure's entry, its bundle fails a check, its bundle is absent while the
  pin records one, or the pin records no bundle for the document under the
  `require_bundles` option, present or absent) THEN THE SYSTEM SHALL fail
  naming the pin, the unresolved object, the check that failed (both
  digests for a subject mismatch, the failed check's name for a bundle),
  and the remediation — exit code 7 when the host could not be reached,
  exit code 5 when the cache refused the request for authentication or
  authorization (naming the host too), exit code 6 for every other failure
  (the architecture's exit-code table) — never emitting a document whose
  component set is silently incomplete.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_unfetchable_reference_fails_loudly
  property: for all attempts a and referenced objects o:
    unreachable(o) ⇒ ¬emitted(a) ∧ exit(a) = 7 ∧ error(a) names (pin, o,
    host, remediation); refused(o) ⇒ ¬emitted(a) ∧ exit(a) = 5 ∧ error(a)
    names (pin, o, host, remediation); (malformed(o) ∨ (absent(o) ∧
    pin_records_bundle(o)) ∨ unresolved(o)) ⇒ ¬emitted(a) ∧ exit(a) = 6 ∧
    error(a) names (pin, o, check(o), remediation), where absent(o) is an
    authoritative not-found, unfetchable(o) = unreachable(o) ∨ refused(o)
    ∨ malformed(o) with unreachable(o) a host that could not be reached (a
    timeout, a refused connection, no route), refused(o) an authentication
    or authorization refusal by the cache, malformed(o) every other fetch
    failure, and unresolved(o) is SBOM-013's set
    (subject mismatch with both digests as check(o), a failed bundle check
    by name, an absent pinned bundle on a reachable host, a document the
    pin records no bundle for under require_bundles, a copied string that
    fails SBOM-008's validation with the field as check(o))

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
    (SBOM-012's failure, exit code 6, naming both digests), never as that
    component's.
    tier:   T0
    verify: cargo nextest run -p sbom per_package_document_subject_must_match_closure
  - WHEN the pin records a bundle for the document (its state in the sealed
    map, PKV-017's) THE SYSTEM SHALL verify the bundle with PKV-011's checks
    first, then check the subject, and only then read any other field of the
    document; IF the bundle fails a check or is absent THEN THE SYSTEM SHALL
    treat the document as unresolved (SBOM-012's failure, exit code 6,
    naming the check or the missing bundle), and never read it; IF the
    bundle's host cannot be reached THEN THE SYSTEM SHALL fail with exit
    code 7 naming the host, as SBOM-012 does for any object; IF the cache
    refuses the bundle request for authentication or authorization THEN THE
    SYSTEM SHALL fail with exit code 5 naming the pin, the bundle and the
    host. The pin decides, so SBOM-001 holds: the same pin always takes the
    same path.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_bundle_verified_before_read
    property: pin_records_bundle(d) ⇒ (read(d) ⇒ verified(bundle(d))) ∧ (unreachable(bundle(d)) ⇒ exit = 7) ∧ (refused(bundle(d)) ⇒ exit = 5) ∧ (¬unreachable(bundle(d)) ∧ ¬refused(bundle(d)) ∧ ¬verified(bundle(d)) ⇒ exit = 6); checks(d) = [bundle, subject, rest] in that order
  - WHILE the pin records no bundle for the document, IF the cache holds no
    document beside the artifact (the producer has published none:
    build-servers#185 not landed, which is every package today) THEN THE
    SYSTEM SHALL emit the component with its artifact digest from the
    closure and no build-time facts, marked `unverified` with the reason
    `no-document`, mark the document `partial`, and print one diagnostic to
    stderr per emission that names each `no-document` component and
    build-servers#185 as the reason, never failing the emission for it; a
    fetch error other than absence stays SBOM-012's failure. WHILE the pin
    records a bundle, absence is SBOM-012's failure.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_absent_in_the_interim_is_marked_not_fatal
    property: ¬pin_records_bundle(d) ∧ absent(d) ⇒ emitted ∧ has_sha256(component(d)) ∧ unverified(component(d), no-document) ∧ stderr names (component(d), "build-servers#185")
  - WHILE the pin records no bundle for the document, IF the cache holds
    the document THEN THE SYSTEM SHALL read it, mark the component
    `unverified` with the reason `no-bundle`, as PKV marks an entry whose
    source has no verified bundle, and print one diagnostic to stderr per
    emission that names each such component and build-servers#185 as the
    reason (the same diagnostic names the `no-document` components), so
    the interim is never silent; the document's fields reach the
    composition only through SBOM-008's allowlist, as a bundled document's
    do, which bounds the name, version and `purl` strings read from an
    unverified document as it bounds every other field. The component's
    own name, version and `purl` never come from the document (SBOM-009
    takes them from the graph at the pin), and IF the document's subject
    names a package other than the closure entry's THEN THE SYSTEM SHALL
    treat it as a subject mismatch (SBOM-012); the identities of the build
    closure's entries are the document's claims from an untrusted source
    (the cache's writer, Security considerations), nested under the
    component and covered by its `unverified` mark, never promoted to
    components of the box. This path ends by
    itself: the first pin that records bundles for its documents takes the
    path above for them, with no flag and no release step.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_without_a_pinned_bundle_is_marked_and_diagnosed
    property: ¬pin_records_bundle(d) ∧ fetched(d) ∧ subject_matches(d) ⇒ read(d) ∧ unverified(component(d), no-bundle) ∧ stderr names (component(d), "build-servers#185"), where fetched(d) is a document the cache returned (neither absent nor unfetchable in any of its three classes) and subject_matches(d) is SBOM-013's subject check
  - A document that carries any `unverified` component is not evidence:
    its build facts for those components are whatever the cache's writer
    put under a correct subject. THE SYSTEM SHALL mark such a document at
    the top level in every serializer (CycloneDX: a `minimal:verification`
    property with the value `partial` on the metadata; SPDX: the same
    annotation on the document; Blueprint: `verification = "partial"`), so
    a consumer that needs evidence can refuse it on the mark alone;
    the emitter's `require_bundles` option is how a reader obtains one that
    is (the CLI flag that sets it follows the command arch#66 settles, Open
    questions).
    tier:   T1
    verify: cargo nextest run -p sbom sbom_with_unverified_components_is_marked_partial_at_the_top_level
    property: (∃k: unverified(k)) ⇔ marked_partial(parse_s(emit_s(c))) for every serializer s
  - THE SYSTEM SHALL emit the `unverified` mark and its reason on the
    component in every serializer — CycloneDX: a `minimal:verification`
    property with the value `unverified` and a `minimal:verification-reason`
    property with `no-document` or `no-bundle`; SPDX: an annotation
    `minimal:verification=unverified;reason=<reason>` on the package;
    Blueprint: `verification = "unverified"` and `verification_reason =
    "<reason>"` on the component — so a reader tells data read without a
    verified bundle from data read with one, and a component with no
    document from one with an unbundled document, never from the
    document's silence.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_unverified_mark_emitted_by_every_serializer
    property: for all serializers s, components k: unverified(k, r) ⇔ marked_unverified(parse_s(emit_s(c)), k, r)
  - WHERE the emitter's `require_bundles` option is set THE SYSTEM SHALL treat a document
    the pin records no bundle for, present or absent, as unresolved
    (SBOM-012's failure, exit code 6, naming the missing bundle) instead of
    reading it: the strict side of the interim, for a reader that wants no
    `unverified` component at all; SBOM-012 names the same condition.
    tier:   T0
    verify: cargo nextest run -p sbom sbom_require_bundles_fails_on_an_absent_bundle

- **SBOM-014** WHEN `min box list --using <pkg>[@<ver>]` filters boxes THE
  SYSTEM SHALL answer from the component set this spec's composition emits
  for each box (SBOM-005: every package present in the environment, the
  launcher-injected and an `open` box's loadout packages included, and
  never the nested build-closure entries SBOM-009 records under a
  component), so the list and the box's SBOM never disagree about what the
  box contains; that set is read from the host's stored copy of the pin's
  sealed closure (the object the box's materialization fetched and kept at
  activation) and the box's stored expanded spec (its loadout entries and
  the launcher's additions, BOX-068) alone, so the list fetches no
  per-package document and needs no network. A box whose stored closure is
  missing or unreadable on the host, or whose upstream package has no
  closure entry (the case its SBOM exits 6 on, SBOM-004), is listed with
  that reason in place of its match, never failing the list for the other
  boxes.
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
  enforced by: the closure walk plus the stored expanded spec's loadout
  packages and launcher additions (BOX-068), with launcher-injection
  tagging, never filtering
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
- **Trust boundary:** until build-servers#185 pins the document digest, the
  Registry Build Cache's writer is a trust boundary of this spec: an
  unbundled per-package document's facts are that writer's claim, bound to
  the tarball by subject digest alone and to no author. The cache's
  writers are the registry's build infrastructure (build-servers) and the
  registry operator; a private registry's cache is written by whoever
  operates it. The spec's
  controls on that boundary are the `unverified` and `partial` marks, the
  stderr diagnostic, SBOM-008's allowlist of copied fields, and
  the `require_bundles` option; a gate that consumes a box document as evidence
  SHALL refuse a `partial` one, and the boundary closes per document as the
  pin records bundles (SBOM-013).
- **Invariant:** THE SYSTEM SHALL never present a document that holds any
  unverified component as evidence.
  enforced by: the top-level `partial` mark in every serializer, which a
  consumer that needs evidence refuses on; `require_bundles` for evidence
  covered by: SBOM-013
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
- [NEEDS CLARIFICATION (MEDIUM): does the Box Spec record, per loadout
  package, the registry it resolved from under `open` loadout mode? Today
  it does not (architecture lines 83, 1074–1077), so a foreign loadout
  package resolves as upstream and `outside-pin` cannot occur. Asked as
  gominimal/arch#138; a yes makes the kind live with no change here.]
- [NEEDS CLARIFICATION (LOW): SPDX `created` timestamp source (proposal:
  pinned commit's committer timestamp); both answers satisfy SBOM-001;
  settle in first-slice review.]
