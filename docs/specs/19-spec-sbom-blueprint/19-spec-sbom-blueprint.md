---
id: SBOM
title: box SBOM + CycloneDX Blueprint
owner: bryan-minimal
epic: gominimal/inbox#582
arch: https://github.com/gominimal/arch/blob/3dab1097cda11652ad24282969ed8dfe61d0d497/architecture.md
arch_sha: "3dab1097cda11652ad24282969ed8dfe61d0d497"
updated: 2026-10-22
---

# SBOM — box SBOM + CycloneDX Blueprint

## Context

Minimal stores the complete declared story of a box: its expanded Box Spec
(BOX-068), its closure and its pins. It cannot export that story in the
formats the world consumes. Security scanners want an SBOM. Compliance wants
documents whose digests are evidence rather than assertion. Build
infrastructure wants per-package SBOMs at publish, chained to the signed
per-commit closure. Developers granting agent boxes want the posture story
reviewable before granting it. `min box list --using <pkg>` (architecture,
Command tree) needs a box's component set to answer from, and the box CLI
spec (BCLI) defers that flag to this spec's epic.

A **box** is any entry the Box Spec expands: a session, task, agent or
service (BOX-046 reads the typed tables as `[boxes.<name>]`). Every box has
an expanded spec the daemon stores (BOX-068). That spec, never the entry or
the running box, is what this spec's documents describe.

**Success:** a box yields schema-valid supply-chain documents whose
component digests chain to the signed catalog closure or carry a declared
digest gap, and whose regeneration is byte-identical.

A **catalog pin** is the triple {repo, commit, closure object} the epic
defines. A document is always emitted under one, and "the pin" below
always means it.

A document for a box is a **composition**. The **per-package document**
published beside the package's artifact (SBOM-013 names it) is the unit. A
box's document is an envelope of composition-level facts over references to
those units, resolved through the box's pin.

A component's closure entry has one of three **states** this spec reads:
`artifact`, `built-locally` and `non-redistributable`. A component has a
**digest gap** of one of three **kinds**: `built-locally` or
`non-redistributable` (the state of its closure entry), or `outside-pin`
(the box's stored expanded spec records a registry for it other than
`[upstream]`). A component with an `artifact` entry has a digest, whether or
not a per-package document exists for it. SBOM-004 says how a component gets
its digest or its gap, and SBOM-011 says how a gap is emitted.

A referenced per-package document is **absent** when the cache answers an
authoritative not-found for its name. Every other failure to fetch it is
**unfetchable**. An unfetchable document is in one of three **classes**.
It is **unreachable** when the host cannot be reached (a timeout, a
refused connection, or no route). It is **refused** when the cache refuses the
request for authentication or authorization. It is **malformed** on every
other fetch failure, such as a malformed answer or a truncated object.
SBOM-012 says what each class does.

**AT2** names the architecture's threat-model entry "Artifact substitution
in the cache or CDN" (Threat Model, Supply chain), whose mitigation is that
verification fails closed.

A box's **posture** is what its expanded Box Spec declares it can reach,
read, write, inherit or expose: `[network]` (mode, `[network.egress]`,
`ingress`, `dynamic_ingress`, `quic443`, `[network.bep]`), `[secrets]`
references, `[env_vars]` and `[loadouts.vars]` with their `inherit` flags,
`[[file_imports]]`, `[[file_exports]]`, `[[github_imports]]`, `volumes`,
`[[loadouts]]` with their patches and lifecycle hooks, `[machine]` and
`[execution]`, `[io]`, `lifetime`, `[nesting]` and `[otel]`. Each axis has
one of three **labels**. An axis is **enforced** when the daemon or host
refuses what it does not allow. It is **declared** when the spec accepts and
records it with enforcement unowned or in flight (BOX-076 warns once at
creation). It is **in flight** when its own spec is open (NET, BRES, BVOL,
BEP). The Blueprint states that label per axis (SBOM-006).

**First slice:** publish emits a per-package document for one catalog
package under SBOM-013's names, beside its artifact. A fixture box then
emits schema-valid CycloneDX 1.5 and minimal-valid SPDX 2.3 over it. The
fixture cache's document bytes never change, so the slice's output is
byte-stable across regenerations under SBOM-001's unbundled case. The
fixture pins no bundle, so the output has the `partial` mark with the
`no-bundle` reason, as a production emission does until the pin records
bundles. CycloneDX 1.5 is the SBOM format because it is the one scanners
read today. The 2.0 draft serves the Blueprint only.

## Users and stories

**Roles:** security engineer, compliance reviewer or downstream consumer,
developer running agent boxes, build-infra operator, and auditor.

- AS A security engineer I WANT a CycloneDX SBOM of any box SO THAT
  existing scanners and policy tooling can evaluate what Minimal boxes
  contain
- AS A compliance reviewer I WANT component digests that verifiably chain to
  the signed per-commit catalog closure SO THAT the document is evidence,
  not assertion
- AS A developer running agent boxes I WANT a Blueprint of a box's declared
  posture SO THAT I can review what an agent box can do before granting it,
  and see which of its boundaries are enforced today
- AS A build-infra operator I WANT the same SBOM model emitted per-package at
  publish time SO THAT catalog artifacts are published with supply-chain
  documents from one emitter
- AS AN auditor I WANT deterministic regeneration SO THAT two parties can
  independently produce and compare the same document
- AS A developer I WANT `min box list --using <pkg>[@<ver>]` to answer from
  the same component set the box's SBOM carries SO THAT the list and the
  document never disagree about what a box contains

## Requirements

- **SBOM-001** WHEN the same catalog pin, the same Box Record resolution
  record and identical declared inputs are emitted twice, the pin recording
  a bundle for every per-package document it references, THE SYSTEM SHALL
  produce byte-identical documents, deriving serials, namespaces and
  timestamps from content and pin, never from wall clock or randomness.
  While the pin records no bundle, the unbundled sub-bullet below bounds how
  two emissions can differ.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_regeneration_deterministic
  property: for all pin, inputs, and independent emissions a, b under
    (pin, inputs), while the pin records a bundle for every per-package
    document it references: bytes(a) == bytes(b)
  - WHILE the pin records a bundle for every per-package document it
    references, IF the cache's contents differ between two emissions under
    the same pin, every object the pinned closure references remaining
    fetchable, THEN THE SYSTEM SHALL still produce byte-identical documents.
    The composition is a function of the pin and its closure, not of what
    the cache happens to hold. An unfetchable referenced object is SBOM-012's
    failure, and fails the same way on every emission.
    tier:   T0
    verify: cargo nextest run -p sbom sbom_determinism_independent_of_cache_state
  - WHILE the pin records no bundle for a per-package document, the closure
    pins the tarball and not the document's bytes, so the composition is a
    function of the pin and of the document bytes it read. Two emissions
    under one pin differ only where the cache's writer replaced a document
    under the same subject, and THE SYSTEM SHALL record the statement digest
    of the bytes it read on the component (SBOM-009), so such a difference
    is attributable to the document and never silent. WHILE the pin records
    the bundle, the bundle binds the bytes and the property above holds
    unconditionally.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_replaced_document_changes_only_its_component_and_digest
    property: bytes(a) ≠ bytes(b) ⇒ R ≠ ∅ ∧ diff(a, b) ⊆ ⋃{component(d) : d ∈ R} ∪ {serial, namespace} (the content-derived identifiers SBOM-001 derives, which follow any component change), where R = {d : ¬pin_records_bundle(d) ∧ read_digest_a(d) ≠ read_digest_b(d)} and a document absent on one emission reads as digest ∅

- **SBOM-002** WHEN a document is emitted as CycloneDX THE SYSTEM SHALL
  produce output that conforms to the vendored CycloneDX 1.5 schema.
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
  digest gap (Context: `built-locally`, `non-redistributable` or
  `outside-pin`), never neither and never both. A component with an
  `artifact` entry has a digest whether or not a per-package document
  exists for it.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_digest_or_gap_total
  property: for all components k: has_sha256(k) xor has_digest_gap(k),
    and has_sha256(k) implies resolves(sha256(k), closure(pin))
  - THE SYSTEM SHALL decide a component's digest or gap from its closure
    entry first, and from a recorded registry only for a package the
    closure holds no entry for. A package with an `artifact` entry has that
    digest whatever registry is recorded for it. A package with a
    `built-locally` or `non-redistributable` entry has that gap. A package
    with no entry whose stored expanded spec (BOX-068) records a registry
    other than `[upstream]` has the `outside-pin` gap, naming that registry
    reduced under SBOM-008 (scheme, host and port). No probe of the cache
    takes part in the decision, so SBOM-001's determinism holds.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_closure_entry_decides_before_recorded_registry
    property: for all packages k: state(entry(closure(pin), k)) = artifact ⇒ has_sha256(k); state(entry(closure(pin), k)) ∈ {built-locally, non-redistributable} ⇒ gap(k) = state(entry(closure(pin), k)); k ∉ closure(pin) ∧ recorded_registry(k) ≠ upstream ⇒ gap(k) = outside-pin
  - IF a package has no closure entry and no recorded registry other than
    `[upstream]`, or its entry is of a state this spec does not read, THEN
    THE SYSTEM SHALL fail the emission with exit code 6 naming the package
    (AT2), never emitting the component with a digest or a gap. The pin does
    not account for the package, and an entry the closure format does not
    define is a broken pin. The design's Box Spec records one upstream
    registry and no registry per loadout package (the architecture's
    "Packages, Containers and supply chain" and "Box Spec" sections), so
    today `outside-pin` cannot occur, and a name resolves against the one
    upstream (the architecture's "Supply chain" threat-model section). An
    `open` box's loadout package from another registry so takes the upstream
    rule: with an `artifact`
    entry of that name it has that digest, and with no entry it is this exit
    6. Whether the design records that registry is an open question below.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_unaccounted_package_fails_with_exit_6
    property: for all packages k: (k ∉ closure(pin) ∧ recorded_registry(k) ∈ {none, upstream}) ∨ (k ∈ closure(pin) ∧ state(entry(closure(pin), k)) ∉ {artifact, built-locally, non-redistributable}) ⇒ ¬emitted ∧ exit = 6 ∧ error names k

- **SBOM-005** THE SYSTEM SHALL include every package present in the box as
  a component, with launcher-injected packages carrying
  `minimal:added-by=launcher`.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_launcher_packages_present
  property: for all boxes b: components(emit(b)) ⊇ packages(b), and for all
    k in launcher_injected(b): added_by(component(k)) == launcher

- **SBOM-006** WHEN a document is emitted as a CycloneDX 2.0 Blueprint THE
  SYSTEM SHALL conform to the vendored draft schema and SHALL emit axes the
  Box Spec cannot declare as schema-TODO properties, never as fabricated
  values.
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
    (BOX-068) and SHALL carry two digests as document properties. The first
    is the spec's posture-projection digest (BOX-071), which binds exactly
    the §6.3.2 field set to the posture Gatehouse admitted the box under.
    That set is `v`, the type fields (`type.name`, `type.source`,
    `type.root`, and `type.registry` when the source is `org`), the network
    fields (`network.mode`, `egress_dns` for the spec's
    `egress.allow_dns_hosts`, `egress_subnets` for `egress.allow_subnets`,
    `egress_deny_subnets` for `egress.deny_subnets`, `ingress_ports` and
    `quic443`), `bep.steering`, `registry_pinned` and `registry_commit`,
    `loadout_mode`, `pty_enabled`, `lifetime`, the `[nesting]` bounds, and
    `secret_grants`. It is computed as BOX-071 computes it (SHA-256 over the
    projection's RFC 8785 JCS bytes, encoded base64url, the stored digest
    copied verbatim). The second is the spec digest, SHA-256 over the
    stored expanded spec's RFC 8785 JCS bytes encoded the same way, which
    binds every other field the Blueprint emits to the spec the box runs
    under: `egress.allow_protocols` and `dynamic_ingress` (which BOX-071
    projects nowhere), the rest of `[network.bep]`, `[secrets]` beyond the
    grants, variables, file imports and exports, GitHub imports, volumes,
    `[execution]`, `[io]`, `[otel]` and `[machine]`. The Blueprint names
    which fields each digest covers, so neither is read as proving more
    than it does.
    tier:   T1
    verify: cargo nextest run -p sbom blueprint_carries_posture_and_spec_digests
    property: posture_digest(emit_bp(c)) == stored_projection_digest(c) (BOX-071's base64url(SHA-256(JCS(projection)))) ∧ spec_digest(emit_bp(c)) == base64url(SHA-256(JCS(expanded_spec(c))))

- **SBOM-007** WHEN a box SBOM is emitted under a pin whose commit
  carries a sealed attribution manifest THE SYSTEM SHALL emit component
  licenses equal to the manifest's license entries for that pin.
  tier:     T0
  verify: cargo nextest run -p sbom sbom_licenses_match_attribution

- **SBOM-008** THE SYSTEM SHALL never embed a variable value, a secret
  value, or a credential held in any posture field or any per-package
  document in any document it emits. The sub-bullets below say what each
  field kind is reduced to before it enters the composition.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_credentials_never_embedded_in_any_serializer
  property: for all compositions c, serializers s in {cdx, spdx, blueprint},
    credentials v in credentials(c) ∪ planted(d) ∪ planted_in_paths(c), where
    every v is at least 16 characters drawn so that no v is a substring of
    any declared input, package name or version of c, and planted_in_paths(c)
    plants one v in each part the sub-bullets drop (a location's userinfo,
    path, query and fragment, a `purl`'s qualifiers and subpath) and none in
    a part they keep (a GitHub import's `owner/repo`, a file entry's relative
    `path`, which are identity and the user's own naming): v not in ir(c),
    and no string anywhere in parse_s(emit_s(c)) equals or contains v
  - THE SYSTEM SHALL record an environment-variable asset (`[env_vars]`,
    `[loadouts.vars]`) by its name and its provenance only, never its value.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_env_assets_carry_name_and_provenance_only
    property: for all serializers s: every environment asset in parse_s(emit_s(c)) carries only name and provenance fields
  - THE SYSTEM SHALL record a `[secrets]` reference by its name and its
    `source` kind only, never its value.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_secrets_carry_name_and_source_kind_only
    property: for all serializers s: every secret in parse_s(emit_s(c)) carries only name and source kind
  - THE SYSTEM SHALL record a `[[github_imports]]` location and the
    `[otel]` endpoint reduced to scheme, host and port. Those three parts
    are an allowlist, so userinfo, path, query, fragment and headers are
    all dropped, whatever a parameter is called. A path segment can hold a
    token (`/hooks/<token>`), so the path goes too. A `[[github_imports]]`
    location keeps its `owner/repo` path alone, which is identity, not a
    secret.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_locations_reduced_to_scheme_host_port
    property: for all serializers s: every location field of the posture in parse_s(emit_s(c)) is of the form scheme://host[:port], or scheme://host/owner/repo for a GitHub import
  - THE SYSTEM SHALL record a `[[file_imports]]` or `[[file_exports]]` entry
    by its `path` relative to the project root alone (architecture: file
    imports and exports), never the project root and never an absolute host
    path. Either can carry a user name or a home directory.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_file_entries_carry_relative_path_only
    property: for all serializers s: every file import or export in parse_s(emit_s(c)) carries only its project-root-relative path and no absolute path
  - THE SYSTEM SHALL record `[network.egress]` fields verbatim:
    `allow_subnets` and `deny_subnets` as CIDRs, `allow_dns_hosts` as host
    names and `allow_protocols` as protocol names. They are not locations,
    and none can carry a credential.
    tier:   T0
    verify: cargo nextest run -p sbom sbom_egress_fields_recorded_verbatim
  - THE SYSTEM SHALL copy from a per-package document (SBOM-009) only an
    allowlist of fields: a build-closure component's name, version, `purl`
    and digests, and a build-environment tool's name and version. Every
    location among them is reduced as the posture's are. Every copied
    `purl` is reduced to its type, namespace, name and version, with
    qualifiers and subpath removed, since a `repository_url` qualifier can
    hold userinfo or a token path. No other field of the document
    (annotations, command lines, environment values, free text of any kind)
    is ever copied, bundled or not.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_copied_document_fields_are_allowlisted
    property: for every document d: fields(imported(d)) ⊆ {name, version, purl, digests, tool name, tool version, location}, every imported location reduced to scheme://host[:port], every copied purl has no qualifiers and no subpath
  - THE SYSTEM SHALL emit no credential a per-package document carries, in
    any of the fields it copies from it, bundled or not.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_credential_planted_in_a_per_package_document_never_emitted
  - THE SYSTEM SHALL accept a string copied from a per-package document
    (a name, version, `purl`, tool name or tool version) only when it is
    valid UTF-8 of at most 256 bytes with no control character (U+0000 to
    U+001F, U+007F) and no line or paragraph separator, and a location only
    when it is at most 2048 bytes of the same kind. A document with any
    other value is unresolved (SBOM-012's failure, exit code 6, naming the
    field), so no document can put a control character, markup or an
    oversized value into a serializer's output. The serializers escape
    every string they emit regardless.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_document_strings_are_bounded_and_control_free
    property: for all documents d, fields f ∈ copied(d): read(d) ⇒ utf8(f) ∧ len(f) ≤ limit(f) ∧ ∀c ∈ f: ¬control(c) ∧ ¬separator(c); a planted control character or a 257-byte name makes d unresolved, and a planted markup string is emitted escaped by every serializer
  - THE SYSTEM SHALL read a per-package document only up to 8 MiB of
    statement bytes, 4,096 build-closure entries, 256 build-environment
    tools and a JSON nesting depth of 16, counting as it parses and
    stopping at the first limit. A document over any limit is unresolved
    (SBOM-012's failure, exit code 6, naming the limit), so an untrusted
    writer cannot exhaust the emitter's memory or time.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_document_read_limits_make_it_unresolved
    property: for all documents d: read(d) ⇒ bytes(d) ≤ 8 MiB ∧ |closure(d)| ≤ 4096 ∧ |tools(d)| ≤ 256 ∧ depth(d) ≤ 16; a 9 MiB body, a 4,097-entry closure or a depth-17 document makes d unresolved

- **SBOM-009** WHEN a component has a per-package document (SBOM-013)
  resolvable through the box's pin THE SYSTEM SHALL take the component's
  build-time facts from that document: its build closure's entries and
  their digests, and the build environment, recorded as that component's
  nested dependency facts and never as components of the box (the box's
  components are SBOM-005's set alone). The component's name and version
  come from the Box Record's resolution record (SBOM-014), with its `purl`
  built from that name and version. Its licenses come from the graph at the
  pin where the pin has no attribution manifest (under a sealed
  attribution manifest SBOM-007 is the one source of licenses). THE SYSTEM
  SHALL reference the document from the component by the tarball's sha256
  and the statement digest SBOM-013 defines, never embed it whole.
  tier:     T0
  verify:   cargo nextest run -p sbom sbom_component_detail_from_document_and_graph

- **SBOM-010** THE SYSTEM SHALL derive composition-level facts (launcher
  injection, posture axes and environment assets) from the box's own
  declaration, never from a component document, which cannot carry them.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_envelope_facts_are_box_derived
  property: for all boxes b: envelope(emit(b)) == declared_facts(b)

- **SBOM-011** IF a component has a digest gap (Context: `built-locally`,
  `non-redistributable` or `outside-pin`) THEN THE SYSTEM SHALL emit that
  component carrying that gap, never omitting it. A document the closure
  references but that is unfetchable is not a gap. It is SBOM-012's
  failure, as is its absence while the pin records a bundle for it. Absence
  while the pin records none is SBOM-013's unbundled case, not a gap. An
  upstream package with no entry at all is SBOM-004's exit 6, not a gap.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_unreferenced_component_carries_its_gap
  property: for all boxes b, k in packages(b): has_digest_gap(k) implies k
    in components(emit(b)) and gap(component(k)) == gap(k), where
    has_digest_gap(k) ⇔ state(entry(closure(pin(b)), k)) ∈ {built-locally,
    non-redistributable} ∨ (k ∉ closure(pin(b)) ∧ recorded_registry(k) ≠
    upstream). The design records no such registry today (Open questions),
    so the second arm is never true.

- **SBOM-012** IF the pinned index or a referenced per-package document
  cannot be fetched (absence excepted while no bundle is pinned, which is
  SBOM-013's unbundled case), or a per-package document is unresolved under
  SBOM-013, or the Box Record's resolution record is missing or unreadable
  (SBOM-014) THEN THE SYSTEM SHALL fail the emission, never emitting a
  document whose component set is silently incomplete. The sub-bullets
  below give each failure its exit code (the architecture's exit-code
  table) and its message.
  tier:     T1
  verify:   cargo nextest run -p sbom sbom_unfetchable_reference_fails_loudly
  property: for all attempts a and referenced objects o: unfetchable(o) ∨
    (absent(o) ∧ pin_records_bundle(o)) ∨ unresolved(o) ⇒ ¬emitted(a),
    where absent(o) is an authoritative not-found, unfetchable(o) =
    unreachable(o) ∨ refused(o) ∨ malformed(o) as Context defines the
    classes, and unresolved(o) is SBOM-013's set (a subject mismatch, a
    failed bundle check, an absent pinned bundle on a reachable host, a
    document the pin records no bundle for under `require_bundles`, a
    copied string or a document that fails SBOM-008's checks or exceeds its
    limits), with a missing or unreadable Box Record resolution record as
    unresolved(record)
  - IF a referenced object's host cannot be reached (Context: unreachable)
    THEN THE SYSTEM SHALL exit with code 7.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_unreachable_host_exits_7
    property: unreachable(o) ⇒ exit(a) = 7
  - IF the cache refuses a request for authentication or authorization
    (Context: refused) THEN THE SYSTEM SHALL exit with code 5.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_refused_request_exits_5
    property: refused(o) ⇒ exit(a) = 5
  - IF the failure is of any other kind (Context: malformed, absence while
    the pin records a bundle, or an unresolved document or record) THEN THE
    SYSTEM SHALL exit with code 6, as a failed check.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_other_failure_exits_6
    property: (malformed(o) ∨ (absent(o) ∧ pin_records_bundle(o)) ∨ unresolved(o)) ⇒ exit(a) = 6
  - WHEN it fails THE SYSTEM SHALL print one error to stderr naming the pin,
    the object, the check that failed and the remediation. For an
    unreachable or refused object the check is the host. For a subject
    mismatch the check is both digests. For a failed bundle check it is the
    check's name. For a string or limit failure it is the field or the
    limit. For a missing resolution record it is the record.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_failure_names_pin_object_check_and_remediation
    property: ¬emitted(a) ⇒ error(a) names (pin, o, check(o), remediation)

- **SBOM-013** WHEN the system resolves a component's per-package document
  THE SYSTEM SHALL read `<spec_hash>.sbom.intoto.jsonl` beside the package's
  artifact in the Registry Build Cache. The file is a DSSE envelope over an
  in-toto v1 Statement whose single `subject` is the package tarball (`<sha256>.zst`,
  the digest the signed closure maps the Build Spec Hash to), whose
  `predicateType` is `https://cyclonedx.org/bom`, and whose predicate is the
  package's CycloneDX 1.5 document covering the transitive build closure by
  built-artifact digest (the architecture's Package SBOM: the software built
  and the build environment). The **document digest** is the sha256 of the
  statement bytes. Its Sigstore bundle, when published, is
  `<spec_hash>.sbom.sigstore.json`, a DSSE over byte-identical statement
  bytes, and its state in the sealed map follows the provenance bundle's
  (spec PKV, PKV-017). Producing both is build infrastructure's work
  (Non-goals). The names and the statement shape are this spec's contract,
  and PKV-011 checks the bundle under them.
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
    map, PKV-017's) THE SYSTEM SHALL check the bundle with PKV-011's checks
    first, then check the subject, and only then read any other field of the
    document. IF the bundle fails a check or is absent THEN THE SYSTEM SHALL
    treat the document as unresolved (SBOM-012's failure, exit code 6,
    naming the check or the missing bundle), and never read it. IF the
    bundle's host cannot be reached THEN THE SYSTEM SHALL fail with exit
    code 7 naming the host, as SBOM-012 does for any object. IF the cache
    refuses the bundle request for authentication or authorization THEN THE
    SYSTEM SHALL fail with exit code 5 naming the pin, the bundle and the
    host. The pin decides, so SBOM-001 holds: the same pin always takes the
    same path.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_bundle_verified_before_read
    property: pin_records_bundle(d) ⇒ (read(d) ⇒ verified(bundle(d))) ∧ (unreachable(bundle(d)) ⇒ exit = 7) ∧ (refused(bundle(d)) ⇒ exit = 5) ∧ (¬unreachable(bundle(d)) ∧ ¬refused(bundle(d)) ∧ ¬verified(bundle(d)) ⇒ exit = 6); checks(d) = [bundle, subject, rest] in that order
  - WHILE the pin records no bundle for the document, IF the cache holds no
    document beside the artifact (the producer has published none, which is
    every package today) THEN THE SYSTEM SHALL emit the component with its
    artifact digest from the closure and no build-time facts, marked
    `unverified` with the reason `no-document`, and mark the document
    `partial`, never failing the emission for it. A fetch error other than
    absence stays SBOM-012's failure. WHILE the pin records a bundle,
    absence is SBOM-012's failure.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_absent_in_the_interim_is_marked_not_fatal
    property: ¬pin_records_bundle(d) ∧ absent(d) ∧ ¬require_bundles ⇒ emitted ∧ has_sha256(component(d)) ∧ unverified(component(d), no-document)
  - WHILE the pin records no bundle for the document, IF the cache holds
    the document THEN THE SYSTEM SHALL read it and mark the component
    `unverified` with the reason `no-bundle`, as PKV marks an entry whose
    source has no verified bundle. The document's fields reach the
    composition only through SBOM-008's allowlist, as a bundled document's
    do, which bounds the name, version and `purl` strings read from an
    unverified document as it bounds every other field. The component's
    own name, version and `purl` never come from the document (SBOM-009
    takes name and version from the Box Record's resolution record and
    builds the `purl` from them). IF the document's subject names a package
    other than the closure entry's THEN THE SYSTEM SHALL treat it as a
    subject mismatch (SBOM-012). The identities of the build closure's
    entries are the document's claims from an untrusted source (the cache's
    writer, Security considerations), nested under the component and
    covered by its `unverified` mark, never promoted to components of the
    box. This path ends by itself: the first pin that records bundles for
    its documents takes the bundled path for them, with no flag and no
    release step.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_document_without_a_pinned_bundle_is_marked_and_diagnosed
    property: ¬pin_records_bundle(d) ∧ fetched(d) ∧ subject_matches(d) ∧ ¬require_bundles ⇒ read(d) ∧ unverified(component(d), no-bundle), where fetched(d) is a document the cache returned (neither absent nor unfetchable in any of its three classes) and subject_matches(d) is SBOM-013's subject check
  - WHEN an emission holds at least one `unverified` component THE SYSTEM
    SHALL print exactly one line to the emitting command's stderr, after
    the document is written, of the form `warning: <n> component(s) of
    <box> read without a verified per-package document, so the document is
    marked partial: <name>@<version> (<reason>), ...`, with `<n>` the count
    of such components, `<box>` the box's name, the components in name
    order and `<reason>` the component's mark reason (`no-document` or
    `no-bundle`). WHEN an emission holds no `unverified` component THE
    SYSTEM SHALL print nothing to stderr for this reason. The line goes to
    stderr so a payload command's stdout stays the document alone.
    tier:   T1
    verify: cargo nextest run -p sbom per_package_interim_diagnostic_text
    property: (∃k: unverified(k)) ⇔ stderr(a) contains exactly one such line, and that line names every unverified k with its reason in name order; (∄k: unverified(k)) ⇒ stderr(a) holds no such line
  - A document with any `unverified` component is not evidence:
    its build facts for those components are whatever the cache's writer
    put under a correct subject. THE SYSTEM SHALL mark such a document at
    the top level in every serializer (CycloneDX: a `minimal:verification`
    property with the value `partial` on the metadata, SPDX: the same
    annotation on the document, Blueprint: `verification = "partial"`), so
    a consumer that needs evidence can refuse it on the mark alone. The
    emitter's `require_bundles` option is how a reader obtains one that is
    evidence (the CLI flag that sets it follows the command ruling, Open
    questions).
    tier:   T1
    verify: cargo nextest run -p sbom sbom_with_unverified_components_is_marked_partial_at_the_top_level
    property: (∃k: unverified(k)) ⇔ marked_partial(parse_s(emit_s(c))) for every serializer s
  - THE SYSTEM SHALL emit the `unverified` mark and its reason on the
    component in every serializer (CycloneDX: a `minimal:verification`
    property with the value `unverified` and a `minimal:verification-reason`
    property with `no-document` or `no-bundle`, SPDX: an annotation
    `minimal:verification=unverified;reason=<reason>` on the package, and
    Blueprint: `verification = "unverified"` and `verification_reason =
    "<reason>"` on the component), so a reader tells data read without a
    verified bundle from data read with one, and a component with no
    document from one with an unbundled document, never from the
    document's silence.
    tier:   T1
    verify: cargo nextest run -p sbom sbom_unverified_mark_emitted_by_every_serializer
    property: for all serializers s, components k: unverified(k, r) ⇔ marked_unverified(parse_s(emit_s(c)), k, r)
  - WHERE the emitter's `require_bundles` option is set THE SYSTEM SHALL
    treat a document the pin records no bundle for, present or absent, as
    unresolved (SBOM-012's failure, exit code 6, naming the missing bundle)
    instead of reading it. This is the strict side of the unbundled case,
    for a reader that wants no `unverified` component at all. SBOM-012
    names the same condition.
    tier:   T0
    verify: cargo nextest run -p sbom sbom_require_bundles_fails_on_an_absent_bundle

- **SBOM-014** WHEN `min box list --using <pkg>[@<ver>]` filters boxes THE
  SYSTEM SHALL answer from the component set this spec's composition emits
  for each box (SBOM-005: every package present in the box, the
  launcher-injected and an `open` box's loadout packages included, and
  never the nested build-closure entries SBOM-009 records under a
  component), so the list and the box's SBOM never disagree about what the
  box contains.
  tier:     T0
  verify:   cargo nextest run -p minimal box_list_using_answers_from_the_sbom_components
  - THE SYSTEM SHALL read that set from the host's stored copy of the pin's
    sealed closure (the object the box's materialization fetched and kept
    at activation) and the box's stored expanded spec (its loadout entries
    and the launcher's additions, BOX-068) alone, fetching no per-package
    document and needing no network. The version it filters on is the one
    in the box's resolution record, below.
    tier:   T0
    verify: cargo nextest run -p minimal box_list_using_reads_stored_closure_and_spec_offline
  - IF a box's stored closure or resolution record is missing or unreadable
    on the host, or its upstream package has no closure entry (the case its
    SBOM exits 6 on, SBOM-004) THEN THE SYSTEM SHALL list that box with
    that reason in place of its match, never failing the list for the
    other boxes.
    tier:   T0
    verify: cargo nextest run -p minimal box_list_using_reports_an_unreadable_box_with_its_reason
  - THE SYSTEM SHALL keep, as part of the Box Record (the host-side
    state of one box, which minimald alone writes, outside the box's
    filesystem and unwritable from inside it), a resolution record of every package the
    box was materialized with: its name, version and Build Spec Hash as the
    graph resolved them at activation. Both the list's `@<ver>` filter and
    the SBOM's component name and version (SBOM-009) SHALL read from that
    record, so the two agree offline and a version is never fetched to
    answer a list. IF the record is missing or unreadable THEN the box's
    SBOM is SBOM-012's failure, exit code 6, naming the record, with no
    fallback to the graph (AT2), and the list reports the box with that
    reason.
    tier:   T0
    verify: cargo nextest run -p minimal box_list_using_version_answers_from_the_stored_resolution_record

## Non-goals

- Live-box/observed mode: the observed-capture slice of the epic (declared
  spec only here)
- Full SPDX profile depth: the epic's SPDX decision (minimal-valid only
  here)
- Usage/link-tier axis: model field reserved, per the epic
- Converging legacy `mfile::Task` onto box primitives: BOX-046 on main reads
  `[tasks.<name>]` as a box entry, which is that destination
- Network-zone enforcement: the Box Spec and networking requirements (zones
  are declared and labelled here)
- Signing composed box documents: they are derivations over signed
  per-package inputs and carry those bundles by reference. Signing policy
  lives with the attestation cutover (build infrastructure).
- Producing the per-package document and its bundle at publish: build
  infrastructure. This spec names them (SBOM-013) so the producer and this
  reader agree.
- Pinning the document digest in the signed closure, which is what makes a
  per-package document sealed under a pin rather than bound through its
  subject: build infrastructure, first step. Until it is merged the chain
  runs bundle identity, then the tarball digest, then the closure.
- Enforcing the declared-only posture axes (file imports and exports, GitHub
  imports, `[otel]`, the VPN mesh): the specs that define them (NET, MRF,
  the file-rules work). The Blueprint labels them `declared` until then.

## Design reasoning

The build/workflow story minimal emits is CycloneDX **formulation**
(schema-stable since 1.5). "Blueprint", the 2.0 draft threat-modeling
schema, carries the posture story. The naming distinction is deliberate, to
avoid a semantic clash in a public CLI. The spec is declared-spec-first
because minimal persists no execution ledger today: the declared model is
cheap and honest, and observed capture is a real subsystem with its own
slice. One lean model crate serves both the CLI and build-infra per-package
emission. The second consumer is why the model takes no CLI or daemon
dependencies. A content-derived catalog pin replaces random serials and
wall-clock time, so documents chain to a Sigstore-verifiable object and
regeneration is reproducible. The epic records the decisions and the
alternatives considered. The `verify:` pointers name the model crate `sbom`.
The name follows the crate when the emitter question below settles.

Which command emits the document is the architecture's to say, not this
spec's. The
command tree reserves `sbom` under `pkg` (a package's own document, the
input this spec composes over) and `container`. The `box` noun has no such
verb, and the CycloneDX Blueprint is the same "declared posture" that `min
box spec <entry>` renders as TOML, JSON or YAML. The ruling is an open
question below, and this spec binds no command until the ruling is merged.
The evidence
favours a payload command, `min box sbom <box>`, with the Blueprint a mode
of it. Design principle 4 makes `pkg sbom` a payload command that writes
only the payload to stdout and takes no `-o`. BCLI-021 fixes `box spec`'s
formats as `toml|json|yaml`, and BCLI-033 requires every machine-output
object to carry a `min/v1/<type>` schema and, for `spec`, the per-value
layer BOX-161 reports, which a CycloneDX document cannot carry. One meaning
per verb (principle 2) then keeps `spec` as Minimal's own rendering and
`sbom` as the outside-schema document, as `pkg sbom` and `container sbom`
are. The requirements bind either answer.

SBOM-009 through SBOM-014 go beyond the epic's acceptance criteria. The
epic predates the choice between eager whole-box emission and composition,
and its criteria do not reach it. Composition by reference wins over eager
whole-box emission for three reasons. The per-package document is the unit
publish already has the inputs for. One document serves every box
containing that package. A composed document inherits corrected component
data (a revised patch ledger, a new advisory disposition) without
regenerating anything. The cost is that resolution can miss, so SBOM-011
and SBOM-012 are requirements rather than error handling: a
document that silently drops a component is worse than one that refuses to
emit. Non-redistributable packages and locally built ones are permanently
outside the cache by design, so the gap arm is the ordinary path, not a
failure mode.

One CycloneDX emitter exists in the org with consumers around it.
`minimal-supply-chain`'s `sbom.rs` emits CycloneDX 1.5 from recipe
metadata, with a random serial and a wall-clock timestamp, and carries a
`build_scan` that hashes built output which no producer uses yet.
`pkgmgr-rs`'s `pkgmgr sbom` is a caller of it and emits nothing itself. The
Go `minimal-sbom` is retired, with its migration guide in
minimal-supply-chain. The webapp's SBOM tab generates its own unsigned
document from source-tarball digests. The model crate here subsumes
`minimal-supply-chain::sbom` behind the facade the supply-chain crate
already lays out: the code moves, a re-export keeps `pkgmgr-rs` compiling,
and the API is refined after. One emitter then serves `min`,
publish and the webapp, which becomes a consumer that falls back to its own
generator only until signed per-package documents exist. The random serial
and timestamp go in the move, since SBOM-001 forbids them.

**Generality:** a second document format fits behind the serializer seam
(SPDX proves it in the first slice). A second consumer (build infra) is a
design input, not an afterthought. What does not generalize: posture
vocabulary is bound to the Box Spec. A second box model needs its own axis
mapping, which is acceptable because the vocabulary follows the spec that
defines the box.

Emitted vocabulary is the Box Spec's, verbatim, as architecture.md's
`box.toml` and the BOX spec define it (Context lists the tables): `[network]
mode = none | host_ip | own_ip` (BOX-079, with the legacy spellings accepted
for one release and never emitted), egress in its nested `[network.egress]`
form (BOX-157), `[secrets]` as references with their `source`, `[env_vars]`
with the `inherit` flag as provenance, and so on. The meaning of the network
modes is the networking spec (NET, `docs/specs/18-spec-box-networking`).
Binding the vocabulary to the architecture means a Box Spec rename is an
arch change that rolls this spec's golden fixtures in the same PR rather
than surprising them. The enforcement label (SBOM-006) is what keeps the
Blueprint honest while much of the posture is declared and not yet
enforced: a reader sees `[[file_imports]]` as a declared boundary until
the spec that enforces it is merged.

In Blueprint terms the box, the host, the client, the project subtree, each
volume, the upstream registry and the egress proxy are zones, with the
box's trust boundary set by `[network] mode`. Packages, secret references,
environment variables, imported and exported files, volumes and loadout
patches are assets. Egress and ingress lists, credentialed flows through the
egress proxy, file and volume transfers and the `[otel]` exporter are flows.
The entrypoint, lifecycle hooks, `lifetime`, `restart`, `timeout`,
`pty_enabled`, `exec_enabled`, `dynamic_ingress` and `dynamic_providers` are
behaviors. Runtime outcomes (dynamic ingress decisions, public exposure),
host-asserted facts (the egress pin, whether `[machine]` limits are enforced)
and client-side consent rules (the three `*-file-rules` and
`[secret-store-rules]` tables, which never enter the spec) are undeclarable
from the spec and stay schema-TODO.

## Security considerations

- **Invariant:** THE SYSTEM SHALL include every package present in the box
  in its SBOM.
  enforced by: the closure walk plus the stored expanded spec's loadout
  packages and launcher additions (BOX-068), with launcher-injection
  tagging, never filtering
  covered by: SBOM-005
- **Invariant:** THE SYSTEM SHALL emit no fabricated posture values, and no
  posture axis as enforced that is not.
  enforced by: schema-TODO properties for undeclarable axes, and the
  enforcement label per axis
  covered by: SBOM-006
- **Invariant:** THE SYSTEM SHALL embed no environment-variable values in
  any document.
  enforced by: the name-and-provenance asset model, so values never enter
  the IR
  covered by: SBOM-008
- **Invariant:** THE SYSTEM SHALL represent every unverifiable digest as an
  explicit gap rather than an omission or a guess.
  enforced by: the digest-or-gap total mapping over the signed closure
  covered by: SBOM-004
- **Invariant:** THE SYSTEM SHALL never emit a document whose component set
  is incomplete without saying so.
  enforced by: components with a gap are emitted with it, and unfetchable
  references abort the emission
  covered by: SBOM-011, SBOM-012
- **Trust boundary:** until the signed closure pins the document digest,
  the Registry Build Cache's writer is a trust boundary of this spec. An
  unbundled per-package document's facts are that writer's claim, bound to
  the tarball by subject digest alone and to no author. The cache's writers
  are the registry's build infrastructure and the registry operator. A
  private registry's cache is written by whoever operates it. The spec's
  controls on that boundary are the `unverified` and `partial` marks, the
  stderr diagnostic, SBOM-008's allowlist of copied fields, and the
  `require_bundles` option. A gate that consumes a box document as evidence
  SHALL refuse a `partial` one, and the boundary closes per document as the
  pin records bundles (SBOM-013).
- **Invariant:** THE SYSTEM SHALL never present a document that holds any
  unverified component as evidence.
  enforced by: the top-level `partial` mark in every serializer, which a
  consumer that needs evidence refuses on, and `require_bundles` for
  evidence
  covered by: SBOM-013
- **Invariant:** THE SYSTEM SHALL never attribute a per-package document to
  a component whose closure digest it does not name as its subject.
  enforced by: the bundle check, then the subject check, before any other
  field of the document is read (SBOM-013)
  covered by: SBOM-013

## Open questions

- [NEEDS CLARIFICATION (HIGH): the command home and the Blueprint's place.
  The architecture reserves `sbom` under `pkg` and `container` only. A box
  document needs a verb under `box`. Proposed, with the evidence in Design
  reasoning: `min box sbom <box>`, a payload command like `pkg sbom`, with
  the Blueprint a mode of it (`--blueprint`) rather than an output format of
  `min box spec`, whose `-o` formats and `min/v1/spec` schema a CycloneDX
  document cannot satisfy. Ruling requested as gominimal/arch#66. The spec
  binds no command until the ruling is merged. The earlier worry that "blueprint"
  already means the Box Spec in the architecture's vocabulary no longer
  holds: the current text uses the word once, for the document itself.]
- [NEEDS CLARIFICATION (HIGH): is a composed box document signed in its own
  right, or a verifiable derivation over signed per-package inputs it
  references? Recommendation on record: a derivation. It calls for no per-box
  signing infrastructure and stays valid as inputs are re-signed. Decide
  with the attestation cutover, gominimal/build-servers#86.]
- [NEEDS CLARIFICATION (MEDIUM): the sealed map's state name for a published
  SBOM bundle and the closure's `sbom_digest` field, which the producer's
  first step adds. SBOM-013 binds the object names and the statement shape
  now. The state name follows the provenance bundle's (`bundled`) unless the
  producer rules otherwise. Settle on gominimal/build-servers#185 before the
  first slice's golden fixtures.]
- [NEEDS CLARIFICATION (MEDIUM): does the Box Spec record, per loadout
  package, the registry it resolved from under `open` loadout mode? Today
  it does not (the architecture's "Packages, Containers and supply chain"
  and "Box Spec" sections), so a foreign loadout package resolves as upstream and
  `outside-pin` cannot occur. Asked as gominimal/arch#138. A yes makes the
  kind live with no change here.]
- [NEEDS CLARIFICATION (LOW): SPDX `created` timestamp source (proposal:
  pinned commit's committer timestamp). Both answers satisfy SBOM-001.
  Settle in first-slice review.]
