---
id: PKV
title: Package verification — `min pkg verify`, fail-closed pulls, and a Sigstore bundle on every artifact
owner: bryan-minimal
epic: gominimal/inbox#721
arch: https://github.com/gominimal/arch/blob/faccc370fdc8568c085ca481b497e43475fdd98a/architecture.md
updated: 2026-09-23
---

# PKV — Package verification — `min pkg verify`, fail-closed pulls, and a Sigstore bundle on every artifact

## Context

Minimal's build servers sign what they publish, and nothing on the consumer side reads the signatures. Every push to the public registry's main seals a per-commit Cache Index with a Sigstore bundle under a pinned production identity, and every artifact a run builds carries a SLSA Provenance v1 statement in a DSSE envelope signed by two KMS-held keys, ECDSA P-256 and ML-DSA-65. A host today checks a tarball's hash against an index it never verified; `min` has no verification code at all; an auditor can verify the index with `cosign` but has no bundle per artifact to verify. The architecture of record (D3, "What verified means", the `pkg` command tree, exit code 6) already says what verification is; this spec binds the behaviour of the command-line surface, the fetch path, the trust root, and the per-artifact Sigstore plane the producer still owes.

After this ships: `min pkg verify <pkg>` reproduces the architecture's four checks and fails closed; payload commands print nothing they have not authenticated; a host's pull refuses an unsigned or mis-signed artifact; every artifact's provenance carries a bundle an auditor verifies with stock `cosign`; and the accepted signers are a versioned, append-only trust root vendored into the signed release.

**Success:** on the current registry head, `min pkg verify` passes for every package whose sealed-map entry is `signed`, exits 6 with the failing check named for a tampered tarball, a foreign signer, or a missing envelope, and every check it reports is reproducible with `cosign` plus the documented commands.

**First slice:** `min pkg verify <pkg>` verifies the Cache Index bundle against a vendored trust root, compares the tarball's recomputed hash to the verified index, and exits 0 or 6 with one line per check.

## Users and stories

**Roles:** developer or auditor, developer, CI author, developer on a stock install, platform engineer, security auditor, post-quantum-sensitive consumer, security engineer

- AS A developer or auditor, I WANT `min` to verify the Cache Index's Sigstore bundle against the pinned production identity before it uses the index, SO THAT nothing keyed by an index I did not verify is trusted.
- AS A developer, I WANT the tarball's content hash recomputed locally and compared to the verified index entry for the package's Build Spec Hash, SO THAT a substituted or corrupted artifact is refused before anything reads it.
- AS A developer, I WANT the artifact's DSSE provenance envelope verified against the trust root's KMS keys and its statement bound to the artifact, SO THAT I know which builder built it, from which source and commit.
- AS A developer, I WANT `min pkg provenance|sbom|build-log <pkg> --verify` to print the payload only after its checks pass, SO THAT a payload I read has already been authenticated.
- AS A CI author, I WANT `min pkg verify` to exit 6 on any failure, 0 only when every check passed, and to emit `--json` with one entry per check, SO THAT a pipeline can gate on it and a human can see which check failed.
- AS A developer on a stock install, I WANT the accepted signers vendored into the `min` release I already verify at update time, SO THAT verification works offline and no first-use trust decision is mine to make.
- AS A platform engineer, I WANT the trust root published at a well-known URL and signed by a meta-key pinned in `min`, SO THAT a signer rotation reaches installed clients without a client release.
- AS A security auditor, I WANT every published provenance statement to carry a Sigstore bundle signed by the same pinned identity as the index, binding its tarball by subject digest, SO THAT I can verify any artifact with stock `cosign` and find it in Rekor by hash.
- AS A developer, I WANT `min pkg verify` to verify the artifact's Sigstore bundle with the same checks as the index bundle, in addition to the KMS envelope, SO THAT the interoperable plane and the post-quantum plane both cover every artifact.
- AS A post-quantum-sensitive consumer, I WANT `--require-pq` to fail unless the ML-DSA-65 signature verifies, SO THAT a classical-only forgery cannot pass my policy.
- AS A platform engineer, I WANT the host's cache fetch to run S1–S3 before it accepts an artifact when verification is enabled, SO THAT a box never starts from a cache entry the pinned root did not sign.
- AS A security engineer, I WANT verification on by default for pulls from the public registry, SO THAT the default install is the verified one.
- AS A security auditor, I WANT one page that lists, per artifact type, the object names, the trust root entries, and the exact `cosign` command that verifies it, SO THAT I can reproduce every check `min` performs without running `min`.

The epic's stretch story, timestamp and transparency layers over the KMS envelope, is out of scope here and lands with gominimal/build-servers#95 and #96 (see Non-goals).

## Requirements

Checks are named `index`, `artifact`, `provenance`, `artifact bundle`; a failure message is `<check>: <detail>`. A bundle's *signing time* is its RFC 3161 timestamp (Rekor v2 issues no signed entry timestamp, so a v2 bundle without one fails the `index` or `artifact bundle` check); an envelope's *build time* is the statement's `runDetails.metadata.finishedOn`, which the same key signs, so the KMS plane's window check is self-asserted until an external timestamp covers the envelope (gominimal/build-servers#95). The *verify error class* is the failure that `min pkg verify` reports with exit 6, carried unchanged into a run's output when the fetch path raises it.

- **PKV-001** WHEN `min pkg verify <pkg>[@<ver>]` resolves a registry pin THE SYSTEM SHALL fetch that commit's Cache Index and its Sigstore bundle and verify the bundle's signature over the index hash, the certificate's SAN and OIDC issuer against a trust-root identity valid at the bundle's signing time, the Rekor inclusion proof against the trust root's log key, and the Sigstore trust-root freshness, before any index entry is read.
  tier:     T1
  verify:   cargo nextest run -p verify index_bundle_verifies_against_pinned_identity
  property: read(index, entry) ⇒ verified(bundle(index), root) before the read, for every entry read on any path
  - IF the bundle is signed by an identity absent from the trust root or outside its validity window THEN THE SYSTEM SHALL exit 6 with `index: signer not trusted` and the identity.
    tier:   T0
    verify: cargo nextest run -p verify index_bundle_foreign_identity_exits_6
  - IF the bundle is absent THEN THE SYSTEM SHALL exit 6 with `index: no bundle`.
    tier:   T0
    verify: cargo nextest run -p verify index_bundle_absent_exits_6

- **PKV-002** THE SYSTEM SHALL accept a Cache Index bundle if and only if stock `cosign verify-blob --bundle` (v3 or later, which reads Rekor v2 bundles) with the trust root's identity and issuer accepts it.
  tier:     T1
  verify:   cargo nextest run -p verify index_bundle_agrees_with_cosign_corpus
  property: for every bundle b in the live corpus, accept_min(b) == accept_cosign(b)

- **PKV-003** WHEN an index has been verified THE SYSTEM SHALL compute the package's Build Spec Hash under the epoch that index declares (today's encoding until the index carries an epoch field, spec EPOCH, gominimal/minimal#1305) and compare the tarball's locally recomputed sha256 to the index entry for that hash, consulting neither the object name nor any bucket metadata.
  tier:     T1
  verify:   cargo nextest run -p verify artifact_hash_bound_to_verified_index
  property: accept(artifact) ⇒ sha256(bytes(artifact)) == index[spec_hash(pkg, epoch(index))]
  - IF the hashes differ THEN THE SYSTEM SHALL exit 6 with `artifact: hash mismatch` and both hashes.
    tier:   T0
    verify: cargo nextest run -p verify artifact_hash_mismatch_exits_6
  - IF the Build Spec Hash is not in the index THEN THE SYSTEM SHALL exit 4 with `artifact: not in index` (a miss is not a verification failure).
    tier:   T0
    verify: cargo nextest run -p verify artifact_not_in_index_exits_4

- **PKV-004** THE SYSTEM SHALL parse `<spec_hash>.intoto.jsonl` one envelope per line, accepting exactly the DSSE fields `payload`, `payloadType` and `signatures[]{keyid, sig}`, and SHALL reject an envelope with any other field, an empty line inside the file (the terminating newline is not one), an empty `signatures`, or more than 8 signatures, before verifying any signature.
  tier:     T1
  verify:   cargo nextest run -p verify envelope_parse_rejects_unknown_fields_and_oversize
  property: parse(e) = Ok ⇒ fields(e) ⊆ {payload, payloadType, signatures} ∧ 1 ≤ |signatures| ≤ 8 ∧ ∀s ∈ signatures. fields(s) = {keyid, sig}

- **PKV-005** THE SYSTEM SHALL verify each signature over the DSSE pre-authentication encoding of the base64-decoded payload, `"DSSEv1" SP len(type) SP type SP len(body) SP body`, with the trust-root key chosen by algorithm and validity and never by the envelope's `keyid` alone.
  tier:     T1
  verify:   cargo nextest run -p verify pae_is_byte_exact
  property: pae(t, b) == b"DSSEv1 " ++ dec(len(t)) ++ b" " ++ t ++ b" " ++ dec(len(b)) ++ b" " ++ b, with b the decoded bytes and never a re-serialised JSON

- **PKV-006** THE SYSTEM SHALL accept a provenance envelope only when the required roles are each satisfied by a distinct trusted key that verified: the classical role (ECDSA P-256) by default, and additionally the post-quantum role (ML-DSA-65) WHERE `--require-pq` is given; a failed signature is skipped, never fatal by itself, and acceptance is never the first valid signature.
  tier:     T1
  verify:   cargo nextest run -p verify role_policy_is_threshold_over_distinct_keys
  property: accept(env, policy) ⇔ ∀r ∈ policy.required. ∃k ∈ root.keys. role(k) = r ∧ verifies(k, env) ∧ distinct over r
  - IF `--require-pq` is given and no ML-DSA-65 signature verifies THEN THE SYSTEM SHALL exit 6 with `provenance: pq signature required`.
    tier:   T0
    verify: cargo nextest run -p verify require_pq_without_mldsa_exits_6

- **PKV-007** THE SYSTEM SHALL verify ML-DSA-65 as the pure, empty-context FIPS 204 algorithm over the raw PAE bytes against raw public-key bytes, and SHALL reject every negative vector of the Wycheproof or ACVP ML-DSA-65 set.
  tier:     T1
  verify:   cargo nextest run -p verify mldsa65_known_answer_and_negative_vectors
  property: ∀(pk, m, sig) ∈ negative_vectors. verify(pk, m, sig) = reject

- **PKV-008** WHEN both required signatures verify THE SYSTEM SHALL decode the statement and accept it only if `_type` is the in-toto Statement v1, `predicateType` is SLSA Provenance v1, some `subject[]` carries `digest.sha256` equal to the locally recomputed tarball hash and `digest.minimal_spec_hash` equal to the Build Spec Hash, `predicate.runDetails.builder.id` equals the trust root's builder identity, and `externalParameters.{repo, package, arch}` equal the caller's expectations; `externalParameters.commit` is reported and asserted only WHERE `--source-commit` is given.
  tier:     T1
  verify:   cargo nextest run -p verify statement_subject_binding_and_expectations
  property: accept(stmt, art) ⇒ ∃s ∈ stmt.subject. s.sha256 == sha256(art) ∧ s.minimal_spec_hash == spec_hash(art)
  - IF any assertion fails THEN THE SYSTEM SHALL exit 6 with `provenance: <assertion>` naming the field.
    tier:   T0
    verify: cargo nextest run -p verify statement_assertion_failure_names_field

- **PKV-009** IF `<spec_hash>.intoto.jsonl` is absent THEN THE SYSTEM SHALL exit 6 with `provenance: none`, and THE SYSTEM SHALL never accept the legacy unsigned `<spec_hash>.intoto.json` as provenance.
  tier:     T1
  verify:   cargo nextest run -p verify absent_envelope_fails_closed_legacy_json_ignored
  property: ∀ artifact a. required(provenance) ∧ envelope(a) = ∅ ⇒ exit = 6, whatever other objects exist under a's name

- **PKV-010** THE SYSTEM SHALL verify every envelope in the live corpus of production `.intoto.jsonl` objects with both signatures and the `{repo, commit, package, arch}` round trip.
  tier:     T0
  verify:   cargo nextest run -p verify live_corpus_round_trip

- **PKV-011** WHEN `--verify` is given to `min pkg provenance <pkg>` THE SYSTEM SHALL run the index, artifact and provenance checks and print the decoded statement only after every required check passes; without `--verify` THE SYSTEM SHALL print the payload preceded by one line stating it is unverified.
  tier:     T0
  verify:   cargo nextest run -p minimal pkg_payload_commands_verify_before_print
  - IF a required check fails THEN THE SYSTEM SHALL print nothing of the payload and exit 6.
    tier:   T0
    verify: cargo nextest run -p minimal pkg_payload_command_prints_nothing_on_failure
  - WHILE no SBOM or build-log document is published for the package THE SYSTEM SHALL, for `sbom --verify` and `build-log --verify`, exit 6 with `sbom: not published` or `build-log: not published` rather than print unverified bytes.
    tier:   T0
    verify: cargo nextest run -p minimal pkg_sbom_verify_unpublished_exits_6
  - WHERE an SBOM document and its bundle are published THE SYSTEM SHALL verify the bundle with the index-bundle checks before printing the SBOM.
    tier:   none
    verify: none, the SBOM document and its publication are gominimal/inbox#582's (spec SBOM); this line binds once that spec names the object

- **PKV-012** THE SYSTEM SHALL exit 0 only when every required check passed and 6 on any signature, hash or attestation failure, and with `--json` SHALL emit one object per check with `name`, `status` in `{pass, fail, absent}` and `detail`; text output SHALL carry the same lines.
  tier:     T1
  verify:   cargo nextest run -p minimal pkg_verify_exit_code_and_json_shape
  property: exit = 0 ⇔ ∀c ∈ checks. status(c) ∈ {pass, absent} ∧ absent(c) ⇒ optional(c, root); exit = 6 ⇔ ∃c. status(c) = fail

- **PKV-013** THE SYSTEM SHALL read the trust root as one versioned, append-only document carrying the builder identity, Sigstore identities (SAN, OIDC issuer, Fulcio, Rekor origin and log key, TSA) and KMS keys (algorithm, key id, raw public-key bytes), each signer with `valid_from` and `valid_to`, vendored into the `min` release and overridable with `--trusted-root <path>`.
  tier:     T0
  verify:   cargo nextest run -p verify trust_root_parses_vendored_and_override
  - IF a key's window does not cover the signing time (bundles) or the build time (envelopes, self-asserted until gominimal/build-servers#95) THEN THE SYSTEM SHALL not use that key for the check.
    tier:   T1
    verify: cargo nextest run -p verify key_outside_validity_window_is_not_used
    property: uses(k, t) ⇒ valid_from(k) ≤ t ∧ (valid_to(k) = ∅ ∨ t < valid_to(k))

- **PKV-014** THE SYSTEM SHALL ship vendored production entries whose builder identity, Sigstore identities and KMS key ids equal the producer's trust policy at the time of vendoring; the producer's repository, which holds that policy and depends on the public verifier, carries the test.
  tier:     T0
  verify:   cargo nextest run -p buildbot trust_policy_matches_vendored_root

- **PKV-015** WHERE a well-known trust-root URL and a pinned meta-key are configured THE SYSTEM SHALL fetch the published root, verify its meta-key signature, refuse a root whose version is lower than the vendored one, and cache it; the vendored root SHALL remain the floor.
  tier:     none
  verify:   none, the URL and meta-key custody are not yet named by the architecture ("What verified means" names the list and the pinning only); gominimal/arch#91 asks for the ruling and the epic's S7 carries the story

- **PKV-016** WHEN the producer publishes a Sigstore bundle for the artifact's provenance statement THE SYSTEM SHALL verify it with the same four checks as the index bundle, bind its subject digest to the locally recomputed tarball hash, and report it as `artifact bundle`; WHILE the trust root marks that plane optional THE SYSTEM SHALL report an absent bundle as `absent`, and WHERE `--require-bundle` is given or the plane is marked required THE SYSTEM SHALL treat absence as `fail`.
  tier:     T1
  verify:   cargo nextest run -p verify artifact_bundle_verified_when_present_absent_policy
  property: status(artifact bundle) = absent ⇒ optional(artifact bundle, root) ∧ ¬require_bundle; required ∧ ∅ ⇒ fail
  - IF the bundle is present and fails any check THEN THE SYSTEM SHALL exit 6 with `artifact bundle: <check>`.
    tier:   T0
    verify: cargo nextest run -p verify artifact_bundle_invalid_exits_6

- **PKV-017** THE SYSTEM SHALL publish, for every artifact a run builds, a Sigstore bundle over a classical DSSE of statement bytes identical to the KMS envelope's, at `<spec_hash>.provenance.sigstore.json` beside the envelope, signed under the same pinned identity as the index, and the sealed map SHALL record the state `bundled` for an entry with both the envelope and the bundle, leaving `signed` meaning envelope-present as before.
  tier:     T1
  verify:   cargo nextest run -p buildbot per_artifact_bundle_statement_bytes_identical
  property: ∀a. statement_bytes(kms_envelope(a)) == statement_bytes(sigstore_dsse(a))

- **PKV-018** WHERE verification is enabled in the client configuration THE SYSTEM SHALL verify, before a remote artifact is accepted at materialization, the index bundle once per registry pin and that artifact's hash and provenance envelope, and SHALL refuse the artifact with the verify error class on any failure.
  tier:     T1
  verify:   cargo nextest run -p rcache materialize_verifies_before_accept
  property: accepted(a) ⇒ index_verified(pin(a)) ∧ hash_ok(a) ∧ provenance_ok(a)
  - IF the artifact's Build Spec Hash is not in the verified index THEN THE SYSTEM SHALL treat it as a cache miss and build locally, as today, raising no verify error.
    tier:   T0
    verify: cargo nextest run -p rcache materialize_miss_builds_locally_under_verification
  - THE SYSTEM SHALL cache the index-bundle result per registry pin for the client's lifetime and SHALL not cache per-artifact results.
    tier:   T0
    verify: cargo nextest run -p rcache materialize_caches_index_result_not_artifact_results
  - IF verification is disabled THEN THE SYSTEM SHALL check only the hash against the index, as today.
    tier:   T0
    verify: cargo nextest run -p rcache materialize_disabled_checks_hash_only

- **PKV-019** WHERE the release ships with verification on by default THE SYSTEM SHALL verify every pull from the public registry as PKV-018 describes unless an explicit configuration line turns it off, and `min doctor` SHALL report when it is off.
  tier:     none
  verify:   none, the default flips only once the vendored root ships in a release and the producer's attestation census reads zero on main (gominimal/build-servers#322), an operator readiness gate the verifier never consults; the epic's S12 tracks the flip

- **PKV-020** THE SYSTEM SHALL document, per artifact type, the object names, the trust-root entries and the exact `cosign` or verifier command that reproduces each check, with a worked example on a live commit, and a daily CI job SHALL run those commands against the current registry head.
  tier:     T0
  verify:   cargo nextest run -p verify docs_commands_match_ci_workflow

## Non-goals

- `min container verify` for OCI archives: its own epic once container builds publish bundles.
- RFC 3161 timestamps and a witnessed transparency log over the KMS envelope: gominimal/build-servers#95 and #96, the epic's stretch story.
- Producing the provenance, the attestation census and its alerts: gominimal/build-servers#75, #322, #329.
- A third, attested-cosigner signature on the envelope: gominimal/build-servers#338; PKV-006's threshold model accepts it without change.
- Computing the Build Spec Hash: gominimal/inbox#583 (spec EPOCH); PKV-003 calls it under the index's declared epoch.
- The SBOM document's content: gominimal/inbox#582 (spec SBOM); PKV-011 only prints it after verification.

## Design reasoning

Two planes, both required by different readers. The architecture describes one plane, Sigstore bundles, because that is the one an auditor with stock tooling can use, and this spec makes it cover every artifact's provenance, binding the artifact by subject digest (PKV-016, PKV-017). The producer's existing KMS envelope is kept as a second plane rather than replaced, for one reason: Sigstore keyless signs with ECDSA only, and the ML-DSA-65 signature is the post-quantum claim. A verifier that dropped the envelope would lose the only PQ signature; a verifier that dropped the bundle would keep auditors dependent on Minimal tooling. The role policy (PKV-006) is how a caller says which planes they need.

The index first, always. Every other check keys on the Cache Index: the Build Spec Hash it maps, the epoch it declares, the content hash it names. Verifying the index bundle before reading an entry (PKV-001) is what makes the rest of the chain rest on a signature rather than on a bucket listing, and it is the host path D3 already draws.

Byte-exact PAE and raw bytes (PKV-005, PKV-007). The single most likely correctness defect in a DSSE verifier is re-canonicalising the payload before hashing; the requirement names the encoding so the test can lock it. Keys and signatures are stored raw because encodings for post-quantum keys have moved while the FIPS 204 bytes have not; a trust root of raw bytes survives a crypto-library migration.

Threshold over distinct keys, never first-valid (PKV-006). A first-valid rule lets one accepted signature carry an envelope; a count-based threshold lets two classical keys satisfy "classical plus PQ". Roles say what a policy means.

Fail closed on absence (PKV-009, PKV-012). The producer falls back to an unsigned `.intoto.json` when a signer errors; a verifier that accepted it would turn a signing outage into an unsigned artifact that passes. `absent` exists in the output only for a plane the trust root itself marks optional, so the policy is data, not a flag a caller forgets.

The trust root is vendored and append-only (PKV-013, PKV-014). The release the user already verifies at update time carries the signers, so a stock install verifies offline and makes no first-use trust decision; a rotation appends an entry with its window, so historical artifacts keep verifying; for the KMS plane the window is checked against a build time the same key signed, which is honest only once an external timestamp covers the envelope (gominimal/build-servers#95), and the spec says so rather than claim a rotation the plane cannot yet enforce. The well-known URL the architecture names is the next step (PKV-015) and waits on the meta-key ruling, because a published root with no pinned meta-key is a trust-on-first-use gap.

Where the verifier lives. The architecture says `min` performs the checks; `min` is public and the producer's repository is private, so the format types and the verifier move into the public repository and the producer depends on them, which is also the only way the two stay byte-compatible. The existing producer-side verifier's tests move with it (PKV-010).

**Generality:** a second registry with its own signers is a second trust root (`--trusted-root`), not a code change; a second signing plane is a new role; a second index format would change PKV-003's key computation only. What would not fit is a registry whose index is unsigned, and that is by design.

## Security considerations

- **Invariant:** WHILE verification is enabled THE SYSTEM SHALL accept an artifact only when its locally recomputed hash equals the entry of a Cache Index whose bundle verified against the trust root.
  enforced by: PKV-001 before any entry read; PKV-003's comparison over recomputed bytes and index only
  covered by: PKV-001, PKV-002, PKV-003
- **Invariant:** THE SYSTEM SHALL accept a provenance statement only when a pinned key of every required role verified a signature over the byte-exact PAE of that statement.
  enforced by: PKV-005's encoding, PKV-006's threshold, PKV-013's key selection by algorithm and window
  covered by: PKV-005, PKV-006, PKV-007, PKV-013
- **Invariant:** THE SYSTEM SHALL bind every accepted statement to the artifact by subject digest, never by object name.
  enforced by: PKV-008's subject match over the recomputed hash
  covered by: PKV-008
- **Invariant:** WHILE verification is enabled THE SYSTEM SHALL fail closed when a signature or bundle the policy requires is absent.
  enforced by: PKV-009, PKV-012's `absent` semantics, PKV-016's policy
  covered by: PKV-009, PKV-012, PKV-016
- **Invariant:** THE SYSTEM SHALL reject an envelope carrying more than 8 signatures before verifying any of them.
  enforced by: PKV-004's cap before the verify loop
  covered by: PKV-004

## Open questions

- [NEEDS CLARIFICATION (HIGH): the well-known trust-root URL and the custody of the meta-key that signs it. architecture.md "What verified means" names the published list and the pinning in `min`; it does not name the URL, the key, or who rotates it. PKV-015 waits on gominimal/arch#91.]
- [NEEDS CLARIFICATION (MEDIUM): whether the architecture's "What verified means" should state the post-quantum plane explicitly. This spec treats the KMS ML-DSA-65 signature as a permanent second plane; the architecture text describes Sigstore only. Asked in gominimal/arch#91.]
- [NEEDS CLARIFICATION (LOW): the crate name in the public repository for the verifier the producer will depend on. `verify` is assumed in the `verify:` lines and changes nothing else.]
