---
id: spec-minimal-verify
title: minimal verify: consumer-side SLSA provenance verification for cache-pulled artifacts
kind: spec
status: planned
tracking-issue: 380
---

# minimal verify: consumer-side SLSA provenance verification for cache-pulled artifacts

## Context

The build-servers system currently signs SLSA Provenance v1 attestations for every artifact, producing 492 signed `.intoto.jsonl` DSSE envelopes with dual signatures (classical ECDSA-P256 + post-quantum ML-DSA-65). These attestations exist in production but are not yet consumed. This creates a verification gap: artifacts are signed but never cryptographically verified before use.

This spec defines the consumer-side verification component that closes the gap, enabling cryptographic verification of artifact provenance before trust. It is the blocking prerequisite for transparency layers (RFC3161 timestamps, witnessed Merkle logs) referenced in build-servers#95, #96, and #86, since those layers depend on envelope authenticity (L0) being established first.

**Existing codebase context (informed by Serena baseline):**
- `rcache` already implements SHA-256 hash verification of artifacts against the cache index
- No DSSE, in-toto, or SLSA verification code exists in this repository
- The unpublished `attest/` prototype mentioned in the issue uses a single-signature, non-DSSE model and is explicitly marked for non-reuse
- `sha2` is already a workspace dependency; crypto verification is greenfield

## Introduction

This specification defines a new `minimal-verify` crate that implements SLSA provenance verification for cache-pulled artifacts. The crate will:

1. Parse DSSE envelopes containing in-toto SLSA Provenance v1 statements
2. Verify dual signatures (ECDSA-P256 + ML-DSA-65) using `aws-lc-rs`
3. Bind artifact digests to locally recomputed hashes (the core security gate)
4. Enforce expectations against provenance metadata (builder ID, source parameters)
5. Expose verification through a `minimal verify` CLI command
6. Provide hooks for future rcache integration with verify-on-pull

## Goals

1. Enable cryptographic verification of SLSA provenance attestations for artifacts
2. Support dual-signature verification (classical + post-quantum) with role-based policies
3. Provide byte-exact PAE recomputation matching the producer implementation
4. Implement secure subject-digest binding using constant-time comparison
5. Expose verification via a `minimal verify` CLI subcommand
6. Lay foundation for future transparency layers (L1 timestamps, L2 log inclusion)
7. Use aws-lc-rs as the consolidated cryptographic backend

## User Stories

**As a minimal user**, I want to cryptographically verify that a cache-pulled artifact was built by build-servers from the expected source commit, so I can trust the artifact's provenance before execution.

**As a minimal developer**, I want the verifier to fail closed on any missing or invalid attestation, so security properties are enforced by default.

**As a security engineer**, I want both classical and post-quantum signature verification, so the system remains secure across cryptographic paradigm shifts.

**As a maintainer**, I want verification integrated into rcache's pull path (future), so provenance checks happen automatically rather than requiring manual invocation.

## Demoable Units of Work

### Unit 1: DSSE Envelope Parser and PAE

Parse `.intoto.jsonl` DSSE envelopes and recompute the Pre-Authentication Encoding (PAE) byte-exactly as the producer does.

**Requirements:**

**R1.1** Parse `.intoto.jsonl` line-by-line, decoding each line as a DSSE `Envelope` with `payload` (base64), `payloadType`, and `signatures[]` fields

**R1.2** Implement strict `deny_unknown_fields` on `Envelope` and `Sig` structures to reject unauthenticated algorithm fields

**R1.3** Enforce `MAX_SIGNATURES` cap (8) before the verify loop to prevent DoS via envelope with thousands of signatures

**R1.4** Reject zero-signature envelopes and blank lines; fail closed when `.intoto.jsonl` is absent

**R1.5** Recompute PAE as `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` where body is the base64-decoded raw payload bytes (not re-canonicalized JSON)

**Proof Artifacts:**

1. **Test**: Unit test `test_pae_lock_vectors()` verifying `pae("application/vnd.in-toto+json", b"hi") == b"DSSEv1 28 application/vnd.in-toto+json 2 hi"` and `pae("t", b"") == b"DSSEv1 1 t 0 "` (ported from producer)

2. **Test**: Unit test `test_envelope_parse_rejects_unknown_fields()` asserting that an envelope with an extra `{"algorithm": "..."}` field in `signatures[]` returns a parse error

3. **Test**: Unit test `test_max_signatures_enforced()` asserting that an envelope with 9 signatures is rejected before any cryptographic operation

### Unit 2: Cryptographic Verification Backends

Implement ECDSA-P256-SHA256 and ML-DSA-65 signature verification using `aws-lc-rs`, abstracted behind a `PqVerify` trait for future backend swaps.

**Requirements:**

**R2.1** Add `aws-lc-rs = { version = "=1.17.x", features = ["unstable"] }` as an exact-pinned dependency

**R2.2** Implement `verify_ecdsa_p256(public_key, pae, der_sig)` using `aws_lc_rs::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk).verify(pae, der_sig)`

**R2.3** Implement `verify_mldsa65(public_key, pae, raw_sig)` using `aws_lc_rs::unstable::signature::ML_DSA_65` with pure (non-pre-hash) mode and empty context

**R2.4** Define `PqVerify` trait with a single `verify(pae, sig)` method, implemented by both ECDSA and ML-DSA backends

**R2.5** Store raw key bytes (1952 bytes for ML-DSA public keys, not DER-wrapped) and raw signature bytes (3309 bytes for ML-DSA) to remain backend-agnostic

**Proof Artifacts:**

1. **Test**: Wycheproof test vector suite for ECDSA-P256-SHA256 verification, asserting known-good signatures verify and known-bad signatures fail

2. **Test**: ACVP or FIPS-204 known-answer test vectors for ML-DSA-65 verification, asserting the verifier produces expected results on standard test cases

3. **Test**: Negative test asserting that a modified PAE (single bit flip) causes verification to fail for both ECDSA and ML-DSA signatures

### Unit 3: in-toto Statement Parsing and Subject Binding

Parse the DSSE payload as an in-toto Statement, validate the SLSA Provenance v1 predicate, and bind the subject digest to a locally recomputed artifact hash.

**Requirements:**

**R3.1** Decode the base64 payload to JSON and parse as in-toto Statement v1, validating `_type == "https://in-toto.io/Statement/v1"` and `predicateType == "https://slsa.dev/provenance/v1"`

**R3.2** Implement subject-digest binding: recompute the artifact's SHA-256 locally and constant-time-compare against `subject[].digest.sha256` from the signed statement

**R3.3** Validate `subject[].digest.minimal_spec_hash` matches the expected spec hash passed by the caller

**R3.4** Extract and validate expectations: `predicate.runDetails.builder.id == "https://github.com/gominimal/build-servers"` and `externalParameters.{repo, commit, package, arch}` match caller-supplied values

**R3.5** Declare `ExternalParameters` struct with exactly four fields (`repo`, `commit`, `package`, `arch`) plus `deny_unknown_fields` to match the producer's wire format

**Proof Artifacts:**

1. **Test**: Round-trip corpus test verifying a set of real production `.intoto.jsonl` envelopes, asserting all expectations (`repo`, `commit`, `package`, `arch`) round-trip correctly

2. **Test**: Unit test `test_subject_binding_fails_on_mismatch()` asserting that verification fails when the locally recomputed artifact hash differs from `subject[].digest.sha256` by a single bit

3. **CLI**: Command `minimal verify --spec-hash <prod-hash> --source-uri https://github.com/gominimal/minimal --source-commit <commit> --package <pkg> --arch <arch>` run against a known-good production artifact, exiting 0 and printing decoded provenance with `--print-provenance`

### Unit 4: Trust Root and Multi-Signature Role Policy

Define a unified trust root carrying pinned public keys with role metadata, and enforce threshold policies over distinct verified keys.

**Requirements:**

**R4.1** Define `TrustedRoot` structure containing `artifactKeys` array with fields `{keyId, algo, role, publicKey (raw bytes), validFor (time window)}`

**R4.2** Implement `RolePolicy` enum with `Default` (≥1 valid signature from any trusted key) and `RequirePq` (the ML-DSA role must specifically verify)

**R4.3** Enforce threshold over distinct accepted **keys**, not raw signature count; skip failed signatures and count distinct keys that passed

**R4.4** Use `keyid` from envelope only to narrow candidate keys; trust is driven solely by the pinned root, never unauthenticated wire metadata

**R4.5** Vendor the trust root offline in v1 (baked into the signed `minimal` release); do not implement `.well-known` fetching without a meta-key

**Proof Artifacts:**

1. **Test**: Unit test `test_role_policy_default()` asserting that verification succeeds when one ECDSA signature verifies, even if the ML-DSA signature is absent or invalid

2. **Test**: Unit test `test_role_policy_require_pq()` asserting that verification fails with `RolePolicy::RequirePq` when ECDSA verifies but ML-DSA does not

3. **File**: Trust root JSON file `minimal-verify/trust-root.json` committed to the repository with at least two keys (one ECDSA, one ML-DSA) and passing schema validation

### Unit 5: Layered Verification Driver (L0 → L1 → L2 hooks)

Implement the gated L0 → L1 → L2 verification flow, where L0 (envelope authenticity) gates L1 (timestamp) and L2 (log inclusion), with L1/L2 stubbed in v1.

**Requirements:**

**R5.1** Implement `verify_envelope()` as the L0 entry point: fetch `.intoto.jsonl`, verify signatures, parse statement, bind subject, check expectations

**R5.2** Define `VerifiedStatement` result type carrying the parsed provenance and confidence level

**R5.3** Implement confidence reporting: distinguish "layer absent" (degraded, fail-open with warning) from "present-but-invalid" (attack, fail-closed)

**R5.4** Add L1 and L2 hook points with stub implementations that log "not yet implemented" and degrade gracefully

**R5.5** Document the gating contract: L1 timestamp verification and L2 log inclusion checks are only meaningful after L0 passes

**Proof Artifacts:**

1. **Test**: Integration test `test_l0_gates_l1_l2()` asserting that when L0 fails (invalid signature), L1 and L2 hooks are never called

2. **Test**: Unit test `test_absent_layer_degrades_gracefully()` asserting that a missing `.tsr` file (L1) logs a warning but does not fail verification when L0 passes

3. **CLI**: Command `minimal verify --spec-hash <hash> --source-uri <uri> --source-commit <commit> --package <pkg> --arch <arch> --json` produces JSON output with `{"l0": "pass", "l1": "not_implemented", "l2": "not_implemented", "confidence": "medium"}` structure

### Unit 6: CLI Integration and Expectations Handling

Expose verification through a `minimal verify` subcommand with options for expectations, trust root path, policy, and output format.

**Requirements:**

**R6.1** Add `cmd_verify.rs` to `crates/minimal/src/` implementing the `verify` subcommand

**R6.2** Support `minimal verify [@<spec>]` shorthand to resolve spec → spec_hash → fetch + verify

**R6.3** Accept `--spec-hash`, `--trusted-root`, `--builder-id`, `--source-uri`, `--source-commit`, `--package`, `--arch`, `--require-pq`, `--print-provenance`, `--json` flags

**R6.4** Exit with code 0 on successful verification, non-zero on any failure (missing key, signature mismatch, unmet expectation, missing attestation)

**R6.5** Default `--trusted-root` to the vendored root; allow override for testing or future `.well-known` integration

**Proof Artifacts:**

1. **CLI**: `minimal verify --help` lists all supported flags with descriptions and exits 0

2. **CLI**: `minimal verify --spec-hash <known-good-hash> --source-uri https://github.com/gominimal/minimal --source-commit <commit> --package <pkg> --arch <arch>` run against a production artifact with valid attestation exits 0

3. **CLI**: `minimal verify --spec-hash <hash> --source-uri https://github.com/gominimal/minimal --source-commit <wrong-commit> --package <pkg> --arch <arch>` run against a production artifact exits non-zero and prints expectation mismatch error

## Non-Goals

1. **Retrofitting the attest/ prototype** — The existing single-signature, non-DSSE `AttestationBundle` is explicitly not reused; this is greenfield work

2. **Auto-verify on pull in rcache (v1)** — Integration into `rcache::materialize` with `--verify` flag is deferred to a follow-up; this spec delivers an explicit CLI command only

3. **L1 (timestamp) and L2 (log inclusion) verification** — These layers are stubbed with hooks; full implementation is tracked in build-servers#95, #96, #86

4. **`.well-known` trust root fetching** — The trust root is vendored offline in v1; serving it from `.well-known` requires a meta-key to avoid TOFU gaps

5. **FIPS-mode cryptography** — `aws-lc-rs` `fips` feature is explicitly kept OFF; the unstable ML-DSA surface is cfg'd out under fips, causing build failures

6. **Branch filtering in expectations** — There is no `branch` field in the producer's wire format; `--source-branch` flag is not offered

## Design Considerations

### Choice of `aws-lc-rs unstable` for ML-DSA verification

The issue proposes `aws-lc-rs` with the `unstable` feature for ML-DSA-65 verification, reversing an earlier framing toward `libcrux-ml-dsa`. This decision merits architecture-record treatment (see linked `architecture.md`), but the key rationale is:

- **`unstable` means API stability, not code immaturity** — the implementation is `mldsa-native`, the same code in AWS-LC's FIPS module and in AWS KMS
- **We already depend on `aws-lc-rs` for ECDSA** — this consolidates to one audited crypto library, one CVE feed
- **`libcrux-ml-dsa` had a real track-record knock** — v0.0.3 silently produced different signatures across platforms (unverified SHA-3 fallback)
- **RustCrypto `ml-dsa` shipped a verify-soundness CVE** (GHSA-5x2r-hc65-25f9, accepting non-canonical signatures)
- **Precedent:** `rustls` gates ML-DSA behind `aws-lc-rs-unstable` for this exact use case

The cost is bounded: stabilization is CMVP-gated with no firm date, and when it lands the API will move. Mitigations:
1. Pin `=1.17.x` exactly (never `^`)
2. Store raw key+sig bytes (backend-agnostic)
3. Abstract verify behind `PqVerify` trait (one-file swap)
4. Gate every upgrade behind Wycheproof/ACVP vectors + production corpus round-trip
5. Keep `fips` feature OFF (unstable surface is cfg'd out)

Documented escape hatch: `libcrux-ml-dsa` and `fips204` behind the same trait, swappable if churn ever bites.

### PAE Byte-Exactness

The PAE (Pre-Authentication Encoding) is `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` where body is the **base64-decoded raw payload bytes**, NOT the base64 string and NOT re-canonicalized JSON. This is the single most likely correctness bug and would silently fail every verification. The implementation is a verbatim port of the producer's `dsse::pae()` function with lock tests ported from the producer's test suite.

### Subject-Digest Binding as the Core Security Gate

The load-bearing security property is binding the signed subject digest to a locally recomputed artifact hash using constant-time comparison. This prevents accepting an attestation for artifact A when verifying artifact B. Filename and bucket metadata are never trusted — they are attacker-influenceable in a public bucket with `allUsers:objectViewer`. The binding comes solely from the signed subject and local recomputation.

### Fail-Closed on Missing Attestations

When `.intoto.jsonl` is absent, verification fails. The producer falls back to legacy unsigned `.intoto.json` when a signer errors; a missing `.intoto.jsonl` means "no signed attestation exists" — L0 cannot pass on the unsigned fallback.

## Repository Standards

- **Error handling:** Follow ADR 0001 — `thiserror` for the library crate, `anyhow` in the CLI integration (informed by ADR 0001)
- **Dependency pinning:** Pin `aws-lc-rs = "=1.17.x"` exactly to control upgrade timing
- **Commit conventions:** Conventional commits (`feat(minimal-verify):`, `test(minimal-verify):`)
- **Testing:** All proof artifacts must pass before merge
- **Documentation:** Inline doc comments for all public types and the `PqVerify` trait

## Open Questions

None. The implementation path is clear and all design decisions are either settled in the issue or deferred to follow-up work (L1/L2, rcache integration, `.well-known` root).

## Technical Considerations

### Module Structure

```
minimal/crates/minimal-verify/src/
  envelope.rs   // Envelope, Sig, JSONL line parse, pae()
  statement.rs  // in-toto Statement v1 / SLSA Provenance v1 types
  trust.rs      // TrustedRoot, TrustedKey, RolePolicy
  crypto.rs     // PqVerify trait + aws-lc-rs ECDSA/ML-DSA backends
  verify.rs     // verify_envelope() entry point, steps 2-6
  layered.rs    // L0 → L1 → L2 driver + confidence reporting
```

### Type Safety

- Use `deny_unknown_fields` on `Envelope`, `Sig`, and `ExternalParameters` to reject wire-supplied fields that could bypass security checks
- Never trust unauthenticated `keyid` or `algorithm` fields — algorithm is inferred from the pinned trust root
- Store raw bytes for keys and signatures to remain encoding-agnostic across potential backend swaps

### Performance Considerations

- Enforce `MAX_SIGNATURES = 8` cap before the verify loop to prevent DoS via envelopes with thousands of signatures (legitimate count is 2)
- ML-DSA verification is ~100x slower than ECDSA but still sub-millisecond; not a bottleneck for single-artifact verification
- Future rcache integration may batch-verify multiple artifacts; defer optimization until profiling shows need

### Upgrade Safety

Every `aws-lc-rs` upgrade must pass:
1. Round-trip verification of a corpus of real production `.intoto.jsonl` envelopes (all expectations round-trip correctly)
2. Wycheproof and ACVP/FIPS-204 known-answer + negative test vectors for both ECDSA and ML-DSA
3. CI early-warning (allow-fail) job testing against a newer aws-lc-rs version to detect API moves before a forced CVE upgrade

## Security Considerations

### Trust Model

- Trust is rooted in the pinned `TrustedRoot`, never in unauthenticated wire metadata
- The `keyid` field from the envelope only narrows candidate keys; it does not establish trust
- A signature verifying against a key not in the trust root is rejected

### Threat Model

- **Attacker serves a valid attestation for artifact A when the user requests artifact B** — mitigated by subject-digest binding with constant-time comparison to locally recomputed hash
- **Attacker serves thousands of signatures in an envelope to DoS the verifier** — mitigated by `MAX_SIGNATURES` cap before the verify loop
- **Attacker exploits a soundness bug in ML-DSA verification** — mitigated by Wycheproof/ACVP test vectors gating every crypto library upgrade
- **TOFU gap in `.well-known` trust root fetching** — mitigated by vendoring the root offline in v1; `.well-known` requires a meta-key first

### Cryptographic Agility

The system supports dual-signature verification (ECDSA + ML-DSA) to remain secure across cryptographic paradigm shifts. The `PqVerify` trait allows swapping backends without changing the verification logic.

### Constant-Time Operations

Subject-digest comparison uses constant-time comparison as defense-in-depth. While both operands are public (the signed subject and the local hash are not secret), constant-time comparison prevents timing side-channels from leaking information about hash differences.

## Verification

All proof artifacts enumerated in the Demoable Units section must pass. Key integration points:

1. **Producer-consumer PAE lock test alignment** — the PAE implementation is ported verbatim from the producer with the same test vectors
2. **Production envelope round-trip** — a corpus of real `.intoto.jsonl` files from the production cache verifies successfully
3. **Wycheproof/ACVP vectors for both algorithms** — standard test suites for ECDSA-P256 and ML-DSA-65 pass
4. **CLI smoke test** — `minimal verify` against a known-good production artifact exits 0

## References

- DSSE protocol / PAE — https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- in-toto Statement v1 — https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- SLSA verifying artifacts — https://slsa.dev/spec/v1.0/verifying-artifacts
- aws-lc-rs ML-DSA (unstable) — https://docs.rs/aws-lc-rs/latest/aws_lc_rs/unstable/signature/index.html
- FIPS-204 (ML-DSA) — https://csrc.nist.gov/pubs/fips/204/final
- Producer implementation (private, build-servers) — `crates/buildbot/src/{dsse,signer,provenance}.rs`
- Sibling issues — build-servers#75 (SLSA L3 epic), #95 (RFC3161), #96 (witnessed log), #86 (verifiable cache index)
