---
id: "TBD"
title: "S5: R2 cache-materialization latency from inside a CF Container"
status: in-progress
date: 2026-07-25
budget_hours: 4
actual_hours: 1
progress: "rcache-reuse mechanism CODE-VERIFIED: new_over_https + R2-custom-domain read already exist (plan under-credited); TWO plan corrections found — keying is SpecHash→index→sha256 (not raw Blake3), and the base-URL+join reader can't consume per-object presigned URLs (use an Access-gated custom domain for Cache A). Latency + closure-exec still live-gated."
related:
  - "plan: /home/.claude/plans/look-at-the-lessons-silly-stallman.md (Phase 0, S5)"
  - "sibling: norrietaylor/minimal-sessions docs/specs/11-r2-build-cache.md"
  - "sibling: norrietaylor/minimal-sessions docs/adr/0013-r2-cache-partition-strategy.md"
  - "sibling: norrietaylor/minimal-sessions docs/patterns/failure/loader-libc-version-coupling.md"
  - "crates/rcache (RemoteCache::new_over_https), crates/common (SpecHash/Blake3)"
tags:
  - cloudflare
  - remote-provider
  - r2
  - rcache
  - cold-start
  - de-risk
---

# Question

From inside a Cloudflare Container, is **lazy per-package** materialization of the
content-addressed cache (many small `<sha256>.zst` GETs — see the keying correction
in Findings; keyed by artifact sha256 via the `index.shisha` translation, **not**
`<spec_hash>`) fast enough for an acceptable cold-session UX — and is eager
whole-cache restore as bad as the sibling measured (a 500 MB monolith at 3.5–17 s)?
Separately: is the glibc loader/libc coupling handled for materialized closures?

# Hypothesis

Lazy per-package content-addressed GETs (keyed by artifact **sha256** resolved
through the index — corrected from "Blake3-keyed") amortize acceptably (fetch only
what a session touches, dedup for free across sessions); eager whole-cache restore
does not and must be avoided. With Cache A **pre-warmed**, cold-session
materialization lands within budget. The loader coupling is real (closures built
against newer glibc can segfault silently, exit 139, under the CF base loader) and
must be handled by pairing loader+libs per binary (patchelf `ld.so` + `DT_RPATH
--force-rpath` across all mirrored FHS dirs).

# Method

1. In a CF Container, point `RemoteCache::new_over_https` at Cache A. **[Corrected —
   see Findings]** Cache A is an **Access-gated R2 custom domain** (base-URL +
   `join` reader), **not** a Worker presign endpoint: the existing `FetchUrl` reader
   cannot consume per-object presigned URLs. Presigning is exercised only for the
   single-object Cache B path. The Worker never proxies bytes either way.
2. Time (a) N small `<sha256>.zst` GET+decompress operations for a real
   session's closure vs (b) one ~500 MB monolith restore; capture p50/p95 and total.
3. Verify a materialized closure **executes**: patchelf the closure's own `ld.so`
   + `DT_RPATH` and confirm no exit-139/segfault under the base-image loader
   (Ubuntu 22.04 / glibc 2.35, or whatever the chosen base ships).
4. Repeat with Cache A pre-warmed vs cold to quantify the pre-warm benefit.

# Gate

**PASS** ⇒ lazy materialization latency is within the agreed cold-session UX budget
(record the number) with Cache A pre-warmed, AND materialized closures run cleanly
⇒ P5 cache reuse is viable as designed. **FAIL** ⇒ if latency blows the budget even
lazily, or the loader coupling can't be resolved per-binary, revise the cache/image
strategy (bake more into the image; reconsider partitioning) before P5.

# Findings

## Code-level pre-verification (2026-07-25, local — no deploy)

Latency and closure-execution are live-gated, but the **rcache-reuse mechanism** is
a set of tree-checkable claims. Verified against `crates/rcache` + `crates/common`,
with three results — one confirmation and **two corrections to the plan**:

### 1. Plain-HTTPS R2 read is already a first-class mode (plan under-credited it) ✓

`RemoteCache::new_over_https(url, index_dir, ot)` exists today
(`crates/rcache/src/remote.rs:130`), builds a reqwest `Client` backend, and the tree
**already documents a Cloudflare R2 custom domain as a supported read backend**
(`crates/common/src/fetchers.rs:271` "a plain-HTTPS mirror (e.g. a Cloudflare R2
custom domain…)"; `:474` "the R2 / mirror base URL must end in `/`";
`remote.rs:216` "an S3-compatible mirror such as a Cloudflare R2 custom domain").
So reading Cache A from R2 over plain HTTPS is **near-zero new code** if the bucket
is reachable at a base URL.

### 2. CORRECTION: keying is two-level (SpecHash → index → sha256), NOT "raw Blake3 SpecHash, zero translation"

The plan (and this stub's earlier framing) said Cache A is "keyed **directly** by the
32-byte Blake3 `SpecHash`, zero key translation." The tree says otherwise:

- `SpecHash` is `SpecHash(pub blake3::Hash)` — a raw 32-byte Blake3, confirmed
  (`crates/common/src/spec_hash.rs:9`, `from_bytes([u8;32])`). But it is the
  **build-graph spec identity**, not the artifact object key.
- The artifact wire key is the artifact's **sha256**, obtained by an **index
  translation**: `RemoteCache::sha256(spec_hash) → index.sha256(spec_hash) → [u8;32]`
  (`remote.rs:466`), then fetched as `base.join("<hex sha256>.zst")`
  (`remote.rs:479`) and verified against that sha256 (`fetch_verified`, `:472`).

Consequence: a Worker **cannot** mint a presigned URL for "the artifact of this
SpecHash" from the SpecHash alone — it (or the client) must first resolve the
`index.shisha` object to get the sha256. Dedup is still free and cross-session, but
it is **content-addressing by artifact sha256 via an index**, not direct Blake3
keying. The plan's P5 wording should be corrected (action item below).

### 3. CORRECTION: the reader is base-URL + `join(object)` — per-object presigned URLs don't fit it

`FetchUrl` (`crates/common/src/fetchers.rs:93`) is exactly `fn join(&self, &str) ->
Self` + `fn filename()`; every fetch is `base.join(object_key)` (index at
`remote.rs:359`, artifacts at `:479`). A **presigned** URL carries a per-object SigV4
signature in its query string — you cannot derive object B's presigned URL by
`join()`-ing onto object A's base. So the plan's "guest touches R2 only via
Worker-minted ~300 s presigned URLs" is **incompatible with the current reader** for
the many-small-objects Cache A path. Two ways out, and the second is likely better:

- (a) a **new `FetchBackend`/`FetchUrl`** whose `join` resolves to a freshly-minted
  presigned URL per object (a resolver hook, not string concat) — real new code; or
- (b) front Cache A with a **Cloudflare Access / signed-cookie-gated R2 custom
  domain**: keeps the existing `new_over_https` + base-join reader **unchanged**,
  authenticates at the edge, and still honors the plan's "Worker never proxies
  bytes" rule. Per-object presigning then applies only to **Cache B** (a single
  per-session `/workspace` object, where per-object presign fits cleanly).

## Live-gated remainder (still TBD — requires deploy)

The actual gate: lazy-vs-monolith materialization latency (p50/p95, warm vs cold
Cache A), and that a materialized closure **executes** under the CF base loader
(the patchelf `ld.so` + `DT_RPATH --force-rpath` recipe). These need a live CF
Container + R2 bucket and cannot be produced locally.

# Conclusion

The "rcache reuses verbatim" claim is **true for the reader-over-HTTPS shape**
(`new_over_https` + R2 custom domain already exist), but the plan's *keying* and
*presigned-URL* mechanics are wrong in detail: keys are two-level
(SpecHash→index→sha256, object key = sha256), and the base-URL+`join` reader cannot
consume per-object presigned URLs. Recommended Cache-A design: Access-gated R2
custom domain (existing reader, no per-object presign), reserving presigned URLs for
the single-object Cache B. Latency remains the one true live gate.

# Action items

- [ ] Correct the plan's P5 + Target-architecture wording: Cache A is content-keyed
      by artifact **sha256 via the `index.shisha` translation**, not "directly by
      the 32-byte Blake3 SpecHash / zero translation."
- [ ] Decide Cache-A auth: **Access-gated R2 custom domain** (keeps the base-URL +
      `join` reader; recommended) vs a new presign-resolving `FetchBackend`.
- [ ] Reserve per-object presigned URLs for **Cache B** (single per-session object).
- [ ] Live: run the materialization latency table + closure-execution/loader check.

# Residual Risks / Live Trial Needed

- Requires live CF Container + R2 bucket + Worker presign endpoint.
- Two SEPARATE buckets — Cache A (shared, non-secret, raw-Blake3-keyed) vs Cache B
  (secret per-session workspace) — must never be crossed; S5 exercises Cache A only.
- Confirm CF container hosts are x86-64-v3 (AVX2) capable if any cached binaries are
  `-march=x86-64-v3` (sibling R-034).

# Artifacts

_TBD — presign Worker, materialization timing script, patchelf recipe, raw logs._
