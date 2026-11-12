---
id: 3323
title: "How the proxy reaches the TPM (T127)"
status: proved
date: 2026-11-12
budget_hours: 16
actual_hours: 3
related:
  - "issue #3323 (this experiment, T127 of the box egress proxy plan)"
  - "issue #1501 (BEP epic)"
  - "issue #3322 (S18: Linux hosts hold the proxy's keys)"
  - "issue #3324 (T128: hold the proxy's keys in the TPM), which waits on this record"
  - "issue #3326 (T129: refuse a TPM key the proxy cannot load)"
  - "issue #2436 (the custody experiment on a TPM 2.0 host)"
  - "docs/specs/24-spec-box-egress-proxy/24-spec-box-egress-proxy.md (BEP-088, BEP-089)"
tags:
  - bep
  - tpm
  - linux
  - keys
---

# Question

The proxy's Linux key store holds each key in the TPM (BEP-088). It can
reach the TPM in two ways:

- the `tss-esapi` crate, which links the `tpm2-tss` C libraries into `bep`
- the `tpm2-tools` commands, which `bep` runs as child processes, as it runs
  `secret-tool` for the sign-in

Which one does the key store use? The answer depends on four costs:

1. Does `tss-esapi` build where `bep` builds: the agent runner, the musl
   cross image (`just test-cross`), and the static musl release binary?
2. What does a host need at run time for `tpm2-tools`?
3. How long does one ECDSA signature and one ECDH take through each?
4. Can the key store tell a key that can come back from a key that is lost
   (BEP-089) through each?

# Hypothesis

`tss-esapi` is faster and gives typed errors, but its C libraries do not
build in the places `bep` builds today. `tpm2-tools` builds everywhere, and
costs a process start for each key use.

# Method

**Hosts.** The first host is Lima on Apple silicon. It runs Ubuntu 25.10 on
arm64, with `tpm2-tss` 4.1.3 and `tpm2-tools` 5.7. Its TPM is `swtpm` 0.7.3
behind the kernel's `tpm_vtpm_proxy`. The bench reaches it as
`device:/dev/tpmrm0`, through the kernel's resource manager. The second TPM is a fresh `swtpm` reached over TCP
(`swtpm:host=localhost,port=2331`), as the CI job `bep-tpm-integration`
reaches it. That TCTI has no resource manager. No hardware TPM was in reach,
so no number below is a hardware number.

**Keys.** Every key is P-256, under an ECC storage key in the owner
hierarchy. Each has `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`,
`userWithAuth` and `noDA`. Each has a 128-bit authorization value from the
OS CSPRNG. One key signs (ECDSA, SHA-256), one agrees (ECDH).

**Timings.** Each figure is the median and p90 of 20 runs, in these cases:

- *Key in use*: the TPM holds the key, or a saved context of it exists, and
  the store signs or agrees once.
- *From blob*: a process that just started creates the storage key, loads
  the key blob, and signs or agrees once. A proxy pays this at start, and
  after the TPM resets, because a TPM reset voids a saved context.

**Checks.** Each run checks the signature with OpenSSL or `p256`. It
compares the ECDH result with the result from OpenSSL or `p256`. It reads
the key's attributes back from the TPM. Last, it tries a wrong
authorization, which the TPM must refuse.

**Builds.** The bench used `tss-esapi` 7.7.0, the current release. The
experiment built it in these ways:

- a glibc build in Lima, against Ubuntu's `libtss2-dev`
- a static musl build on Alpine 3.22, against Alpine's `tpm2-tss-static`
- a static musl build against a `tpm2-tss` 4.1.3 from source, configured
  with `--enable-nodl`

The record also reads the musl cross image's base, the agent runner's package set, and
the Linux release job.

The scripts and the bench crate are in
[`2026-11-13-bep-tpm-interface/`](2026-11-13-bep-tpm-interface/).

# Findings

## 1. Both interfaces meet the custody checks

Through both, OpenSSL or `p256` accepts the signature, and the ECDH result
is equal to a software computation of it. The TPM reports `fixedTPM`, `fixedParent` and `noDA` on
both keys, and refuses a wrong authorization with `TPM_RC_AUTH_FAIL`
(`0x9a2`). The TPM refuses `tpm2_duplicate` too. A plain duplicate also needs a
policy session, so that refusal does not prove `fixedParent` on its own. The
attributes the TPM reports do.

## 2. Time per key use

| case | `tpm2-tools`, Lima TPM | `tss-esapi`, Lima TPM | `tpm2-tools`, `swtpm` TCP | `tss-esapi`, `swtpm` TCP |
|---|---|---|---|---|
| ECDSA, key in use | 36.4 ms (p90 40.7) | 11.3 ms (p90 11.4) | 19.8 ms (p90 21.5) | 0.4 ms (p90 0.5) |
| ECDH, key in use | 25.1 ms (p90 27.9) | 11.3 ms (p90 11.5) | 19.5 ms (p90 20.8) | 0.4 ms (p90 0.4) |
| ECDSA, from blob | 126.0 ms (p90 130.2) | 29.0 ms (p90 29.5) | 62.7 ms (p90 66.4) | 2.4 ms (p90 2.6) |
| ECDH, from blob | 110.3 ms (p90 115.5) | 29.1 ms (p90 33.5) | 62.9 ms (p90 65.7) | 2.4 ms (p90 2.6) |
| start a process or a context | 7.9 ms | 1.0 ms | 14.8 ms | 0.3 ms |

In Lima, each TPM command costs about 11 ms through `tpm_vtpm_proxy`, which
is why `tss-esapi` takes 11 ms there and 0.4 ms over TCP. `tpm2-tools` adds
14 ms to 25 ms per key use on top of that: a process start, a context load,
and the flushes. The `swtpm` TCP column for `tpm2-tools` includes three
`tpm2_flushcontext` runs after each command (finding 5).

A hardware TPM is slower than both. That narrows the gap in proportion, but
it was not measured.

**What this costs the proxy.** The proxy signs once for each leaf
certificate, and it caches each leaf's server configuration
(`crates/bep/src/proxy.rs`, `servers`), so signing is off the hot path. It
agrees once for each sealed value it redeems (`crates/bep/src/redeemer.rs`
calls `seal::open_held`), and it caches no opened value. So through
`tpm2-tools`, each request with a sealed value in it takes about 25 ms
more in Lima. Through `tss-esapi`, it takes 11 ms more.

## 3. `tss-esapi` does not build where `bep` builds today

| where | `tss-esapi` | `tpm2-tools` |
|---|---|---|
| ci-linux-native (glibc) | builds with `libtss2-dev`, which only the `bep-tpm-integration` job installs | nothing at build time |
| agent runner | does not build. The runner builds in a Minimal sandbox from `.minimal/minimal.toml`, and `gominimal/pkgs` has no `tpm2-tss` package | nothing at build time |
| musl cross image (`just test-cross`) | does not build. The image is Ubuntu 20.04 with no `tpm2-tss` and no OpenSSL for the musl target. Its apt has `libtss2-dev` 2.3.2, a glibc build | nothing at build time |
| static musl release | builds only with `tpm2-tss` built from source (finding 4) | nothing at build time |

`tss-esapi` is a build dependency of the `bep` crate on Linux. Every Linux
build of `bep` then needs the `tpm2-tss` headers and libraries. So each of
these places needs a change first:

- a `tpm2-tss` package in `gominimal/pkgs`
- a `Cross.toml` pre-build that cross-builds `tpm2-tss` and OpenSSL for musl
- `libtss2-dev` in every ci-linux-native job, which is a frozen workflow
- a `tpm2-tss` source build in the release job

A cargo feature can leave the TPM store out of these builds. Then the
store's code compiles in one CI job only.

## 4. A static musl `bep` reaches the TPM only with a hand-built `tpm2-tss`

The Linux release builds static musl binaries
([release pipeline](../internal/release-pipeline.md), "Build jobs"). Three
attempts:

1. **Alpine's `tpm2-tss-static`.** It links. At run time it fails:
   `tctildr` loads each TCTI with `dlopen`, and static musl has none
   ("Dynamic loading not supported", `0xa0015`).
2. **`tpm2-tss` with `--enable-nodl`, with each TCTI.** `--enable-nodl`
   links each TCTI in, in place of `dlopen`. The `tss-esapi-sys` link line
   lists the libraries in an order a static link cannot resolve. So the
   build needs `-Wl,--start-group` and the library list by hand. Then each
   TCTI defines `Tss2_Tcti_Info`, and the device, `swtpm` and `mssim` TCTI
   libraries collide.
   Allowing the duplicate symbol gave a binary that crashed at start.
3. **`--enable-nodl` with the device TCTI only.** It links as `static-pie`
   (8.9 MB) and runs against `/dev/tpmrm0`. It passes the signature, ECDH,
   attribute and wrong-authorization checks. ECDSA and ECDH take 11.1 ms
   with the key in use, and 27.0 ms from the blob.

So a static `bep` reaches only `/dev/tpmrm0`. It cannot reach the `swtpm`
over TCP that CI uses, so CI proves a glibc build with other `tpm2-tss`
libraries than the release puts in `bep`. `tss-esapi` 8.0 has a `bundled` feature
that builds `tpm2-tss` from source. It is an alpha (`8.0.0-alpha.4`) and was
not tried.

## 5. A TPM with no resource manager runs out of slots

`swtpm` over TCP has no resource manager. Without one, a `tpm2-tools`
command leaves the objects and sessions it loaded in the TPM. The third
`tpm2_create` failed with `TPM_RC_OBJECT_MEMORY` (`0x902`), and
`tpm2_ecdhzgen` with "out of memory for session contexts" (`0x903`). A
`tss-esapi` context that held three objects did not create a fourth. The
TPM has three transient slots.

Through `/dev/tpmrm0`, the kernel's resource manager swaps objects out, and
flushes what a process leaves when it exits. So the key store uses
`/dev/tpmrm0`, never `/dev/tpm0`. In CI, the TCP `swtpm` needs one of
these changes:

- The key store flushes after each command.
- The job puts `tpm2-abrmd` in front of `swtpm`.
- The job reaches `swtpm` through `tpm_vtpm_proxy`, as Lima does.


## 6. Only `tss-esapi` tells the failures apart without parsing text

The key store must keep a key the TPM cannot reach now, and name
`bep --replace-key` for a key that is gone (BEP-089). `tpm2-tools` exits
with status 1 for every failure (`tools-errors.sh`):

| failure | exit | what tells it apart |
|---|---|---|
| wrong authorization | 1 | `ErrorCode (0x000009a2)` in the ESYS log line |
| TPM unreachable (`swtpm` down) | 1 | `Tss2_Tcti_Swtpm_Init() Cannot connect` |
| no TPM device | 1 | `Tss2_Tcti_Device_Init() Failed to open` |
| authorization file unreadable | 1 | `Could not open file "<path>" error Permission denied` |
| key file missing | 1 | `Could not open file "<path>" error No such file or directory` |
| key blob damaged | 1 | `ErrorCode (0x000001df)`, `TPM_RC_INTEGRITY` |
| key blob under another storage key | 1 | `ErrorCode (0x000001df)`, the same code |

The key store can tell each case apart, but only from the `tpm2-tss` log
lines on standard error. Those lines are not a stable interface. The key
store can check for a missing or unreadable file before it runs a command.
Then only the TCTI failures and the response code come from standard
error.
`tss-esapi` returns each as a typed error: the TCTI layer apart from the TPM
layer, with the response code as a number.

## 7. The authorization value stays off the command line

`tpm2-tools` reads an authorization value from a file (`-p file:<path>`) or
from standard input (`-p file:-`). Both work in 5.7. A value given as
`-p hex:<value>` is in the process's argument list, which other users of
the host can read. The bench passes `hex:`. The key store must not.

# Conclusion

**The key store reaches the TPM through the `tpm2-tools` commands.**

`tss-esapi` is faster: 11 ms against 25 ms to 36 ms per key use in Lima,
and 0.4 ms against 20 ms over TCP. It also gives typed errors. But today it
does not build where an agent or the release builds `bep`. Each of those
places needs the change that finding 3 lists. The release also needs a
hand-linked, device-only `tpm2-tss`, which CI then does not prove. `tpm2-tools` needs none of that. Its cost is a process start for
each key use, about 25 ms for each redeemed sealed value in Lima, and
error sorting by text.

Revisit the choice in two cases. The first is a hardware TPM that shows
the per-use time is too slow. The second is a release of `tss-esapi` 8.0
whose `bundled` build links statically.

# Action items

For T128 ([#3324](https://github.com/gominimal/minimal/issues/3324)), which
uses this record:

- Run `tpm2_createprimary`, `tpm2_create`, `tpm2_load`, `tpm2_sign` and
  `tpm2_ecdhzgen` with `TPM2TOOLS_TCTI` set: `device:/dev/tpmrm0` on a host,
  and the value of `BEP_TPM_TCTI` in a test.
- Pass the authorization value as `-p file:<path>` or on standard input.
  Never pass it in the argument list.
- Keep a saved context of each key while the proxy runs. Load each key
  again from its blob at start, and when the TPM refuses its saved
  context.
- Flush transient objects and sessions after each command when the TCTI is
  not `device:/dev/tpmrm0`, so the tests pass against the TCP `swtpm`.
- `tpm2-tools` is a runtime dependency of `bep` on Linux. The `bep` refusal
  when `tpm2_getcap` is not on `PATH` names the package. Debian and Ubuntu:
  `tpm2-tools`.

For T129 ([#3326](https://github.com/gominimal/minimal/issues/3326)):

- Sort a failure from the table in finding 6. Check the key file and the
  authorization file before the command runs, then read the TCTI failure or
  the `ErrorCode (0x…)` response code from standard error. Pin each case in
  a test.

# Artifacts

- [`tools-bench.sh`](2026-11-13-bep-tpm-interface/tools-bench.sh): the
  `tpm2-tools` timings and checks.
- [`tools-errors.sh`](2026-11-13-bep-tpm-interface/tools-errors.sh): what
  `tpm2-tools` reports for each failure.
- [`esapi-bench/`](2026-11-13-bep-tpm-interface/esapi-bench/): the
  `tss-esapi` timings and checks.
- [`static-musl-build.sh`](2026-11-13-bep-tpm-interface/static-musl-build.sh):
  the static musl build against a device-only `tpm2-tss`.
