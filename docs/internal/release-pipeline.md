---
title: Release pipeline
description: How releases are built, staged, smoke-tested, promoted, and installed: release.yml, nightly.yml, promote.yml, prune-releases.yml, and the curl|sh installer.
---

> This is internal documentation. It is not published to the docs site.

# Release pipeline

Distribution is bucket-centric. A release run stages an **immutable**
`gs://minimal-one/versions/<short-sha>/` folder (artifacts + a `components`
manifest); which version users actually receive is decided separately by
mutable **channel pointer files** (`stable`, `unstable`, `nightly`) at the
bucket root, written by [`scripts/set-channel.sh`](../../scripts/set-channel.sh).
Staging is inert; flipping a pointer is the single, cheap, reversible action
that ships (or rolls back) a version. All GCS writes authenticate via GitHub
OIDC / Workload Identity Federation.

## release.yml: build, sign, stage

[`.github/workflows/release.yml`](../../.github/workflows/release.yml) runs on
manual `workflow_dispatch` (inputs: `dry_run`, `skip_ci_verify`), via
`workflow_call` from nightly.yml, or on a `vMAJOR.MINOR.PATCH[-suffix]` tag
push.

**verify-ci gate.** The `verify-ci` job requires the five lane aggregators,
`ci-success`, `ci-linux-native-success`, `ci-linux-kvm-success`,
`ci-macos-success`, `ci-shell-installer-success` (the required checks on
`main`; see [docs/ci-strategy.md](../ci-strategy.md)), to have reported
success on the exact commit being released. `skip_ci_verify` is an admin
override for green-but-unreported commits.

**Build jobs.**

- `build-release-linux-{amd64,arm64}`: static musl builds of `mip`, `min`
  (package `minimal`), and `minimald`, one cargo invocation per package so the
  fat-LTO links serialize. Each job then builds a native-glibc `minvmd` against
  a materialized libkrun prefix and uploads that prefix's `libkrun` +
  `libkrunfw` pair, so a Linux install ships the VM backend rather than
  depending on a system libkrun.
  [`scripts/rewrite-linux-linkage.sh`](../../scripts/rewrite-linux-linkage.sh)
  sets the two RUNPATHs the shipped layout needs (`minvmd` →
  `$ORIGIN/../lib`, `libkrun` → `$ORIGIN`, the latter because its `dlopen` of
  `libkrunfw` resolves against the *calling* object's RUNPATH) and hard-fails
  on a soname bump, which would otherwise silently invalidate the `lib/` dests
  in stage-release.sh.
- `build-release-macos-arm64` (self-hosted Apple Silicon, gated on the
  `RUN_MACOS_CI` kill-switch): builds `minvmd` (libkrun /
  Hypervisor.framework) and `min`, rewrites minvmd's libkrun linkage to
  `@rpath` ([`scripts/rewrite-macos-linkage.sh`](../../scripts/rewrite-macos-linkage.sh)),
  verifies `min` links only system libraries, and Developer-ID-signs both
  (hardened runtime + timestamp, notarization-ready).
- `build-libkrun-macos-arm64`: builds the trimmed `libkrun.1.dylib` shipped to
  macOS users (same pinned build every macOS CI lane tests against) on a
  hosted runner; `sign-macos-artifacts` re-signs it and the darwin `gvproxy`
  with the Developer ID identity on the self-hosted runner.
- `fetch-release-guest-artifacts`: guest kernel Image and ext4 rootfs (cache
  pulls keyed by the pinned upstream commit) plus pin-verified `gvproxy`
  binaries, for both guest arches.
- `build-release-initramfs`: packs the guest initramfs (minimald as pid-1)
  from the same shipped musl `minimald` binaries.
- `compute-version-string`: reads the version out of a built binary so the
  GitHub Release name matches `minimald -V` exactly.

**release job.** Downloads everything, generates shell completions for `mip`,
`min`, and `minimald`, then:

- uploads a legacy `minimalone-<sha>.tar.zst` bundle to
  `gs://minimal-shim/archives/`, retained for backward compatibility with
  the legacy `minimal-shim` archive path;
- creates the GitHub Release (tag `release-<sha>`, or the pushed `v*` tag; a
  suffixed tag becomes a prerelease) with all binaries, guest artifacts, and
  `completions.tar.gz`.

**stage-installer job** (skipped entirely on `dry_run`):

- [`scripts/stage-release.sh`](../../scripts/stage-release.sh) uploads the
  artifacts and a `components` manifest (one row per component/os/arch with
  its SHA-256, kind, and install destination: the authoritative per-platform
  component list) to immutable `gs://minimal-one/versions/<short-sha>/`;
- a version-pinned copy of [`scripts/install.sh`](../../scripts/install.sh)
  is uploaded next to them, so each version's install path is self-contained;
- [`scripts/set-channel.sh`](../../scripts/set-channel.sh) points the
  `unstable` channel at the new version. `unstable` auto-advances on every
  release: no gate.

## nightly.yml: daily cut + smoke + nightly channel

[`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml) runs at
10:00 UTC. A `check` job skips the rebuild when HEAD is already staged (public
HEAD request on the version's `components` manifest), then invokes release.yml
via `workflow_call`. Three smoke jobs run the shared session e2e
([`scripts/session-e2e.sh`](../../scripts/session-e2e.sh)) against the
**shipped** artifacts (native Linux daemon, Linux + KVM microVM, and the
signed macOS binaries assembled in the installer layout), feeding a
skip-tolerant `smoke-success` aggregator. Only then does `promote-nightly`
flip the `nightly` pointer via set-channel.sh. `nightly-tests.yml` is the
separate 06:00 UTC nightly *test* tier, unrelated to releasing; see
[docs/ci-strategy.md](../ci-strategy.md).

## promote.yml: gated promotion to stable

[`.github/workflows/promote.yml`](../../.github/workflows/promote.yml)
(workflow name `promote-cli`) is the manual path that moves the `stable` (or
`unstable`) pointer. Inputs: `sha` (defaults to the latest staged version in
the bucket), `target`, `dry_run`, `override_provenance`. The `gate` job opens a
promotion-approval GitHub issue, notifies Slack, and polls until someone on the
workflow's approver allowlist (the initiating user is excluded) comments
`approved` / `denied`; closing the issue without approval counts as denial.

**nightly-provenance gate.** Before flipping the pointer, the `promote` job
runs [`scripts/verify-nightly-provenance.sh --sha "$SHA"`](../../scripts/verify-nightly-provenance.sh),
which queries GitHub Actions to confirm the version was built by a successful
`nightly.yml` run whose Linux smoke jobs actually ran and passed (the
skip-tolerant `smoke-success` aggregator alone is not trusted, so a no-op
nightly run that skipped its smokes cannot vouch for a SHA; `smoke-macos` may
be skipped by the `RUN_MACOS_CI` kill-switch). This rejects manually
dispatched release.yml runs and tag-push builds. Staging a version does not
make it promotable. The `override_provenance`
emergency input bypasses this gate when checked; use it only for documented
emergency releases that skip the nightly path.

The `promote` job then runs set-channel.sh, which verifies the version is
actually staged before flipping the pointer. Finally it dispatches a
`reference-docs-promoted` repository event that triggers a rebuild of the
published reference docs at docs.minimal.dev.

## prune-releases.yml: GitHub Release housekeeping

[`.github/workflows/prune-releases.yml`](../../.github/workflows/prune-releases.yml)
runs at 04:17 UTC on Mondays and Fridays (plus manual dispatch, which defaults
to a dry-run preview) and deletes auto-cut `release-<sha>` GitHub Releases and
their tags once they age out (default: older than 2 months, always keeping the
10 newest). The logic lives in
[`scripts/prune-releases.sh`](../../scripts/prune-releases.sh); exact
`vMAJOR.MINOR.PATCH` releases are never deleted (hard guard), and the
installer serves from GCS, so pruning removes redundant copies, not live
install targets.

## install.sh: channel → version → components

[`scripts/install.sh`](../../scripts/install.sh) is the strict-POSIX `curl |
sh` installer. Against `https://storage.googleapis.com/minimal-one` it fetches
the channel pointer (default `stable`; the per-channel endpoints under
`go.minimal.dev/<channel>` serve this same script with a
`MINIMAL_INSTALL_TARGET_OVERRIDE=<channel>` line injected to pin the target),
resolves the version, fetches the
immutable `versions/<version>/components` manifest (refusing an unknown
`# format:` header), and for each row matching the host os/arch downloads,
SHA-256-verifies, and atomically installs the file. The on-disk hash is the
skip oracle, so reruns only touch changed components, and a running daemon is
stopped before an executable is swapped. Per-platform sets (from
stage-release.sh's `COMPONENTS` table): every platform gets the session stack —
`bin/min`, `bin/minvmd`, `bin/mingvproxy`, a `git-remote-min` symlink, the
libkrun the VM backend links (`lib/libkrun.so.1` + `lib/libkrunfw.so.5` on
Linux, `lib/libkrun.1.dylib` on macOS), and the guest payload
(`data/{vmlinuz,rootfs.img,initramfs.cpio}`) for its own arch. Linux
additionally gets `bin/mip`, `bin/minimald`, and the AppArmor
profile/tunable/loader under `data/`.

The switch binary installs as **`mingvproxy`**, not `gvproxy`: the `bin` prefix
is `~/.local/bin`, which is on `PATH`, and podman/crc ship their own `gvproxy`
there — under the upstream name whichever was installed last would win a `PATH`
lookup, in either direction. The bytes are stock gvproxy;
[`switch::GVPROXY_FILE`](../../crates/switch/src/lib.rs) is the resolver's
matching definition, and install.sh removes a `bin/gvproxy` left by a
pre-rename install when its bytes are still the ones we recorded writing.

It also wires shell integration (PATH init files, `min` completions, one
marker-fenced rc block). `--uninstall` reverses all of it offline from the
local install record, keeping user-modified files unless `--force`;
`--purge` also removes the data/state/cache trees.

## Runbook

**Cut a release.**

1. Pick a `main` commit whose five lane aggregators are green.
2. Actions → *Release* → Run workflow (use `dry_run` to rehearse), or push a
   `vX.Y.Z` tag for a versioned GitHub Release.
3. The run stages `gs://minimal-one/versions/<short-sha>/` and auto-points
   `unstable` at it. Nightly runs do the same for `nightly` after smoke.

**Promote to stable.**

1. **Verify the SHA was nightly-built.** The promote workflow rejects versions
   not built and smoke-tested by `nightly.yml`: manually dispatched or
   tag-staged SHAs fail the provenance gate after the multi-hour approval
   completes, even if a later no-op nightly run carries the same SHA. If you
   need to promote a non-nightly version in an emergency, check
   `override_provenance` when dispatching.
2. Actions → *promote-cli* → Run workflow with `target: stable` (optionally a
   specific staged `sha`; empty means the latest staged).
3. A second person from the approver allowlist comments `approved` on the
   auto-opened issue (the initiator cannot self-approve).
4. The provenance check runs, then set-channel.sh flips the `stable` pointer.
   Rollback is the same workflow pointed at a previously staged version.
