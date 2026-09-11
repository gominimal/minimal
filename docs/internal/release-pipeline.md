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
manual `workflow_dispatch` (inputs: `versioned`, `dry_run`, `skip_ci_verify`,
`restage`) or via `workflow_call` from nightly.yml. No tag push builds
anything: the `v<semver>` tag is created last, by promotion, on a commit that
was already built, smoked, and promoted.

Two shapes of run share the pipeline. A **nightly / plain** build stages
`versions/<short-sha>/` and cuts an auto-pruned `release-<sha>` GitHub
Release. A **versioned** build (`versioned: true`) builds with
`MINIMAL_RELEASE_VERSION` set to `Cargo.toml` `package.version`, so every
binary reports the release version on an untagged commit; packages the
`.deb`/`.rpm`/`.apk` from the same bytes; generates the release notes; stages
`versions/<semver>/`; and parks a **draft** GitHub Release `v<semver>` with
everything attached. Both then smoke the shipped artifacts in the same run
and record the smoke against the staged row.

**verify-ci gate.** The `verify-ci` job requires the five lane aggregators,
`ci-success`, `ci-linux-native-success`, `ci-linux-kvm-success`,
`ci-macos-success`, `ci-shell-installer-success` (the required checks on
`main`; see [docs/ci-strategy.md](../ci-strategy.md)), to have reported
success on the exact commit being released. `skip_ci_verify` is an admin
override for green-but-unreported commits.

**Version.** Every binary reports one version string, derived by the
`version` crate at build time
([`crates/version/src/scheme.rs`](../../crates/version/src/scheme.rs)).
`MINIMAL_RELEASE_VERSION`, when set in the build environment, wins outright:
a release build on an untagged commit reports `0.6.0`, not
`0.6.0-dev.7.g<sha>`. It must equal the workspace `package.version` in
`Cargo.toml`, which the build script enforces (and
[`scripts/assert-release-version.sh`](../../scripts/assert-release-version.sh)
asserts for builds outside this pipeline). The `assert-version` job resolves
the run's version: for a versioned build it reads `package.version`, refuses
one that is already tagged, and runs the same lint every PR runs; every build
job then exports it as `MINIMAL_RELEASE_VERSION`, and
`compute-version-string` asserts the built binary reports it. Without the
override, `git describe` supplies only the commit count and hash on top of
`package.version`, which is therefore the *declared next release* rather than
a guess: `feat:` since the last tag means a minor, anything else a patch, and
while the project is 0.x a breaking change is reported but never bumps the
major. [`scripts/next-version.sh`](../../scripts/next-version.sh) derives the
level and the release notes from one walk of the full commit bodies since the
last released tag (so a `BREAKING CHANGE:` footer under a plain subject is
caught), and its `--check` mode is the lint — the workspace `package_version`
test, run for real on the native lane's full-history checkout, and `just
check-version` — that fails a PR whose `package.version` is stale or not
strictly above the newest `v*` tag.

**Build jobs.**

- `build-release-linux-{amd64,arm64}`: static musl builds of `mip`, `min`
  (package `minimal`), `minimald`, and `minvmd`, one cargo invocation per
  package so the fat-LTO links serialize. `minvmd` links a static `libkrun.a`
  built from the vendored pin by the `build-libkrun-static-linux` composite
  ([`scripts/build-libkrun-linux.sh`](../../scripts/build-libkrun-linux.sh)),
  so it ships as a single self-contained binary with no `lib/` sibling, no
  RUNPATH, and no glibc floor — and both arches ship it, where only amd64 had
  a (dynamic) `minvmd` before. Each job asserts the result is `statically
  linked` or `static-pie linked` (amd64 musl emits a static PIE, which
  `file(1)` names differently) and really contains the KVM backend, since a
  stub `minvmd` builds and links just as cleanly.
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
  GitHub Release name matches `minimald -V` exactly, and on a versioned build
  asserts it is the release version.

**release job.** Downloads everything, generates the release notes
([`scripts/next-version.sh --notes`](../../scripts/next-version.sh): full
commit bodies since the last released tag, breaking changes first),
generates shell completions for `mip`, `min`, and `minimald`, and on a
versioned build packages the `.deb`/`.rpm`/`.apk` for both Linux arches from
this run's binaries ([`scripts/package-nfpm.sh`](../../scripts/package-nfpm.sh)
in `ARTIFACTS_DIR` mode, pinned nfpm). Then:

- uploads a legacy `minimalone-<sha>.tar.zst` bundle to
  `gs://minimal-shim/archives/`, retained for backward compatibility with
  the legacy `minimal-shim` archive path;
- creates the GitHub Release with the notes and all binaries, guest
  artifacts, `completions.tar.gz`, and (versioned) the packages: tag
  `release-<sha>` for a nightly/plain build, or a **draft** `v<semver>`
  targeting this commit for a versioned one (a `-suffix` version is a
  prerelease). A draft creates no tag; publishing it later does.

**stage-installer job** (skipped entirely on `dry_run`):

- [`scripts/stage-release.sh`](../../scripts/stage-release.sh) uploads one
  row, `gs://minimal-one/versions/<version>/` (`<short-sha>` or `<semver>`):
  the artifacts, a `components` manifest (one row per component/os/arch with
  its SHA-256, kind, and install destination: the authoritative per-platform
  component list), a version-pinned copy of
  [`scripts/install.sh`](../../scripts/install.sh) so each version's install
  path is self-contained, the release notes as `notes.md`, and (versioned)
  `pkg/` with the packages. Immutable is enforced, not assumed: a version
  whose `components` manifest already exists fails before any upload, and
  every upload carries `--if-generation-match=0` so an existing object is
  never replaced. The `restage` input (`--restage`) is the explicit, logged
  opt-in for re-running a versioned build that failed after staging;
- [`scripts/set-channel.sh`](../../scripts/set-channel.sh) points the
  `unstable` channel at the new version. `unstable` auto-advances on every
  release: no gate.

**smoke jobs.** Three jobs run the shared session e2e
([`scripts/session-e2e.sh`](../../scripts/session-e2e.sh)) against the
**shipped** artifacts: the native Linux daemon, Linux + KVM microVM, and the
signed macOS binaries assembled in the installer layout (skip-tolerant: the
`RUN_MACOS_CI` kill-switch). On a versioned build the native job also installs
the `.deb` and checks `/usr/bin/min -V` reports the release version. They run
on dry runs too; only the recording below is skipped.

**record-smoked job.** After the smokes and the staging succeed,
[`scripts/record-smoked.sh`](../../scripts/record-smoked.sh) writes
`versions/<version>/smoked`: the SHA-256 of the row's live `components`
manifest plus the run URL. Provenance is thereby a property of the row — the
promotion gate hashes the live manifest and compares, so "these bytes were
smoked" is checked directly rather than inferred from a workflow run id, and
a re-staged row can never inherit a stale blessing.

## nightly.yml: daily cut + smoke + nightly channel

[`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml) runs at
10:00 UTC. A `check` job skips the rebuild when HEAD is already staged (public
HEAD request on the version's `components` manifest), then invokes release.yml
via `workflow_call`, which builds, stages, smokes, and records the smoke as
described above. Only if that whole run succeeds (or was skipped as a no-op)
does `promote-nightly` flip the `nightly` pointer via set-channel.sh.
`nightly-tests.yml` is the separate 06:00 UTC nightly *test* tier, unrelated
to releasing; see [docs/ci-strategy.md](../ci-strategy.md).

## promote.yml: gated promotion to stable

[`.github/workflows/promote.yml`](../../.github/workflows/promote.yml)
(workflow name `promote-cli`) is the manual path that moves the `stable` (or
`unstable`) pointer. Inputs: `version` (a semver from a versioned build, or a
nightly short sha; defaults to the latest staged nightly sha), `target`,
`dry_run`, `override_provenance`. The `gate` job opens a
promotion-approval GitHub issue, notifies Slack, and polls until someone on the
workflow's approver allowlist (the initiating user is excluded) comments
`approved` / `denied`; closing the issue without approval counts as denial.

**smoke-provenance gate.** Before flipping the pointer, the `promote` job
runs [`scripts/verify-smoked.sh --version "$VERSION"`](../../scripts/verify-smoked.sh),
which reads the row's `smoked` marker, re-hashes the live `components`
manifest, and requires the digests to match. A version nobody smoked has no
marker; a row re-staged after its smoke no longer matches. Both fail before
the pointer is touched. Every release run — nightly or versioned — smokes and
records, so the gate runs on the default path; the `override_provenance`
emergency input bypasses it when checked, and the approval issue shows it.

The `promote` job then runs set-channel.sh, which verifies the version is
actually staged before flipping the pointer, and dispatches a
`reference-docs-promoted` repository event that triggers a rebuild of the
published reference docs at docs.minimal.dev.

**publish.** A `stable` promotion (not a dry run) calls
[`.github/workflows/publish-packages.yml`](../../.github/workflows/publish-packages.yml).
When the promoted version is a semver it publishes the draft GitHub Release —
which is what creates the `v<semver>` tag, last, on the already-smoked commit
and triggers no build — then runs the AUR and Homebrew publishers. A promoted
nightly sha has nothing versioned to publish and the workflow says so.

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
stage-release.sh's `COMPONENTS` table): Linux amd64/arm64 get `bin/min`,
`bin/mip`, `bin/minimald`, `bin/minvmd`, `bin/gvproxy-min`, a `git-remote-min`
symlink, the guest payload (`data/{vmlinuz,rootfs.img,initramfs.cpio}`), and the
AppArmor profile/tunable/loader under `data/`; macOS arm64 gets `bin/min`,
`bin/minvmd`, `bin/gvproxy-min`, `lib/libkrun.1.dylib`, the `git-remote-min`
symlink, and the same guest payload. Only macOS carries a `lib/` component:
the Linux `minvmd` links libkrun statically.
It also wires shell integration (PATH init files, `min` completions, one
marker-fenced rc block). `--uninstall` reverses all of it offline from the
local install record, keeping user-modified files unless `--force`;
`--purge` also removes the data/state/cache trees.

## Runbook

**Cut a versioned release.**

1. Pick a `main` commit whose five lane aggregators are green.
   `package.version` in `Cargo.toml` is the version that will be cut; `just
   check-version` says whether it is right (the `package_version` lint keeps
   it ahead of the newest tag and consistent with the commits, on every PR).
   Never push a tag by hand: nothing builds from one, and the tag is created
   by the promotion.
2. Actions → *Release* → Run workflow on that commit with `versioned: true`
   (use `dry_run` to rehearse). The run builds every binary reporting the
   release version, packages, stages `gs://minimal-one/versions/<semver>/`
   (write-once), smokes the shipped bytes, records the smoke, parks a draft
   GitHub Release `v<semver>`, and points `unstable` at the row.
3. If the run failed after staging and you are re-running the same version,
   set `restage: true`; a fresh commit needs nothing special. A leftover
   draft is replaced automatically.

Nightly runs stage `versions/<short-sha>/` and point `nightly` at it the same
way; a plain (non-versioned) dispatch does the same for `unstable`.

**Promote to stable.**

1. Actions → *promote-cli* → Run workflow with `target: stable` and the
   `version` (the semver; empty means the latest staged nightly sha, which
   has nothing versioned to publish).
2. A second person from the approver allowlist comments `approved` on the
   auto-opened issue (the initiator cannot self-approve).
3. The smoke-provenance gate runs — the row's bytes must be the bytes a
   release run smoked; a version that was never smoked, or was re-staged
   since, is refused before the pointer moves — then set-channel.sh flips
   the `stable` pointer. `override_provenance` is for documented emergencies
   only and is visible in the approval issue.
4. For a semver, `publish-packages.yml` publishes the draft GitHub Release
   (creating the `v<semver>` tag) and runs the AUR and Homebrew publishers.
   Rollback is the same workflow pointed at a previously staged version.
