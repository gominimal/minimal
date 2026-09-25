---
title: Release pipeline
description: "How to cut a stable release, and how the pipeline builds, stages, smoke-tests, promotes, and installs releases: release.yml, nightly.yml, promote.yml, publish-packages.yml, prune-releases.yml, and the curl|sh installer."
---

> This is internal documentation. It is not published to the docs site.

# Release pipeline

A release goes out in two separate steps. First, a release run builds and
tests the artifacts. It uploads them to a write-once folder in the
`gs://minimal-one` bucket. Nobody receives that build yet. Second, a promotion
moves a channel pointer (`stable`, `unstable`, or `nightly`) to the folder.
Users install whatever their channel points at.

## Cut a stable release

Follow these steps in order. The examples use version `X.Y.Z` and commit
`<commit>`. Replace both with your values.

### Before you start

- You start each promotion run in steps 6 and 7, and a second person on the
  approver list in `promote.yml` approves it. The workflow does not let you
  approve your own run.
- Make sure that the repository secrets `AUR_SSH_PRIVATE_KEY` and
  `BREW_TAP_TOKEN` exist, and that the `gominimal/homebrew-minimal` repository
  exists. No check reads them before step 7. If one is missing, a publish job
  fails in step 7.
- A version number is permanent. After step 4 stages `X.Y.Z`, that number
  always means that build. To release a later fix, bump `package.version` in
  a PR and cut the next version.

### 1. Choose the commit and check the version

Choose a `main` commit. These required checks must be green on it:
`ci-success`, `ci-linux-native-success`, `ci-linux-kvm-success`,
`ci-macos-success`, and `ci-shell-installer-success`. A commit that a nightly
run built and smoked meets this rule, because the nightly run makes the same
check.

The version comes from `package.version` in the root `Cargo.toml`. Check it
at the commit:

```sh
git switch --detach <commit>
just check-version
```

Do not push a `v*` tag. The publish run in step 7 creates the tag.

### 2. Give the commit a branch

GitHub starts a manual workflow run on a branch or a tag, not on a commit
hash. If your commit is the tip of `main`, use `main` and skip this step.
Otherwise, push a branch that points at the commit:

```sh
git push origin <commit>:refs/heads/release/X.Y.Z
```

Nothing in the pipeline reads the branch name. The draft release and the tag
point at the commit. Steps 3 and 4 call this branch `<branch>`. It is `main`
or `release/X.Y.Z`.

### 3. Rehearse the release run

```sh
gh workflow run release.yml --ref <branch> -f versioned=true -f dry_run=true
```

A dry run builds, signs, packages, and smoke-tests everything. It uploads
nothing and does not use up the version number. Wait for it to pass.

### 4. Stage the release

```sh
gh workflow run release.yml --ref <branch> -f versioned=true -f dry_run=false
```

When the run passes, it did these things:

- It staged `gs://minimal-one/versions/X.Y.Z/`. The folder is write-once.
- It smoke-tested the artifacts and wrote `versions/X.Y.Z/smoked`, the record
  that step 6 checks.
- It created a draft GitHub Release `vX.Y.Z` with the notes and every
  artifact attached. A draft has no tag.
- It moved the `unstable` channel to `X.Y.Z`. There is no approval step for
  this. If your commit is older than the newest nightly build, unstable users
  go back to it until the next nightly run moves `unstable` forward again.

If the run fails after the staging job, fix the cause and run it again with
`-f restage=true`. A restage deletes the smoke record first, so you cannot
promote the version until its new smoke passes.

### 5. Test the staged release

Make sure that the smoke record exists:

```sh
curl -fsS https://storage.googleapis.com/minimal-one/versions/X.Y.Z/smoked
```

Install it the way a user does. The `unstable` channel points at it after
step 4:

```sh
curl -fsSL https://go.minimal.dev/unstable | sh
min --version
```

To test without the `unstable` channel, write a private pointer. Any name made
of `A-Za-z0-9._-` works. You need write access to the bucket, and anyone who
knows the name can install from it. Delete the pointer when you finish.

```sh
scripts/set-channel.sh --channel rc --version X.Y.Z --bucket gs://minimal-one
curl -fsSL https://storage.googleapis.com/minimal-one/versions/X.Y.Z/install.sh | sh -s -- rc
gcloud storage rm gs://minimal-one/rc
```

### 6. Promote to stable

Rehearse first. A dry-run promotion runs the approval step and the smoke
check, and changes nothing:

```sh
gh workflow run promote.yml -f target=stable -f version=X.Y.Z -f dry_run=true
```

Then promote for real:

```sh
gh workflow run promote.yml -f target=stable -f version=X.Y.Z
```

The workflow opens an approval issue. The second person comments `approved`
on it. Then the workflow does these things, in this order:

1. It checks the smoke record against the staged files, and refuses the
   version if they do not match.
2. It moves `stable` to `X.Y.Z`. Users of the install script get the new
   version from this point.
3. It tells the docs site to rebuild from the release commit.

The promotion does not publish anything by default. The `publish` input is
off, so the GitHub Release stays a draft and the AUR and Homebrew packages do
not change. You publish in step 7.

### 7. Publish the release

Run the promotion again for the same version, with `publish` on:

```sh
gh workflow run promote.yml -f target=stable -f version=X.Y.Z -f publish=true
```

The run goes through approval and the smoke check again. It writes the
`stable` pointer again, which changes nothing while `stable` points at
`X.Y.Z`. If `stable` now points at a different version, this run moves it
back to `X.Y.Z`. Then the run does these things, in this order:

1. It publishes the draft GitHub Release, which creates the `vX.Y.Z` tag and
   marks the release Latest.
2. It publishes the AUR package and the Homebrew formula.

If a publish job fails, fix the cause and use **Re-run failed jobs** on the
same run. Do not start a new run. The release publish job refuses a release
that is already public, so a new run fails at its first publish job.

### 8. Clean up

If you pushed a branch in step 2, delete it:

```sh
git push origin --delete release/X.Y.Z
```

Also delete any private pointer that you wrote in step 5.

### Roll back

Run the promotion again with `target=stable` and an earlier version that has a
smoke record. The promotion refuses a version without a smoke record. Choose
your rollback version before you promote. Use `override_provenance=true` only
in an emergency. The approval issue shows that you used it.

## We test every artifact we release

This is our policy. Every artifact that a user can install must pass a test
of the exact bytes that we publish, before a channel points at them. The
release run tests the artifacts it built, then records a hash of the staged
manifest. The promotion checks that hash, so it moves a channel only to bytes
that passed.

The table shows what the pipeline tests today. A row that says **gap** does not
meet the policy yet.

| Artifact | How the release run tests it |
| --- | --- |
| Linux amd64 `min`, `minimald`, `minvmd`, `gvproxy-min` | `smoke-linux-amd64` runs the session e2e on the host daemon. `smoke-linux-kvm` runs it in a KVM microVM. |
| amd64 guest kernel, rootfs, and initramfs | `smoke-linux-kvm` boots them. |
| arm64 guest kernel, rootfs, and initramfs | `smoke-macos` boots them. |
| macOS arm64 `min`, `minvmd`, `libkrun.1.dylib`, `gvproxy-min` | `smoke-macos` runs the session e2e with the signed files in the installer layout. **Gap:** when the `RUN_MACOS_CI` variable is `false`, this job skips and the run counts the skip as a pass. |
| Linux arm64 `min`, `minimald`, `minvmd`, `gvproxy-min` on a Linux host | **Gap.** No smoke job runs on a Linux arm64 host. |
| Linux `mip`, amd64 and arm64 | **Gap.** `smoke-linux-kvm` downloads `mip`, but no job runs it. |
| amd64 `.deb` | `smoke-linux-amd64` installs it and checks that `min -V` shows the release version. Versioned runs only. |
| arm64 `.deb`, every `.rpm`, every `.apk` | **Gap.** No job installs them. |
| `install.sh` and the AppArmor profile installer | The `ci-shell-installer` lane tests both scripts on every PR. **Gap:** no release job installs the staged folder through `install.sh`. |
| Homebrew formula and AUR package | `just test-shell` tests the publish scripts against fixture remotes, and CI runs it. **Gap:** no job installs the published package. |
| `completions.tar.gz` and the legacy `minimalone-<sha>.tar.zst` bundle | **Gap.** No job tests them. |

## Pipeline reference

### Staged folders and channels

Each release run uploads one folder, `gs://minimal-one/versions/<version>/`.
It holds the artifacts, a `components` manifest, a copy of `install.sh`, and
the release notes as `notes.md`. A versioned release also has the packages in
`pkg/`. Each manifest row gives one component, its OS and architecture, its
SHA-256, and where it installs. The folder never changes after upload.

A channel is a small file at the bucket root, such as
`gs://minimal-one/stable`. It holds one version name.
[`scripts/set-channel.sh`](../../scripts/set-channel.sh) writes it, after it
makes sure that the version folder exists. To move a channel, or to roll it
back, you write this file again. All bucket writes use GitHub OIDC and
Workload Identity Federation.

A release run makes a nightly build or a versioned release:

| | Nightly build | Versioned release |
| --- | --- | --- |
| Folder name | Short commit hash, such as `versions/9b763dd5/` | Version number, such as `versions/0.6.0/` |
| Started by | `nightly.yml` every day, or a manual run without `versioned` | A manual run with `versioned: true` |
| Version the binaries report | `0.6.0-dev.70.g9b763dd5` | `0.6.0` |
| GitHub Release | `release-<sha>`, deleted later by `prune-releases` | Draft `vX.Y.Z`, published in step 7 |
| Git tag | None | `vX.Y.Z`, created in step 7 |
| Packages (`.deb`, `.rpm`, `.apk`) | None | In `pkg/` and on the GitHub Release |
| Stable promotion with `publish=true` publishes | Nothing | GitHub Release, AUR, and Homebrew |

### release.yml: build, test, stage

[`.github/workflows/release.yml`](../../.github/workflows/release.yml) starts
from a manual run or from `nightly.yml`. Its inputs are `versioned`,
`dry_run`, `skip_ci_verify`, and `restage`. A tag push starts nothing.

**CI gate.** The `verify-ci` job requires the five required checks listed in
step 1 of the release steps to be green on the exact commit. See
[docs/ci-strategy.md](../ci-strategy.md). `skip_ci_verify` is an admin
override for a commit whose checks are green but did not report.

**Version.** The `version` crate sets the version string at build time
([`crates/version/src/scheme.rs`](../../crates/version/src/scheme.rs)). When
the build environment sets `MINIMAL_RELEASE_VERSION`, the binaries report
that value, such as `0.6.0` in place of `0.6.0-dev.7.g<sha>`. The value
must equal `package.version` in `Cargo.toml`. The build script enforces this,
and [`scripts/assert-release-version.sh`](../../scripts/assert-release-version.sh)
checks it for builds outside this pipeline.

The `assert-version` job reads `package.version` for a versioned run. It
refuses a version that already has a tag. It also runs
[`scripts/next-version.sh --check`](../../scripts/next-version.sh), the same
check that runs on every PR. That script reads the full commit messages since
the last release tag. A `feat:` commit requires a minor bump, and anything
else a patch. A breaking change appears first in the notes. At 0.x it does not bump the
major version. The same check runs as the
workspace `package_version` test and as `just check-version`. It fails a PR
whose `package.version` is stale or not above the newest `v*` tag.

**Build jobs.**

- `build-release-linux-{amd64,arm64}` builds static musl binaries of `mip`,
  `min` (package `minimal`), `minimald`, and `minvmd`. Each package has its
  own cargo command, so the LTO links run one after another. `minvmd`
  links a static `libkrun.a` from the vendored pin
  ([`scripts/build-libkrun-linux.sh`](../../scripts/build-libkrun-linux.sh)).
  The result is one binary with no `lib/` folder and no glibc requirement.
  The job checks that each binary is static and that `minvmd` contains the
  KVM backend.
- `build-release-macos-arm64` runs on the self-hosted Apple Silicon runner
  when `RUN_MACOS_CI` is not `false`. It builds `minvmd` and `min`, changes
  the libkrun link path in `minvmd` to `@rpath`
  ([`scripts/rewrite-macos-linkage.sh`](../../scripts/rewrite-macos-linkage.sh)),
  and checks that `min` links only system libraries. It signs both binaries
  with the Developer ID, the hardened runtime, and a timestamp.
- `build-libkrun-macos-arm64` builds the `libkrun.1.dylib` for macOS users on
  a hosted runner. `sign-macos-artifacts` signs it and the macOS `gvproxy`
  with the Developer ID on the self-hosted runner.
- `fetch-release-guest-artifacts` gets the guest kernel and the ext4 rootfs
  from the cache, and the pinned `gvproxy` binaries, for both guest
  architectures.
- `build-release-initramfs` packs the guest initramfs, with the release
  `minimald` as process 1.
- `compute-version-string` reads the version from a built binary. The GitHub
  Release name uses it. On a versioned run, the job checks that it equals the
  release version.

**release job.** This job downloads all build outputs. It writes the release
notes with `scripts/next-version.sh --notes` and generates shell completions
for `mip`, `min`, and `minimald`. On a versioned run it builds the `.deb`,
`.rpm`, and `.apk` for both Linux architectures from the same binaries
([`scripts/package-nfpm.sh`](../../scripts/package-nfpm.sh)). Then it does
two things:

- It uploads the legacy `minimalone-<sha>.tar.zst` bundle to
  `gs://minimal-shim/archives/` for the old `minimal-shim` install path.
- It creates the GitHub Release with the notes, the binaries, the guest
  artifacts, `completions.tar.gz`, and the packages. A nightly build gets
  `release-<sha>`. A versioned run gets a draft `vX.Y.Z` that points at the
  commit. A version with a `-` suffix is a prerelease.

**stage-installer job.** A dry run skips this job.
[`scripts/stage-release.sh`](../../scripts/stage-release.sh) uploads the
version folder. It refuses to start if the folder already has a `components`
manifest, and every upload uses `--if-generation-match=0`, so no upload can
replace a file. The `restage` input turns this off for one run. It deletes
the `smoked` record first, so the folder needs a new smoke before anyone
can promote it.

**Smoke jobs.** The smoke jobs run the session e2e
([`scripts/session-e2e.sh`](../../scripts/session-e2e.sh)) against the release
artifacts. `smoke-linux-amd64` uses the host daemon, `smoke-linux-kvm` uses a
KVM microVM, and `smoke-macos` uses the signed macOS files in the installer
layout. On a versioned run, `smoke-linux-amd64` also installs the amd64
`.deb`. The smokes also run on a dry run. The section on artifact tests above
lists what they do not cover.

**record-smoked job.** After the smokes and the staging pass,
[`scripts/record-smoked.sh`](../../scripts/record-smoked.sh) writes
`versions/<version>/smoked`. The file holds the SHA-256 of the staged
`components` manifest, the commit, and the run URL. The promotion compares
this hash with the live manifest, so a folder that someone stages again does
not keep an old result. Then `set-channel.sh` moves `unstable` to the version. `unstable` moves
on every release run that passes, with no approval.

### nightly.yml: the daily build

[`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml) starts
at 10:00 UTC. Its `check` job skips the build when the current `main` commit
already has a staged folder. Otherwise it calls `release.yml`, which builds,
stages, and smoke-tests as described in the release.yml section. If that
passes, or the build had nothing to do, `promote-nightly` checks the smoke
record with `verify-smoked.sh` and moves the `nightly` channel. A night with
nothing to build cannot move `nightly` to a folder that failed its smoke.

`nightly-tests.yml` at 06:00 UTC is a separate test run. It releases nothing.
See [docs/ci-strategy.md](../ci-strategy.md).

### promote.yml: move a channel

[`.github/workflows/promote.yml`](../../.github/workflows/promote.yml), named
`promote-cli` in the Actions list, moves `stable` or `unstable`. Its inputs are
`version`, `target`, `dry_run`, `override_provenance`, and `publish`. `version` is a
version number or a nightly commit hash. When you leave it empty, the
workflow uses the newest staged nightly build.

**Approval.** The `gate` job opens an approval issue, posts to Slack, and
waits. A person on the approver list, other than the person who started the
run, comments `approved` or `denied`. If someone closes the issue without an
approval, the workflow stops.

**Smoke check.** The `promote` job runs
[`scripts/verify-smoked.sh`](../../scripts/verify-smoked.sh). It compares the
hash in the `smoked` record with a new hash of the live `components` manifest.
A version with no record fails. A folder that someone staged again after its
smoke also fails. `override_provenance` skips this check in an emergency, and the
approval issue shows that choice.

**Channel move and docs.** `set-channel.sh` moves the channel. The job then
sends a `reference-docs-promoted` event to `gominimal/webapp` with the release
commit, and the docs site at docs.minimal.dev rebuilds from that commit.

### publish-packages.yml: publish a stable release

A `stable` promotion with `publish=true` that is not a dry run calls
[`.github/workflows/publish-packages.yml`](../../.github/workflows/publish-packages.yml).

- `publish-release` publishes the draft `vX.Y.Z`. Publication creates the tag
  on the release commit. It does not start a build. The job fails if no draft exists
  or if the release is already public. For a nightly commit hash, it prints a
  notice and does nothing.
- `publish-aur` publishes `minimal-bin` to the AUR from the staged folder.
- `publish-brew` updates the formula in `gominimal/homebrew-minimal` from the
  GitHub Release.

A prerelease, such as `0.6.0-rc1`, gets a public GitHub Release but no AUR
or Homebrew update. Neither can hold a prerelease. The `apt`, `dnf`, and `apk`
repositories come from the `pkg/` folder, and the infra repository builds them.

### prune-releases.yml: delete old nightly releases

[`.github/workflows/prune-releases.yml`](../../.github/workflows/prune-releases.yml)
starts at 04:17 UTC on Mondays and Fridays. A manual run defaults to a
preview. It deletes `release-<sha>` GitHub Releases and their tags after two
months, and it always keeps the newest ten. The logic is in
[`scripts/prune-releases.sh`](../../scripts/prune-releases.sh). It never
deletes a `vX.Y.Z` release. The installer reads from the bucket, so pruning
does not remove anything that users install.

### install.sh: from channel to installed files

[`scripts/install.sh`](../../scripts/install.sh) is the `curl | sh`
installer, in strict POSIX `sh`. It works in these steps:

1. It reads the channel file from `https://storage.googleapis.com/minimal-one`.
   The default channel is `stable`. `go.minimal.dev/<channel>` serves the
   same script with a `MINIMAL_INSTALL_TARGET_OVERRIDE=<channel>` line added.
2. It downloads `versions/<version>/components`. It refuses a manifest with an
   unknown `# format:` header.
3. For each row that matches the host OS and architecture, it downloads the
   file, checks its SHA-256, and moves it into place. A file whose hash on
   disk already matches stays as it is. The installer stops a running daemon
   before it replaces an executable.

The components come from the `COMPONENTS` table in `stage-release.sh`:

- Linux amd64 and arm64: `bin/min`, `bin/mip`, `bin/minimald`, `bin/minvmd`,
  `bin/gvproxy-min`, a `git-remote-min` symlink, the guest files
  (`data/vmlinuz`, `data/rootfs.img`, `data/initramfs.cpio`), and the AppArmor
  profile, tunable, and loader under `data/`.
- macOS arm64: `bin/min`, `bin/minvmd`, `bin/gvproxy-min`,
  `lib/libkrun.1.dylib`, the `git-remote-min` symlink, and the same guest
  files. Only macOS has a `lib/` folder, because the Linux `minvmd` links
  libkrun statically.

The installer also adds shell setup: PATH init files, `min` completions, and
one marked block in the shell rc file. `--uninstall` removes all of it with no
network access, from the local install record. It keeps files that you
changed unless you add `--force`. `--purge` also deletes the data, state, and
cache folders.
