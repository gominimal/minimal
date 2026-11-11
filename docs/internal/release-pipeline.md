---
title: Release pipeline
description: "How to cut a stable release, and how the pipeline builds, stages, smoke-tests, promotes, and installs releases: release.yml, stage-release.yml, nightly.yml, promote.yml, prune-releases.yml, and the curl|sh installer."
---

> This is internal documentation. It is not published to the docs site.

# Release pipeline

A release goes out in two separate steps. First, a release run builds and
tests the artifacts. It uploads them to a write-once folder in the
`gs://minimal-one` bucket. Nobody receives that build yet. Second, a promotion
moves a channel pointer (`stable`, `unstable`, or `nightly`) to the folder.
Users install whatever their channel points at.

## Cut a stable release

Follow these steps in order. The examples use version `X.Y.Z`, commit
`<commit>`, and release line `release/X.Y.x`, such as `release/0.7.x`. Replace
them with your values.

A release takes one of two paths:

- A minor release cuts a new release line from `main`. Follow every step.
- A patch is staged from the existing line, with no new branch. See
  [Stage a patch](#stage-a-patch).

The [release manager runbook](https://github.com/gominimal/release-ops/blob/main/RUNBOOK.md)
says who does this work and when. This page says how.

### Before you start

- You start the promotion run in step 7, and a second member of the
  `@gominimal/minimalists` team approves it. The workflow does not let you
  approve your own run.
- A version number is permanent. After step 4 stages `X.Y.Z`, that number
  always means that build. To release a later fix, bump `package.version` in
  a PR and stage the next version.
- A release runs on a branch that outlives one build. Fixes merge into
  `release/X.Y.x` by PR while `main` keeps moving. Each release candidate
  uses up its own version number, such as `X.Y.Z-rc1`, because a staged
  number is permanent.
- A release candidate stops after step 6. Only the final version goes on to
  step 7. The promotion does not refuse a candidate version: it moves
  `stable` to it for every user of the install script, and it creates its
  tag.

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

Do not push a `v*` tag. The promotion in step 7 creates the tag.

### 2. Cut the release line

GitHub starts a manual workflow run on a branch or a tag, not on a commit
hash. Push a branch that points at the commit, even when the commit is the
tip of `main`. A run on `main` builds the commit that `main` points at when
the run starts, and `main` can move between steps 3 and 4.

```sh
git push origin <commit>:refs/heads/release/X.Y.x
```

[`cut-minor.yml`](#cut-minoryml-start-a-minor-release) does this step for you.
It creates the branch as the `minimal-release-ops` App, the backport label, and
the bump PR on `main`. By hand, only a repository admin can create a branch
under `release/`, so ask one to push it. The branch name must start with `release/`. CI runs the required checks on
pushes and PRs to `main` and `release/**` only. Without those checks, step 4
refuses each fix that merges into the branch.

The `release branches` ruleset keeps the branch safe to sign from. Except
for admins, it refuses direct pushes, force pushes and deletion on
`release/**`. Each change needs a PR with a code-owner approval and the
required checks.

The draft release and the tag point at the commit. The branch name also
decides whether the signing jobs can run:

- The `release` environment holds `KC_PW` and admits `main` and `release/*`.
  A signed run needs one of those branches.
- The `signing` runner group lists each branch by its exact name, because it
  takes no wildcard. Add the new branch before step 3, or the signing jobs
  wait in the queue. This needs an organization owner:

```sh
gh api orgs/gominimal/actions/runner-groups/3 --jq '{name, visibility, allows_public_repositories, restricted_to_workflows, selected_workflows: (.selected_workflows + ["gominimal/minimal/.github/workflows/release.yml@refs/heads/release/X.Y.x"])}' \
  | gh api -X PATCH orgs/gominimal/actions/runner-groups/3 --input -
```

That update can empty the group's repository list. With an empty list, the
signing jobs wait in the queue and the runner stays idle. Add the repository
again, then check that the second command prints `gominimal/minimal`:

```sh
gh api -X PUT orgs/gominimal/actions/runner-groups/3/repositories/$(gh api repos/gominimal/minimal --jq .id)
gh api orgs/gominimal/actions/runner-groups/3/repositories --jq '.repositories[].full_name'
```

When the line stops getting patches, remove its entry from the group in the
same way, and add the repository again.

Keep the branch after the release. It carries the fixes that go into the
release while `main` moves on, and each patch on the line goes out from it.
Step 8 brings its fixes back to `main`.

Before step 7, open a PR on `main` that bumps `package.version` to the next
minor, unless `cut-minor.yml` opened it. After the `vX.Y.0` tag exists, the version check fails on `main` until
its version is above that tag.

### 3. Rehearse the release run

```sh
gh workflow run release.yml --ref release/X.Y.x -f versioned=true -f dry_run=true
```

A dry run builds, signs, and smoke-tests everything. It uploads
nothing and does not use up the version number. Wait for it to pass. The run
page shows the commit that it built.

Do not merge into the branch from now until step 4 stages the release. A fix
that merges after the dry run gets staged without a rehearsal.

### 4. Stage the release

Make sure that the branch still points at the commit that the dry run built:

```sh
git fetch origin release/X.Y.x
git rev-parse FETCH_HEAD
```

If the branch moved, run step 3 again. Then stage:

```sh
gh workflow run release.yml --ref release/X.Y.x -f versioned=true -f dry_run=false
```

When the run passes, it did these things:

- It staged `gs://minimal-one/versions/X.Y.Z/`. The folder is write-once.
- It smoke-tested the artifacts and wrote `versions/X.Y.Z/smoked`, the record
  that step 7 checks.
- It created a draft GitHub Release `vX.Y.Z` with the notes and every
  artifact attached. A draft has no tag.
- It did not move any channel. `unstable` follows `main`, and only a
  promotion points a channel at `X.Y.Z`.

If the run fails after the staging job, fix the cause and run it again with
`-f restage=true`. A restage deletes the smoke record first, so you cannot
promote the version until its new smoke passes.

### 5. Test the staged release

Make sure that the smoke record exists:

```sh
curl -fsS https://storage.googleapis.com/minimal-one/versions/X.Y.Z/smoked
```

No channel points at the staged release, so install it by version. This needs
no access to the bucket, so anyone on the team can run it:

```sh
curl -fsSL https://storage.googleapis.com/minimal-one/versions/X.Y.Z/install.sh | sh -s -- --version X.Y.Z
```

Use this command to soak the build until the promotion. A problem that blocks
the promotion needs a fix on the line and a new version, because a staged
number is permanent.

### 6. Check minimal-skills against the staged build

[`gominimal/minimal-skills`](https://github.com/gominimal/minimal-skills)
describes the behaviour of the released build, so it follows the release.
Check its claims against the staged version `X.Y.Z`, before the promotion,
so that a fix can still go in before users get the build. Run its evals, and
file each place where minimal-skills and the running build disagree in
[`gominimal/inbox`](https://github.com/gominimal/inbox). The repository keeps
one `release/vX.Y.x` branch for each release line. That name has a `v`,
unlike `release/X.Y.x` in this repository. minimal-skills has no rule on
`release/` branches, so the release manager creates it when the line is cut.

A release candidate stops here.

### 7. Promote to stable

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
4. It publishes the draft GitHub Release, which creates the `vX.Y.Z` tag and
   marks the release Latest.
5. It reports the version to `gominimal/release-ops`, which appends it to
   `releases` in `rotation.yaml`.

If the release publish job or the report fails, fix the cause and use
**Re-run failed jobs** on the same run.

The promotion also opens a PR that moves `release/X.Y.x` to the next patch.
Someone on the team reviews and merges it before the next stage. If that job
fails, use **Re-run failed jobs** too.

### 8. Forward port the release branch

After each promotion to stable, bring the fixes that merged into
`release/X.Y.x` back to `main`. `main` moves while a release is out, so a port that waits costs more than one that
does not. Compare the branch, not the tag. A fix can merge into the branch
after the tag, and the tag does not contain it.

The promotion created the tag on GitHub, so fetch it with the branch. The
explicit refspecs write `origin/main` and `origin/release/X.Y.x` in any
clone. `--force` replaces a stale local tag of the same name. If the second
command prints `branch already on main`, there is nothing to port and nothing
to merge. Skip to the tag check at the end of this step:

```sh
git fetch --force origin main:refs/remotes/origin/main release/X.Y.x:refs/remotes/origin/release/X.Y.x tag vX.Y.Z
git merge-base --is-ancestor origin/release/X.Y.x origin/main && echo "branch already on main"
```

List the branch commits that have no identical patch on `main`:

```sh
git cherry -v origin/main origin/release/X.Y.x | grep '^+'
```

The list holds the version bumps, and also each cherry-pick whose conflicts
someone resolved by hand. Find the `main` PR for each fix in the list. If a
fix has no PR on `main`, open a PR that brings it to `main` and land it.

Then merge the branch tip back into `main`. The tag is on the branch, so the
merge brings the tag into the history of `main`. The version of every `main`
build comes from `git describe`, which finds only tags that the commit
descends from. The release notes and `just check-version` find the previous
release the same way. Without the merge, they all keep counting from the
previous release. The merge also records the commits after the tag, so the
next `git cherry` does not list a fix that is already ported.

The merge uses the `ours` strategy, which keeps the tree of `main` and
records only the history. It drops any change on the branch that `main`
lacks, so merge only after `main` has every fix in the list:

```sh
git switch -c chore/merge-back-X.Y.Z origin/main
git merge -s ours origin/release/X.Y.x -m "Merge branch 'release/X.Y.x' into main"
```

Push the branch and open a PR. The PR must go in as a merge commit, because
the other merge buttons drop the link to the branch and its tag. The merge
queue squashes every PR, so this PR cannot go through it.
[`merge-back.yml`](#merge-backyml-merge-a-line-into-main) automates this step
once it is enabled. Until then, someone on the bypass list of the `main` ruleset
does these things:

1. Turns on **Create a merge commit** in the repository settings.
2. Merges the PR outside the queue, with a merge commit.
3. Turns the setting off again.

Then check that the tag is on `main`:

```sh
git fetch origin main:refs/remotes/origin/main
git merge-base --is-ancestor vX.Y.Z origin/main && echo "tag on main"
```

### Stage a patch

A patch is the next version on a release line. It does not need a new branch,
and it does not use step 1 or step 2. The weekly patch and an emergency fix both take
this path. A second release candidate, and the final version after the
candidates, go out from the line in the same way.

Only the newest line gets patches. The version check refuses a version below
the newest `v*` tag, so a line stops when the next minor is promoted.

Do these steps:

1. Land each fix on `main` first, then cherry-pick it to `release/X.Y.x` by
   PR. Once [`backport.yml`](#backportyml-open-a-pr-on-a-release-line) is
   enabled, the `backport release/X.Y.x` label opens that PR for you. Title the PR `fix:`, because a `feat:` or breaking subject on the line
   requires a minor and fails the version check. Land the `package.version`
   bump by PR if the line is not already on the next patch.
2. Check that the five required checks from step 1 are green on the branch
   tip, and check the version there:

   ```sh
   git fetch origin release/X.Y.x
   git switch --detach FETCH_HEAD
   just check-version
   ```

3. Follow steps 3 to 6 with `--ref release/X.Y.x`. For the final version,
   also follow steps 7 and 8. A release candidate stops after step 6.

[`stage-release.yml`](#stage-from-a-release-line) does step 2 here, and steps 3
and 4 above, in one dispatch. Then continue from step 5.

### Emergency release

An emergency release abandons any staged version that no one promoted. The
abandoned version never goes out, and its number stays used up, because
`versions/` is write-once.

Suppose that a run stages the planned `0.7.3` for Monday. An emergency on
Thursday takes the next number, `0.7.4`, and goes out from the tip of the line.
On Monday, do not promote `0.7.3`, because that moves `stable` backwards. The
tip already has everything that was in `0.7.3`. The next planned version is
`0.7.5`.

1. Merge the fix into the line. Set `package.version` to the next unused
   number. The number of a staged version does not count as unused, even if
   the line still declares it.
2. Stage it, test it, and promote it as usual. A short soak is your decision.
3. Leave the abandoned version alone. Do not delete its folder or its draft
   GitHub Release, because the draft is how `gominimal/release-ops` knows that no
   one can use the number again.

The [release manager runbook](https://github.com/gominimal/release-ops/blob/main/RUNBOOK.md)
says who decides and how to log the release.

### Roll back

Run the promotion again with `target=stable`, `rollback=true`, and an earlier
version that has a smoke record. Without `rollback=true`, the promotion refuses
a version below the current `stable`. It also refuses a version without a smoke
record. Choose a version that was on `stable` before, and choose it before you
promote. Use `override_provenance=true` only
in an emergency. The approval issue shows that you used it.

## Stage from a release line

Patches and release candidates go out from the newest `release/X.Y.x` line.
[`.github/workflows/stage-release.yml`](../../.github/workflows/stage-release.yml)
stages one with one dispatch. It replaces steps 1 to 4 above for a line that
exists:

```sh
gh workflow run stage-release.yml
```

Set `package.version` on the line by PR first. To stage a candidate, set it to
`X.Y.Z-rcN`. To stage the final version, set it to `X.Y.Z`. The final version
is a new build, even when it has the same commits as the last candidate.

The workflow does these things, in this order:

1. It picks the newest `release/X.Y.x` branch. Only the newest line gets
   patches.
2. It checks that the five required checks from step 1 are green on the tip.
3. It checks `package.version` on the tip against the computed version.
4. It runs `release.yml` on the line with `versioned=true` and `dry_run=true`,
   and waits.
5. It checks that the tip did not move, then runs `release.yml` with
   `versioned=true` and `dry_run=false`, and waits. If the run built any other
   commit, the workflow cancels it.

Then continue from step 5, [Test the staged release](#5-test-the-staged-release).

**The computed version.** A tag or a staged folder uses up a version number,
whether or not anyone promoted it.
[`scripts/stage-version.sh`](../../scripts/stage-version.sh) reads the tags and
the staged folders. The next final version is one patch above the highest final
version used on the line, or `X.Y.0` on a new line. The next candidate is one
above the highest candidate of that version, or `rc1`. A candidate uses up only
its own number. `package.version` must be one of those two. It must also pass
`next-version.sh --check`, so a `feat:` commit on a line stops the run.

| Used on `release/0.7.x` | Accepted `package.version` |
| --- | --- |
| `0.7.2`, `0.7.3-rc1` | `0.7.3-rc2` or `0.7.3` |
| `0.7.2`, `0.7.3-rc1`, `0.7.3-rc2` | `0.7.3-rc3` or `0.7.3` |
| `0.7.2`, `0.7.3-rc1`, `0.7.3` | `0.7.4-rc1` or `0.7.4` |

**Inputs.** `dry_run=true` stops after the dry run and uses up no number. Use
`restage=true` when a run failed after the staging job and the folder has no
smoke record. The workflow refuses to restage a folder that has one.

**What a dry run does not prove.** A dry run skips the uploads, so it can pass
on a line whose identity cannot write to the buckets. The first real stage from
`release/0.7.x` failed this way at the `gs://minimal-shim` upload. The failure
comes before the staging job, so it does not use up the number.

**If you stop the workflow.** Canceling `stage-release` or reaching its timeout
stops only the wait. A running `release.yml` run keeps going, so cancel it in the
Actions list as well.

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
| `minzoned` (every platform that has `min`) | [`scripts/dist-build.sh`](../../scripts/dist-build.sh) runs the link gate ([`scripts/check-zoned-links.sh`](../../scripts/check-zoned-links.sh)) on the binary it built. The release workflow runs the gate again on every renamed and signed artifact before upload. On macOS it also checks the signature against the designated requirement that `min` uses. |
| amd64 guest kernel, rootfs, and initramfs | `smoke-linux-kvm` boots them. |
| arm64 guest kernel, rootfs, and initramfs | `smoke-macos` boots them. |
| macOS arm64 `min`, `minvmd`, `libkrun.1.dylib`, `gvproxy-min` | `smoke-macos` runs the session e2e with the signed files in the installer layout. **Gap:** when the `RUN_MACOS_CI` variable is `false`, this job skips and the run counts the skip as a pass. |
| Linux arm64 `min`, `minimald`, `minvmd`, `gvproxy-min` on a Linux host | **Gap.** No smoke job runs on a Linux arm64 host. |
| Linux `mip`, amd64 and arm64 | **Gap.** `smoke-linux-kvm` downloads `mip`, but no job runs it. |
| `install.sh` and the AppArmor profile installer | The `ci-shell-installer` lane tests both scripts on each PR that changes them. **Gap:** no release job installs the staged folder through `install.sh`. |
| `completions.tar.gz` and the legacy `minimalone-<sha>.tar.zst` bundle | **Gap.** No job tests them. |

## Pipeline reference

### Staged folders and channels

Each release run uploads one folder, `gs://minimal-one/versions/<version>/`.
It holds the artifacts, a `components` manifest, a copy of `install.sh`, and
the release notes as `notes.md`. Each manifest row gives one component, its OS and architecture, its
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
| Stable promotion publishes | Nothing | GitHub Release |

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
check that runs in the `package_version` test on PRs that reach the Rust test
lanes. That script reads the full commit messages since
the last release tag. A `feat:` commit requires a minor bump. A breaking
change under any type also requires a minor bump, and appears first in the
notes. At 0.x it does not bump the major version. Anything else requires a
patch. The same check runs as the
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
  when `RUN_MACOS_CI` is not `false`. It builds `minvmd`, `min`, and
  `minzoned`, changes the libkrun link path in `minvmd` to `@rpath`
  ([`scripts/rewrite-macos-linkage.sh`](../../scripts/rewrite-macos-linkage.sh)),
  and checks that `min` and `minzoned` link only system libraries. It
  puts `minzoned` in an app bundle, `Minimal.app`. It signs `minvmd`, `min`,
  and the bundle with the Developer ID, the hardened runtime, and a
  timestamp. Then it notarizes all of them and staples the bundle. See the
  **The macOS app bundle** and **Notarization** paragraphs below.
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

**minzoned.** Every release that publishes `min` must also publish the
box-zone answerer binary. The session-start advisory (NET-122) copies it
into a root-owned host-service path. The scripts in this repository do their
half of the work:

- [`scripts/dist-build.sh`](../../scripts/dist-build.sh) builds `minzoned`
  in its own cargo invocation. A build beside `-p minvmd` or a `--workspace`
  build unifies the KVM backend into the binary, and a root host service must
  never contain it. The script then runs the link gate
  ([`scripts/check-zoned-links.sh`](../../scripts/check-zoned-links.sh))
  on the binary. Every library must resolve from a system directory. The
  binary must have no embedded search path, and its interpreter must be a
  system loader. If the gate fails, the build fails.
- [`scripts/stage-release.sh`](../../scripts/stage-release.sh) stages
  `bin/minzoned` beside `bin/min` on every Linux platform that has `min`. On
  macOS it stages the files of the app bundle under `bin/Minimal.app`, also
  beside `bin/min`. The staged copy is only the source that the advisory
  copies. No unit file and no `launchd` property list refers to it at its
  user-writable path.
- [`scripts/install.sh`](../../scripts/install.sh) installs it beside `min`
  and replaces it on upgrade, like every other `bin` row. On macOS an
  upgrade from a release that installed `bin/minzoned` removes that file,
  because the program is now in the bundle.

*Still optional in the scripts.* The release workflow uploads `minzoned`
on every platform, but `stage-release.sh` still accepts a missing
`minzoned` artifact with a warning that names the omitted row. It stages
all other artifacts. A release staged without it gives
no `minzoned` to the host. The advisory then shows the state `this release
ships no minzoned; the DNS service install is unavailable` and does not
offer the step. The optional list goes after a release publishes the
artifact on every platform.

*Identity model.* Each check runs where it has meaning:

- **The release proves link-cleanliness.** The link gate runs on the binary
  that `dist-build.sh` built. The release workflow runs it again on every signed
  and renamed artifact, as the last check before upload. The uploaded bytes
  are then the bytes that the gate checked. The user's machine does not run
  the gate.
- **The user side checks identity.** The source is beside `min` in a prefix
  that its user can write, so each user-side check is only a pre-check. On
  macOS, the advisory runs `codesign --verify --strict -R` on the app bundle
  with the Developer ID designated requirement. The requirement names Apple's
  Developer ID chain, the team in `subject.OU`, and the signing identifier.
  The signature covers the program, `Info.plist`, and the icon.
- The release build of `min` gets the team ID and the identifier at compile
  time, from `MINIMAL_ZONED_TEAMID` and `MINIMAL_ZONED_IDENTIFIER`.
  Without them, a release `min` does not offer the step, and it gives the
  reason `this build carries no signing identity`. It never falls back to
  `codesign --strict` alone, because any ad-hoc signature passes that check.
  Debug and test builds skip the check.
- On both operating systems, the advisory then pins the SHA-256 of the bytes
  that it checked. On macOS it pins each file of the bundle, because the
  signature does not cover the stapled ticket.
- **The privileged step checks the root-owned copy again** (design §7.1,
  post-install custody). The rendered root command examines the destination
  directory and each parent directory up to `/`. It stops at the first one
  that is not owned by root or that group or others can write to. The message
  names that directory. Without this check, a user can rename a directory on
  the path between the check and the rename. The sticky bit does not count: it
  only limits who can rename or remove an entry, and some macOS hosts set it
  on `/Library/PrivilegedHelperTools`.
  Both destinations pass on a stock host: `/Library/PrivilegedHelperTools` on
  macOS and `/usr/local/lib/minimal` on Linux. The command then runs
  `install` to an exclusive `mktemp` name in that directory and hashes the
  copy. If the hash is different, it removes the copy and exits with both
  hashes in the message. On macOS it runs the `codesign -R` check on the copy
  again. Then it renames the copy into place. Only after that does it write
  the unit or property list that names the copy. On macOS the copy is the
  whole bundle. The command makes it in an exclusive `mktemp -d` directory
  that only root can read, and hashes each file against its pin. It runs the
  `codesign -R` check on the directory, and then renames the directory to
  `/Library/PrivilegedHelperTools/Minimal.app`.

The release workflow
([`.github/workflows/release.yml`](../../.github/workflows/release.yml))
handles `minzoned` with the same steps that the other binaries have:

- `build-release-linux-{amd64,arm64}`: the shared entry point builds and
  link-gates `minzoned` already. The rename step adds
  `mv minzoned minzoned-linux-<arch>`. A new step runs the link gate
  on the renamed file, and one `upload-artifact` step uploads it.
- `build-release-macos-arm64`: the job's `env` gets
  `MINIMAL_ZONED_TEAMID` and `MINIMAL_ZONED_IDENTIFIER`, so the `min`
  that it builds has the signing identity. The job builds `minzoned` in
  its own invocation, link-gates it, and assembles `Minimal.app` around it.
- The job signs the bundle with the Developer ID, the hardened runtime, a
  timestamp, and `--identifier "$MINIMAL_ZONED_IDENTIFIER"`. The signature
  has no entitlements, unlike the `minvmd` signature. There is no hypervisor
  entitlement, no `disable-library-validation`, no
  `allow-dyld-environment-variables`, and no JIT. The job then checks the
  signature with the designated requirement that `min` uses.
- After the signature check, the link gate runs again on the signed
  program.
- The job notarizes the bundle with the other macOS binaries, staples it,
  and uploads its files. See the **The macOS app bundle** and
  **Notarization** paragraphs below.
- The release job and the stage-installer job stay the same. They collect
  artifacts by the platform-suffixed names, so the new names go into the
  GitHub Release and the `components` manifest. The SHA-256
  columns of the manifest are the checksums.

This section does not close these residuals:

- A shell-installer install on Linux, into the user's prefix, has no
  signature. The privileged step accepts the copy only up to the hash pin.
  That limit is inside the single-operator premise of design §7.1.
- `answerer_survives_session_stop` is the e2e proof that the installed
  answerer service continues after a session stops. It installs a root-run
  unit, and no macOS lane can run `sudo` without a password.
  [`scripts/session-e2e.sh`](../../scripts/session-e2e.sh) skips it there. A
  privileged macOS e2e runner is still necessary for that proof.

**The macOS app bundle.** macOS lists each `launchd` job in System Settings,
under General, then Login Items & Extensions. A job whose program is a bare
signed file has the developer's name and a placeholder icon. A job whose
program is not signed is an item from an unidentified developer. A job has
an app's name and icon only when its program is in an app bundle that the
vendor's Developer ID signs. So the release puts `minzoned` in a bundle, and
both jobs that `min finalize-install` installs run the program in the
root-owned copy of that bundle:

```
Minimal.app/Contents/Info.plist                    packaging/macos/Info.plist
Minimal.app/Contents/MacOS/minzoned                the program
Minimal.app/Contents/Resources/AppIcon.icns        packaging/macos/AppIcon.icns
Minimal.app/Contents/_CodeSignature/CodeResources  added by codesign
Minimal.app/Contents/CodeResources                 added by stapler
```

[`scripts/build-app-bundle.sh`](../../scripts/build-app-bundle.sh) assembles
the first three files. `just app-bundle` runs it on a debug `minzoned` and
writes an unsigned bundle to `target/app-bundle`. The bundle identifier in
`Info.plist` is the signing identifier, `MINIMAL_ZONED_IDENTIFIER`. The
release job fails if they are different.

A release publishes flat files, not directories. After the job staples the
bundle, `build-app-bundle.sh flatten` copies each bundle file to a flat
name that starts with `minzoned-macos-arm64`. The program keeps the name
`minzoned-macos-arm64`. `stage-release.sh` installs each flat file at its
path under `bin/Minimal.app`, and `scripts/stage-release_test.sh` fails if
the two tables are different. The job then makes the bundle again from the
flat files, as the installer does. It runs the `codesign -R` check and
`stapler validate` on that copy.

The program in the bundle does not pass `codesign --verify` as a file by
itself, because its signature names the bundle's `Info.plist`. It still
runs. Do not use `minzoned-macos-arm64` from the GitHub Release without the
other bundle files.

The range job has no script when the step installs the bundle. Its program is
`minzoned reserve-local-range`, and the range is a constant in the program.
A script has no signature that macOS can read, so a job that runs a script
stays an item from an unidentified developer.

To test the job without a release, run `release.yml` with `dry_run` set. It
builds, signs, notarizes, staples, and checks the bundle, and it publishes
nothing. The name and icon in System Settings are a manual check. Run
`min finalize-install` from that build on a Mac. `sfltool dumpbtm` then
shows the two jobs with `Minimal.app` as their parent.

**The `bep` app bundle.** The release puts `bep`, the Box Egress Proxy,
inside `bep.app`. A release `bep` generates its keys in the Secure Enclave and
keeps them in the data-protection keychain, under the keychain access group
`3G47C5HY64.dev.minimal.bep`. macOS grants that group only to a program
signed with the `keychain-access-groups` entitlement. It honours the
entitlement only when a provisioning profile in the program's bundle
authorises it. A debug `bep` keeps its keys in the login keychain and needs
no bundle.

```
bep.app/Contents/Info.plist                    packaging/macos/bep/Info.plist
bep.app/Contents/MacOS/bep                     the program
bep.app/Contents/embedded.provisionprofile     the Developer ID profile
bep.app/Contents/_CodeSignature/CodeResources  added by codesign
bep.app/Contents/CodeResources                 added by stapler
```

[`scripts/build-bep-bundle.sh`](../../scripts/build-bep-bundle.sh)
assembles the first three files, and flattens and rebuilds the bundle as
`build-app-bundle.sh` does for `Minimal.app`. The flat names start with
`bep-macos-arm64`. `stage-release.sh` installs them under `bin/bep.app`, and
links `bin/bep` to `bep.app/Contents/MacOS/bep`, so `minvmd` still finds
`bep` beside itself. The job signs the bundle with the identifier
`dev.minimal.bep` and the entitlements in
`packaging/macos/bep/bep.entitlements`, then notarizes and staples it.

The profile is the repository secret `MACOS_BEP_PROVISION_PROFILE`: the
Developer ID provisioning profile for the App ID `dev.minimal.bep`, base64
encoded. `build-bep-bundle.sh check-profile` checks its team, its
application identifier, its keychain access groups, that it provisions every
Mac, and its expiry. The release fails if one is wrong. `scripts/build-bep-bundle_test.sh` tests that
check. The profile names one Developer ID Application certificate. When you renew
that certificate, make the profile again against the new certificate and
replace the secret.

Secure Enclave keys never leave the Mac that made them. A Mac restored from
a backup, migrated to new hardware or reset has no proxy keys. `bep` makes
new ones at its next start when it published none before. Otherwise, run
`bep --replace-key <role>` for each role it names. Seal again each value
that you sealed to the old sealing key, and create again each box that you
created before then. The keys of an earlier release stay in the login keychain,
where this release does not look for them.

**Notarization.** After the signature checks and the last link gate,
`build-release-macos-arm64` sends `min`, `minvmd`, and the `bep` and
`minzoned` app bundles to the Apple notary service before it uploads them. The step puts
each one in a zip made with `ditto`, because `notarytool` does not take a
bare Mach-O file or a bundle directory. It runs
`xcrun notarytool submit --wait` on each zip. The
release fails unless each result is `Accepted`. On any other result, the
step prints the notary log for that submission. Notarization does not
change the file, so the job uploads the same signed bytes.

The job does not staple `min` or `minvmd`. The release publishes each as a
bare Mach-O file, and `stapler` can attach a ticket only to an app bundle, a
`.pkg`, or a `.dmg`. Gatekeeper gets the ticket from Apple online when it
checks a binary. The job staples the two app bundles. The ticket is the file
`Contents/CodeResources`, which the signature does not cover.

The step needs two things that the workflow cannot set up:

- A `notarytool` keychain profile in the signing keychain
  (`minimal-signing.keychain-db`) on the self-hosted macOS runner. Create it
  as the runner user with
  `xcrun notarytool store-credentials <profile> --keychain
  ~/Library/Keychains/minimal-signing.keychain-db`. Give it an App Store
  Connect API key (`--key`, `--key-id`, `--issuer`), or an Apple ID with an
  app-specific password and team `3G47C5HY64`. The step unlocks the keychain
  with the `KC_PW` secret from the `release` environment, as the signing
  steps do. The last step of each signing job locks it again.
- The repository variable `MACOS_NOTARY_PROFILE`, set to the profile name.
  If the variable is empty, the step fails before it submits anything.

`libkrun.1.dylib` and the macOS `gvproxy`, which `sign-macos-artifacts`
signs, are not notarized.

**release job.** This job downloads all build outputs. It writes the release
notes with `scripts/next-version.sh --notes` and generates shell completions
for `mip`, `min`, and `minimald`. Then it does two things:

- It uploads the legacy `minimalone-<sha>.tar.zst` bundle to
  `gs://minimal-shim/archives/` for the old `minimal-shim` install path.
- It creates the GitHub Release with the notes, the binaries, the guest
  artifacts, and `completions.tar.gz`. A nightly build gets
  `release-<sha>`. A versioned run gets a draft `vX.Y.Z` that points at the
  commit. A version with a `-` suffix is a prerelease. On a rerun, the job
  replaces a draft that an earlier attempt left. It keeps a `release-<sha>`,
  because people can already have its files, and uploads only the assets it
  lacks. If an asset it has differs from this build, the job fails. It never
  replaces a public `vX.Y.Z`, so a rerun fails on one.

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
layout. The smokes also run on a dry run. The section on artifact tests above
lists what they do not cover.

**record-smoked job.** After the smokes and the staging pass,
[`scripts/record-smoked.sh`](../../scripts/record-smoked.sh) writes
`versions/<version>/smoked`. The file holds the SHA-256 of the staged
`components` manifest, the commit, and the run URL. The promotion compares
this hash with the live manifest, so a folder that someone stages again does
not keep an old result. For a nightly or plain build, `set-channel.sh` then
moves `unstable` to the version, with no approval. A versioned build does not
move `unstable`.

### cut-minor.yml: start a minor release

Only a minor release gets a new branch. Patches come from the line.
[`.github/workflows/cut-minor.yml`](../../.github/workflows/cut-minor.yml) starts
a minor. It runs only on dispatch from `main`, and it replaces step 2 above:

```sh
gh workflow run cut-minor.yml -f commit=<commit>
```

Leave out `commit` to cut from the tip of `main`. Use `-f dry_run=true` to make
every check and create nothing.

The workflow refuses a commit that is not on `main`, or that does not have the
five required checks green. It also refuses one whose `package.version` is not
`X.Y.0` or `X.Y.0-rcN`, and one that fails `next-version.sh --check`. Then it does
these things. Step 1 runs as the `minimal-release-ops` App, which can bypass the
release branch rules. Steps 2 and 3 run as `minimal-backporter`, which cannot:

1. It creates `release/X.Y.x` at the commit.
2. It creates the `backport release/X.Y.x` label.
3. It opens a PR that moves `main` to the next minor. Merge this PR before you
   promote the version at the commit, `vX.Y.0` or `vX.Y.0-rcN`. Once that tag
   exists, `main` still declares the same version and its version check fails.

Then continue from step 3 of [Cut a stable release](#cut-a-stable-release),
with `--ref release/X.Y.x`.

Run it again after a failure, and pass the original `commit` on every rerun.
Without it, the rerun cuts from the tip of `main`. After the bump PR merges,
that tip is the next minor, and the rerun cuts the next line. It carries on if
the line already exists at the same commit, and it refuses a line at any other
commit. If the bump branch exists with no PR, it opens the PR. It does not
open a bump PR when the branch already has an open or merged one. It also does
not open one when `main` no longer declares the version at the commit.

**Admin step for each new line.** An organization owner adds
`gominimal/minimal/.github/workflows/release.yml@refs/heads/release/X.Y.x`
to the `signing` runner group, because the workflow cannot. See
[step 2](#2-give-the-commit-a-branch).

The buckets do not need a change. Both Workload Identity providers map any
`release/X.Y.x` branch to `attribute.minimal_release`, which has write access to
`gs://minimal-shim` and `gs://minimal-one`.

The workflow itself needs one admin step, once: add `minimal-release-ops` as a bypass
actor on the `release branches` repository rules. Those rules stop anyone else
from creating a branch under `release/`.

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
`version`, `target`, `dry_run`, `override_provenance`, and `rollback`. `version` is a
version number or a nightly commit hash. When you leave it empty, the
workflow uses the newest staged nightly build, so an empty `version` works
only for `unstable`.

**Approval.** The `gate` job opens an approval issue, sends an
`approval-requested` event to release-ops (see
[Slack notifications](#slack-notifications)), and waits. If no approver
decides within 350 minutes, the gate stops, just before its six-hour limit. Any member of the `@gominimal/minimalists` team can approve, except
the person who started the run. The workflow reads the team once, when the
gate opens. A change to the team's membership applies from the next
promotion, not to one already waiting. If the workflow cannot read the team,
or the team has no other member, the gate fails and the workflow promotes
nothing. An approver comments
`approved` or `denied`. If someone closes the issue without an approval, the
workflow stops.

**Version guards.** Run promotions from `main`. A release branch that predates
these guards runs its older workflow, which does not enforce them.
Before a promotion to `stable` moves anything, the `promote`
job runs [`scripts/check-promotion.sh`](../../scripts/check-promotion.sh)
against the current `stable`. The job runs after the approval, because `stable`
can move while the approval waits. A dry run makes the same checks. The
`promote` job runs one at a time for each channel, so two approved runs cannot
both pass the check and then write out of order. GitHub keeps one waiting
run for each channel: a third run cancels the waiting one, which you must then
start again. A dry run waits in its own queue and never cancels a real run.

- It refuses a candidate, such as `0.7.3-rc2`. No input turns this off. A
  candidate is for soak only, so stage the final version.
- It refuses a version below the current `stable`, unless you set `rollback`. For
  example, a run stages `0.7.3`, an emergency promotes `0.7.4`, and someone then
  promotes `0.7.3` on the planned day. The approval issue shows `rollback`.
- It refuses a nightly commit hash. Only a staged release goes to `stable`;
  promote nightlies to `unstable`. No input turns this off.
- If `stable` already holds a nightly commit hash, a release replaces it with a
  warning, because there is no order to check.

**Smoke check.** The `promote` job runs
[`scripts/verify-smoked.sh`](../../scripts/verify-smoked.sh). It compares the
hash in the `smoked` record with a new hash of the live `components` manifest.
A version with no record fails. A folder that someone staged again after its
smoke also fails. `override_provenance` skips this check in an emergency, and the
approval issue shows that choice.

**Channel move and docs.** `set-channel.sh` moves the channel. The job then
sends a `reference-docs-promoted` event to `gominimal/webapp` with the release
commit, and the docs site at docs.minimal.dev rebuilds from that commit.

**Next-patch bump.** After a real `stable` promotion of `X.Y.Z`, the `bump-line`
job sets `package.version` to the next patch with
[`scripts/set-package-version.sh`](../../scripts/set-package-version.sh). It opens
a PR from `chore/bump-X.Y.Z+1` to `release/X.Y.x`, as the `minimal-backporter` App, so
CI runs on the PR. The job does nothing unless the line still declares the version
it just promoted, so a rollback changes nothing. A rerun changes nothing when
the branch already has an open or merged PR. If the branch exists with no PR,
because an earlier run pushed it and then failed to open the PR, a rerun opens
the PR. The job does nothing for a nightly commit hash, or when the line does
not exist. It fails if it cannot read the line, so you can run it again.

To start the next version with a candidate, change the PR to `X.Y.Z-rc1` before
you merge it.

**Release publish.** A `stable` promotion that is not a dry run then runs
the `publish` job. It publishes the draft `vX.Y.Z`. Publication creates the
tag on the release commit. It does not start a build. The job fails if the
release does not exist. If the release is already public, the job changes
nothing, but it fails if the `vX.Y.Z` tag is missing or is not on the
release commit. For a nightly commit hash, it prints a notice and does
nothing.

**Report to release-ops.** After a real `stable` promotion, the `report-release`
job sends a `release-promoted` `repository_dispatch` to `gominimal/release-ops`
with the version and the person who started the run. The `record-release.yml`
workflow there appends the version to `releases` in `rotation.yaml`, with a
commit to `main`. It skips a version that it already logged, so a rerun or a
rollback changes nothing. A nightly commit hash is not reported. Do not edit
`releases` by hand.

### Slack notifications

The workflows do not post to Slack themselves. They send a `release-event`
`repository_dispatch` to `gominimal/release-ops`, through the
[`release-event`](../../.github/actions/release-event/action.yml) action, and
release-ops posts it in `#releases`. The token comes from the
`minimal-backporter` App, whose key is in the `release` environment. A send
that fails only warns, so it never fails a release job. Dry runs send nothing.

| Event | When | Where it posts |
| --- | --- | --- |
| `stage` | A `stage-release` run ends: success, failure (with the job that failed), or cancelled | The week's handoff thread |
| `approval-requested` | `promote` opens its approval issue, with a link to it | The week's handoff thread |
| `promote` | A promotion does not go through: refused (an approver denied, or the issue was closed), timed out (no decision in 350 minutes), failed, or cancelled | The week's handoff thread |
| `rollback` | A `rollback=true` promotion to `stable` ends, as success or failure | The week's handoff thread |
| `nightly-failed` | A `nightly` run fails or is cancelled, with the `check`, `release` and `promote-nightly` results | Top level of the channel |

A promotion that succeeds sends no `promote` event. For `stable`, release-ops
posts it from the `release-promoted` event that `report-release` already sends.
A successful promotion to `unstable` sends neither event, so nothing posts.

### merge-back.yml: merge a line into main

> Not enabled. The workflow does nothing until the repository variable
> `MERGE_BACK_ENABLED` is `true`, and it stays unset until the design is agreed.
> The `minimal-release-ops` App is already a bypass actor on the `main` ruleset, so
> the variable is the only switch. Until then, use the manual merge in the
> release steps. The job runs only when dispatched from `main`.

[`.github/workflows/merge-back.yml`](../../.github/workflows/merge-back.yml)
does the manual merge-back as one run, outside the merge queue. The queue
squashes every PR, and a squash drops the link to the tag. A person starts the
run after a stable promotion. Its inputs are `version` and `reviewed`.

The run uses [`scripts/merge-back.sh`](../../scripts/merge-back.sh):

1. It stops if the tag `vX.Y.Z` is not on `release/X.Y.x`.
2. It does nothing if the line is already on `main`.
3. It runs `git cherry` against `main`, on the line tip and not the tag. A fix
   can merge into the line after the tag.
4. If a line commit has no identical patch on `main`, the workflow opens an
   issue that lists the commit, and stops. It updates the open issue on a
   second run. It does not merge.
5. It merges the line with the `ours` strategy, which keeps the tree of `main`.
   It pushes the merge commit to `main`, without force.

`git cherry` always lists the version bumps, and each pick with resolved
conflicts. For each commit in the issue, land the fix on `main` if `main` does
not have it. Then run the workflow again, and put each remaining commit in
`reviewed`. Those are the commits that `main` has in another form, or does not
need. The issue marks a commit whose `cherry-pick -x` source is on `main`, but
you must still read it. The merge drops any change that only the line has.

If `main` moves during the run, the push fails and changes nothing. Run the
workflow again.

### prune-releases.yml: delete old nightly releases

[`.github/workflows/prune-releases.yml`](../../.github/workflows/prune-releases.yml)
starts at 04:17 UTC on Mondays and Fridays. A manual run defaults to a
preview. It deletes `release-<sha>` GitHub Releases and their tags after two
months, and it always keeps the newest ten. The logic is in
[`scripts/prune-releases.sh`](../../scripts/prune-releases.sh). It never
deletes a `vX.Y.Z` release. The installer reads from the bucket, so pruning
does not remove anything that users install.

### backport.yml: open a PR on a release line

[`.github/workflows/backport.yml`](../../.github/workflows/backport.yml) picks
a merged `main` PR onto a release line and opens a PR there. It uses
[`korthout/backport-action`](https://github.com/korthout/backport-action).

The workflow does nothing until the repository variable `BACKPORT_ENABLED` is
`true`. Before an admin sets it:

- The labels `backport release/X.Y.x` and `backport-conflict` must exist.
- The repository setting `squash_merge_commit_title` must be `PR_TITLE`, and the
  `release branches` ruleset must allow only squash merges. See the merge rule
  below.
- The repository setting that allows rebase merges must be off. The workflow
  reads one merge commit, so a rebase-merged PR is picked commit by commit and
  the guard sees only the last one.
- Each line that takes backports must run the conflict-marker scan. A line cut
  before the scan existed needs `scripts/check-conflict-markers.sh` and the
  `conflict-markers` job ported to it by hand.

**Start a backport.** Add the label `backport release/X.Y.x` to a PR on `main`.
The run starts when the PR merges, or when you add the label to a merged PR.

**Title guard.**
[`scripts/backport-title-guard.sh`](../../scripts/backport-title-guard.sh)
refuses a `feat` title and a breaking title, because either one forces the line
to the next minor. It also refuses a source commit with a `BREAKING CHANGE`
footer. The run comments on the source PR and stops. If the change is safe on
the line, retitle the source PR as `fix`, then remove the label and add it
again. A retitle does not remove a footer, so backport that change by hand.

**The backport PR.** The action cherry-picks the squash commit to the branch
`backport/<number>-to-release/X.Y.x`. It opens the PR as `minimal-backporter`,
with the title of the source PR. The body names the source PR. It does not copy
the source body, because agent-runtime reads `Closes #n` in a PR body as a link
to an epic.

**Merge rule.** Squash-merge the PR, and keep the PR title as the subject. A
cherry-picked commit keeps the source subject. A rebase merge puts that subject
on the line, so a retitled `feat` still forces a minor. A squash of one commit
does the same under any other setting.

**Conflicts.** The action commits the first conflict as it stands, in a commit
named `BACKPORT-CONFLICT`. Then it opens a draft. The workflow adds the label
`backport-conflict`, and adds the source PR, the source commit, and the
conflicted paths to the PR body. Resolve each path on the branch, then mark the
PR ready. A modify/delete conflict does not leave conflict markers, so check
each path in the list.

**Workflow files.** The token has no `workflows` permission. GitHub refuses the
push of a pick that changes `.github/workflows`, and the run reports that on
the source PR. Backport those changes by hand.

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

- Linux amd64 and arm64: `bin/min`, `bin/minzoned`, `bin/mip`,
  `bin/minimald`, `bin/minvmd`, `bin/gvproxy-min`, a `git-remote-min` symlink,
  the guest files (`data/vmlinuz`, `data/rootfs.img`, `data/initramfs.cpio`),
  and the AppArmor profile, tunable, and loader under `data/`.
- macOS arm64: `bin/min`, the `bin/Minimal.app` bundle that contains
  `minzoned`, `bin/minvmd`,
  `bin/gvproxy-min`, `lib/libkrun.1.dylib`, the `git-remote-min` symlink, and
  the same guest files. Only macOS has a `lib/` folder, because the Linux
  `minvmd` links libkrun statically.

`bin/minzoned` is the box-zone answerer binary that the session-start
advisory copies into its root-owned service path. On macOS it is in
`bin/Minimal.app`, and the advisory copies the bundle. The installer puts it
beside `min`, and nothing else refers to it there. Manifest rows write no
unit file and no `launchd` property list. None of them names the root-owned
service path that the advisory's privileged command creates.

The installer also adds shell setup: PATH init files, `min` completions, and
one marked block in the shell rc file. `--uninstall` removes all of it with no
network access, from the local install record. It keeps files that you
changed unless you add `--force`. `--purge` also deletes the data, state, and
cache folders.

### ci.yml: the conflict-marker scan

The `conflict-markers` job in
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs
[`scripts/check-conflict-markers.sh`](../../scripts/check-conflict-markers.sh)
on every PR and push. It fails on a conflict marker in a tracked text file. The
required check `ci-success` depends on it, so a PR with markers cannot merge.

For a PR, GitHub runs the `ci.yml` of the merge with the base branch. The scan
covers a release line only when that line has this job. A line cut from `main`
has it. An older line needs this job and the script ported by PR.

The scan does not see a modify/delete conflict, because that conflict leaves no
markers. The list of conflicted paths in the draft PR body names those paths.
