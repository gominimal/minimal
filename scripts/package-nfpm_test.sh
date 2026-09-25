#!/usr/bin/env bash
#
# package-nfpm_test.sh — test harness for scripts/package-nfpm.sh.
#
# The script has two artifact sources (the release run's own ARTIFACTS_DIR and
# the staged bucket row) that release.yml and `just pkg-nfpm` dispatch to
# separately; nothing else compares them. This harness drives BOTH against
# fixtures with a stub nfpm (NFPM_BIN) and a stub `min` (for completions), no
# network and no pinned download, and asserts the anti-drift contract: the two
# branches resolve the SAME canonical version and produce IDENTICAL nfpm argv
# for a released semver. It also covers the per-format channel normalization and
# the refusals. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/package-nfpm.sh"
[ -f "$script" ] || { echo "cannot find package-nfpm.sh next to test" >&2; exit 1; }
# shellcheck disable=SC1091  # dynamic path: testlib.sh sits beside this harness
. "$here/testlib.sh"

require_tools curl
# sha256_of (sourced below) needs sha256sum or shasum; the harness computes
# fixture digests with it, so skip where neither exists.
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
    || { echo "${0##*/}: skipping, no sha256sum/shasum on PATH"; exit 0; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-nfpmtest)"
trap 'rm -rf "$root"' EXIT

# The digest routine must match the script's, so it is extracted rather than
# copied: one definition.
source_function "$script" sha256_of

# --- fixtures -----------------------------------------------------------------

# The release run's own build output: every basename the driver copies, both
# arches. minimal-linux-* is the stub `min` (the completions step runs the host
# arch's copy); the rest only need to exist.
artifacts="$root/artifacts"
mkdir -p "$artifacts"
stub_min="$root/stub-min"
cat >"$stub_min" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# A stub for `min completions install ...`: writes the three files the driver
# asserts on, unless told to write nothing (the completions-assertion test).
[ "${STUB_MIN_WRITE_NOTHING:-0}" = 1 ] && exit 0
data="${XDG_DATA_HOME:?stub min expects XDG_DATA_HOME}"
mkdir -p "$data/bash-completion/completions" "$data/zsh/completions" "$data/fish/completions"
printf 'stub bash completion\n' >"$data/bash-completion/completions/min"
printf 'stub zsh completion\n'  >"$data/zsh/completions/_min"
printf 'stub fish completion\n' >"$data/fish/completions/min.fish"
EOF
chmod +x "$stub_min"
for arch in amd64 arm64; do
    cp "$stub_min" "$artifacts/minimal-linux-$arch"
    for name in minimald mip minvmd gvproxy; do
        printf 'stub binary of %s %s\n' "$name" "$arch" >"$artifacts/$name-linux-$arch"
    done
done
# An incomplete local build output (one file missing) for the refusal below.
incomplete="$root/incomplete"
mkdir -p "$incomplete"
cp "$stub_min" "$incomplete/minimal-linux-amd64"

# The bucket fixture: an immutable staged row carrying a `version` file and the
# same basenames, plus the components manifest the driver verifies downloads
# against. Content is distinct per row so the digests differ.
bucket="$root/bucket"
stage_row() {
    local row="$1" version="$2" rowdir="$bucket/versions/$1"
    mkdir -p "$rowdir"
    printf '%s\n' "$version" >"$rowdir/version"
    : >"$bucket/versions/$row/components"
    for arch in amd64 arm64; do
        cp "$stub_min" "$rowdir/minimal-linux-$arch"
        for name in minimald mip minvmd gvproxy; do
            printf 'stub binary of %s %s at %s\n' "$name" "$arch" "$row" >"$rowdir/$name-linux-$arch"
        done
        for name in minimal minimald mip minvmd gvproxy; do
            file="$rowdir/$name-linux-$arch"
            sha="$(sha256_of "$file")"
            # component os arch version sha256 kind dest src
            printf '%s linux %s %s %s binary /usr/bin/%s versions/%s/%s-linux-%s\n' \
                "$name" "$arch" "$version" "$sha" "$name" "$row" "$name" "$arch" \
                >>"$bucket/versions/$row/components"
        done
    done
}
stable_row=0.5.4
channel_row=8e7e72c2
canonical="0.6.0-dev.10.g8e7e72c2"
stage_row "$stable_row" "$stable_row"
stage_row "$channel_row" "$canonical"

# The stub nfpm: proves the driver resolved a binary (NFPM_BIN bypasses the
# pinned download) and records each invocation's argv plus the driver-exported
# PKGVER/NFPM_ARCH — the surface the two branches must agree on.
stub_nfpm="$root/stub-nfpm"
cat >"$stub_nfpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
    --version) echo "nfpm version v0.0.0-stub"; exit 0 ;;
esac
log="${NFPM_STUB_LOG:?stub nfpm expects NFPM_STUB_LOG}"
target=""; prev=""
for a in "$@"; do
    [ "$prev" = "--target" ] && target="$a"
    prev="$a"
done
# argv only (the config path is under the repo root, identical for both
# branches); ARTIFACT_DIR is deliberately not recorded, it differs by design.
printf '%s|PKGVER=%s NFPM_ARCH=%s\n' "$*" "$PKGVER" "$NFPM_ARCH" >>"$log"
mkdir -p "$target"
printf 'stub package\n' >"$target/minimal-$NFPM_ARCH.stub"
EOF
chmod +x "$stub_nfpm"

out_dir="$root/out"
mkdir -p "$out_dir"

# run <log> <pkgver> [extra args] — drive the script with a stub nfpm, from the
# local build output (run_artifacts) or the staged bucket row (run_bucket).
run_artifacts() {
    local log="$1" pkgver="$2"; shift 2
    NFPM_BIN="$stub_nfpm" NFPM_STUB_LOG="$log" PKGVER="$pkgver" \
        ARTIFACTS_DIR="$artifacts" OUT_DIR="$out_dir" \
        "$script" "$@"
}

run_bucket() {
    local log="$1" pkgver="$2"; shift 2
    NFPM_BIN="$stub_nfpm" NFPM_STUB_LOG="$log" PKGVER="$pkgver" \
        MINIMAL_BUCKET_URL="file://$bucket" OUT_DIR="$out_dir" \
        "$script" "$@"
}

# --- the anti-drift contract: both branches agree on a released semver --------

al="$root/artifacts.log"; bl="$root/bucket.log"
a_out="$(run_artifacts "$al" "$stable_row" 2>&1)"; a_rc=$?
b_out="$(run_bucket "$bl" "$stable_row" 2>&1)"; b_rc=$?

if [ "$a_rc" -eq 0 ]; then ok "ARTIFACTS_DIR mode succeeds"; else bad "ARTIFACTS_DIR mode succeeds (rc=$a_rc; out: $a_out)"; fi
if [ "$b_rc" -eq 0 ]; then ok "bucket mode succeeds"; else bad "bucket mode succeeds (rc=$b_rc; out: $b_out)"; fi
if [[ "$a_out" == *"version $stable_row (row $stable_row)"* ]]; then
    ok "ARTIFACTS_DIR mode resolves the stable semver"
else
    bad "ARTIFACTS_DIR mode resolves the stable semver (out: $a_out)"
fi
if [[ "$b_out" == *"version $stable_row (row $stable_row)"* ]]; then
    ok "bucket mode resolves the same stable semver"
else
    bad "bucket mode resolves the same stable semver (out: $b_out)"
fi
if [ -s "$al" ] && diff <(sort "$al") <(sort "$bl") >/dev/null; then
    ok "both branches produce identical nfpm argv + PKGVER/ARCH"
else
    bad "both branches produce identical nfpm argv + PKGVER/ARCH differ:
--- ARTIFACTS_DIR ---
$(cat "$al")
--- bucket ---
$(cat "$bl")"
fi
# Six invocations (3 formats x 2 arches) is the shape the driver promises.
if [ "$(wc -l <"$al")" -eq 6 ]; then ok "one nfpm invocation per format x arch (6)"; else bad "expected 6 nfpm invocations, got $(wc -l <"$al")"; fi

# --- channel normalization ----------------------------------------------------

cl="$root/channel.log"
c_out="$(BUILT_VERSION="$canonical" run_artifacts "$cl" "$channel_row" --channel unstable 2>&1)" || true
if grep -q 'PKGVER=0.6.0~dev.10.g8e7e72c2' "$cl"; then
    ok "deb/rpm normalize the dev version with ~"
else
    bad "deb/rpm normalize the dev version with ~ (log:
$(cat "$cl"))"
fi
if grep -q 'PKGVER=0.6.0_dev.10.g8e7e72c2' "$cl"; then
    ok "apk normalizes the dev version with _"
else
    bad "apk normalizes the dev version with _ (log:
$(cat "$cl"))"
fi
if [[ "$c_out" == *"version 0.6.0~dev.10.g8e7e72c2 (row $channel_row)"* ]]; then
    ok "the canonical built version stays the source (PKGVER is the row)"
else
    bad "the canonical built version stays the source (out: $c_out)"
fi

# --- completions assertion ----------------------------------------------------

expect 1 "completions install did not write" "a stub min that writes nothing fails the completions assertion" -- \
    env STUB_MIN_WRITE_NOTHING=1 NFPM_BIN="$stub_nfpm" NFPM_STUB_LOG="$root/none.log" \
        PKGVER="$stable_row" ARTIFACTS_DIR="$artifacts" OUT_DIR="$out_dir" "$script"

# --- refusals -----------------------------------------------------------------

expect 1 "must not carry the v prefix" "a v-prefixed PKGVER is refused" -- \
    run_artifacts "$root/r.log" v0.6.0
expect 1 "is not a semver" "a non-semver PKGVER on stable is refused" -- \
    run_artifacts "$root/r.log" 0.6
expect 1 "is not a commit sha" "a semver row on a channel is refused" -- \
    run_bucket "$root/r.log" "$stable_row" --channel nightly
expect 1 "BUILT_VERSION is required" "a channel row in ARTIFACTS_DIR mode needs BUILT_VERSION" -- \
    run_artifacts "$root/r.log" "$channel_row" --channel nightly
expect 1 "ARTIFACTS_DIR not found" "a missing ARTIFACTS_DIR is refused" -- \
    env NFPM_BIN="$stub_nfpm" NFPM_STUB_LOG="$root/r.log" PKGVER="$stable_row" \
        ARTIFACTS_DIR="$root/nope" OUT_DIR="$out_dir" "$script"
expect 1 "missing local artifact" "a missing local artifact is refused" -- \
    env NFPM_BIN="$stub_nfpm" NFPM_STUB_LOG="$root/r.log" PKGVER="$stable_row" \
        ARTIFACTS_DIR="$incomplete" OUT_DIR="$out_dir" "$script"
expect 1 "unknown --channel" "an unknown channel is refused" -- \
    run_artifacts "$root/r.log" "$stable_row" --channel beta
expect 1 "unknown format" "an unknown format is refused" -- \
    run_artifacts "$root/r.log" "$stable_row" --formats msi
expect 1 "selected nothing" "--formats selecting nothing is refused" -- \
    run_artifacts "$root/r.log" "$stable_row" --formats ""

finish
