#!/usr/bin/env bash
#
# stage-release.sh — publish a release into the distribution GCS bucket in the
# layout the curl|bash installer expects (docs/specs/07-spec-installer).
#
# Given a directory of built release artifacts (the flattened output of the
# release workflow's download-artifact step), this script:
#
#   1. Computes the SHA-256 of every artifact that applies to some platform.
#   2. Writes a `components` manifest — a flat, whitespace-delimited table with
#      one row per (component, os, arch) variant — describing what the installer
#      must download and where to place it.
#   3. Uploads the artifacts and the manifest under `versions/<VERSION>/` with
#      immutable cache headers.
#
# Staging is inert: it never changes which version users get. Publishing a
# version to a channel (making `stable`/`unstable` point at it) is a separate,
# reversible step — see `scripts/set-channel.sh`. The installer resolves
# <channel> -> <version> -> versions/<version>/components and, for each row
# matching the host os/arch, downloads `src`, checksum-checks it against
# `sha256`, and installs it at `dest`. `src` is bucket-root-relative; here every
# artifact lives at `versions/<VERSION>/<basename>`.
#
# Usage:
#   scripts/stage-release.sh [options]
#
# Options (env var in parens overrides the default; flags win over env):
#   --artifacts-dir DIR   Directory of built artifacts   (ARTIFACTS_DIR, default: artifacts)
#   --version VER         Release version / folder name   (VERSION, default: git short sha)
#   --bucket URL          gs:// bucket URL                 (BUCKET, default: gs://minimal-one)
#   --allow-missing       Warn and omit rows whose artifact is absent (default: hard error)
#   --dry-run             Print the manifest and planned uploads; touch nothing
#   -h, --help            Show this help
#
# Requires: bash, sha256sum, and (unless --dry-run) an authenticated `gcloud`.

set -euo pipefail

die() {
    printf 'stage-release: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# --- Configuration ---------------------------------------------------------

ARTIFACTS_DIR="${ARTIFACTS_DIR:-artifacts}"
BUCKET="${BUCKET:-gs://minimal-one}"
VERSION="${VERSION:-}"
ALLOW_MISSING=0
DRY_RUN=0

# Manifest format version. Bump only on a breaking change to the column layout;
# the installer reads the `# format:` header (spec R2.4) and refuses an
# unsupported value rather than misparsing.
FORMAT_VERSION=1

while [ $# -gt 0 ]; do
    case "$1" in
        --artifacts-dir) ARTIFACTS_DIR="$2"; shift 2 ;;
        --version)       VERSION="$2"; shift 2 ;;
        --bucket)        BUCKET="$2"; shift 2 ;;
        --allow-missing) ALLOW_MISSING=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage 0 ;;
        *)               die "unknown argument: $1 (try --help)" ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION="$(git rev-parse --short=8 HEAD)" \
        || die "no --version given and 'git rev-parse' failed"
fi
# The version becomes a bucket path segment and the pointer-file contents; keep
# it to the same safe charset the installer validates (spec R2.2).
case "$VERSION" in
    *[!A-Za-z0-9._-]*) die "version '$VERSION' contains characters outside [A-Za-z0-9._-]" ;;
esac

[ -d "$ARTIFACTS_DIR" ] || die "artifacts dir not found: $ARTIFACTS_DIR"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
if [ "$DRY_RUN" -eq 0 ]; then
    command -v gcloud >/dev/null 2>&1 || die "gcloud not found (use --dry-run to skip uploads)"
fi

# --- Component table -------------------------------------------------------

# One entry per (component, os, arch) variant the installer should place, as
# `component|os|arch|kind|dest|artifact-basename`:
#   - os/arch use the installer's normalized names (linux|darwin, amd64|arm64).
#   - dest is `<prefix-token>/<subpath>`; the installer maps `bin`  -> ~/.local/bin,
#     `lib` -> ~/.local/lib (a bin sibling, for @rpath/../lib), and `data` ->
#     ~/.local/share/minimal, and marks anything under `bin` +x.
#   - artifact-basename is the file's name inside ARTIFACTS_DIR (the release
#     workflow's merge-multiple flattens every upload to its basename). For
#     kind `symlink` rows it is instead the LINK TARGET, relative to dest's own
#     directory: no artifact is hashed or uploaded, and the manifest's sha256
#     column carries the `-` placeholder (spec R5.6).
#   - the `minimal` CLI installs as `bin/min`: the user-facing command is `min`
#     (the installer's completion generation runs `<bin>/min`, spec R9.3), while
#     the component and artifact names keep the crate name.
#
# Linux hosts install just the three self-contained musl binaries. macOS hosts
# additionally need minvmd + gvproxy and the guest microVM payload (kernel,
# rootfs, initramfs) to boot Linux workloads under libkrun; macOS is arm64-only
# here, and its guest is arm64, so it consumes the arm64 guest artifacts.
COMPONENTS=(
    # Linux amd64
    "minimald|linux|amd64|file|bin/minimald|minimald-linux-amd64"
    "mip|linux|amd64|file|bin/mip|mip-linux-amd64"
    "minimal|linux|amd64|file|bin/min|minimal-linux-amd64"
    "git-remote-min|linux|amd64|symlink|bin/git-remote-min|min"
    # Linux arm64
    "minimald|linux|arm64|file|bin/minimald|minimald-linux-arm64"
    "mip|linux|arm64|file|bin/mip|mip-linux-arm64"
    "minimal|linux|arm64|file|bin/min|minimal-linux-arm64"
    "git-remote-min|linux|arm64|symlink|bin/git-remote-min|min"
    # macOS arm64 (darwin)
    "minimal|darwin|arm64|file|bin/min|minimal-macos-arm64"
    "git-remote-min|darwin|arm64|symlink|bin/git-remote-min|min"
    "minvmd|darwin|arm64|file|bin/minvmd|minvmd-macos-arm64"
    # The trimmed libkrun minvmd links against (built by the release workflow's
    # build-libkrun-macos-arm64 job), staged into lib/ (ie: minvmd/../lib).
    # Basename MUST be libkrun.1.dylib: minvmd's load command is @rpath/libkrun.1.dylib
    # and the release job adds a @loader_path/../lib rpath.
    "libkrun|darwin|arm64|file|lib/libkrun.1.dylib|libkrun-macos-arm64.dylib"
    "gvproxy|darwin|arm64|file|bin/gvproxy|gvproxy-darwin-arm64"
    "initramfs|darwin|arm64|file|data/initramfs.cpio|initramfs-arm64.cpio"
    "rootfs|darwin|arm64|file|data/rootfs.img|rootfs-arm64.img"
    "vmlinuz|darwin|arm64|file|data/vmlinuz|vmlinuz-arm64"
    # AppArmor profile, its tunable, and the privileged loader that installs it,
    # for Ubuntu 24.04+ hosts (docs/reference/linux-host-setup). These are repo
    # files, not build outputs — staged into ARTIFACTS_DIR below — and ship to
    # every Linux host as ordinary `data`-prefix components. noarch text, but the
    # manifest keys on arch, so one row per Linux arch; the uploader dedups by
    # basename to a single upload. The loader lands non-+x under data/ and is run
    # as `sudo bash <path>`; the installer prints that hint when a host needs it.
    "apparmor-profile|linux|amd64|file|data/apparmor/minimald|minimald.apparmor"
    "apparmor-profile|linux|arm64|file|data/apparmor/minimald|minimald.apparmor"
    "apparmor-tunable|linux|amd64|file|data/apparmor/tunables/minimald|minimald.apparmor-tunable"
    "apparmor-tunable|linux|arm64|file|data/apparmor/tunables/minimald|minimald.apparmor-tunable"
    "apparmor-installer|linux|amd64|file|data/apparmor/install-apparmor-profile.sh|install-apparmor-profile.sh"
    "apparmor-installer|linux|arm64|file|data/apparmor/install-apparmor-profile.sh|install-apparmor-profile.sh"
)

# Stage the AppArmor components from the checkout this script runs in. They are
# repo files rather than release-workflow artifacts, so copy them into the
# ephemeral workdir — never into ARTIFACTS_DIR, which the caller owns and
# --dry-run promises not to touch (it may even be read-only) — under the
# stable basenames the component table references. The manifest loop prefers
# a staged file over an ARTIFACTS_DIR one of the same basename, so a stale
# copy left in the artifacts dir cannot shadow the checkout's current file.

# --- Build the manifest ----------------------------------------------------

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-stage)"
trap 'rm -rf "$workdir"' EXIT
manifest="$workdir/components"

staged_dir="$workdir/staged"
mkdir -p "$staged_dir"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
stage_repo_file() {
    [ -f "$repo_root/$1" ] || die "missing repo file for staging: $1"
    cp "$repo_root/$1" "$staged_dir/$2" || die "failed to stage $1 into $staged_dir"
}
stage_repo_file packaging/apparmor/minimald          minimald.apparmor
stage_repo_file packaging/apparmor/tunables/minimald minimald.apparmor-tunable
stage_repo_file scripts/install-apparmor-profile.sh  install-apparmor-profile.sh

{
    printf '# format: %s\n' "$FORMAT_VERSION"
    printf '# component   os      arch    version   sha256%*s   kind   dest                 src\n' 58 ''
} >"$manifest"

# Files to upload, deduped (a basename may back more than one row).
declare -A upload_seen=()
upload_list=()

for entry in "${COMPONENTS[@]}"; do
    IFS='|' read -r comp os arch kind dest basename <<<"$entry"

    # `git push min://<session>` resolves the min:// scheme to a
    # `git-remote-min` helper on PATH; the min binary detects that basename
    # (argv[0]) and enters remote-helper mode, so a symlink is all it takes.
    # A symlink row ships no artifact: the last field is the link target and
    # the sha256 column is the `-` placeholder the installer expects (R5.6).
    if [ "$kind" = symlink ]; then
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            "$comp" "$os" "$arch" "$VERSION" "-" "$kind" "$dest" "$basename" >>"$manifest"
        continue
    fi

    file="$staged_dir/$basename"
    [ -f "$file" ] || file="$ARTIFACTS_DIR/$basename"

    if [ ! -f "$file" ]; then
        if [ "$ALLOW_MISSING" -eq 1 ]; then
            printf 'stage-release: warning: missing artifact, omitting %s/%s/%s: %s\n' \
                "$comp" "$os" "$arch" "$file" >&2
            continue
        fi
        die "missing artifact for $comp/$os/$arch: $file (use --allow-missing to skip)"
    fi

    sha="$(sha256sum "$file" | cut -d' ' -f1)"
    src="versions/$VERSION/$basename"

    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
        "$comp" "$os" "$arch" "$VERSION" "$sha" "$kind" "$dest" "$src" >>"$manifest"

    if [ -z "${upload_seen[$basename]:-}" ]; then
        upload_seen[$basename]=1
        upload_list+=("$file")
    fi
done

[ "${#upload_list[@]}" -gt 0 ] || die "no artifacts matched the component table in $ARTIFACTS_DIR"

# --- Report / upload -------------------------------------------------------

version_prefix="$BUCKET/versions/$VERSION"

printf '=== components manifest (%s/components) ===\n' "$version_prefix" >&2
cat "$manifest" >&2
printf '=== %d artifact(s) -> %s/ ===\n' "${#upload_list[@]}" "$version_prefix" >&2
printf '  %s\n' "${upload_list[@]}" >&2

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'stage-release: dry run, nothing uploaded\n' >&2
    exit 0
fi

# Immutable version artifacts: cache aggressively. Content is addressed by the
# version segment, so a given URL never changes payload.
IMMUTABLE_CACHE="public, max-age=31536000, immutable"

gcloud storage cp \
    --cache-control="$IMMUTABLE_CACHE" \
    "${upload_list[@]}" "$version_prefix/"

gcloud storage cp \
    --cache-control="$IMMUTABLE_CACHE" \
    "$manifest" "$version_prefix/components"

printf 'stage-release: staged %s at %s (no channel updated; see set-channel.sh)\n' \
    "$VERSION" "$version_prefix" >&2
