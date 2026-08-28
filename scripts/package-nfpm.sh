#!/usr/bin/env bash
#
# package-nfpm.sh — build minimal's deb/rpm/apk packages from the staged
# release artifacts.
#
# A release is staged into the installer bucket as a versions/<version>/ row
# (scripts/stage-release.sh): the static musl binaries, the AppArmor files,
# and the rest. This script takes a promoted semver (PKGVER), pulls the
# staged Linux artifacts for both amd64 and arm64, generates shell
# completions from the built `min` (the scripts/dist-build.sh technique),
# and runs the pinned nfpm — fetched and SHA-256-verified against
# vendor/nfpm/nfpm.lock, the same pin pattern as scripts/fetch-gvproxy.sh —
# once per format x arch against packaging/nfpm.yaml.
#
# This script only produces packages. Repo-tree hosting — reprepro/aptly for
# apt, createrepo_c for dnf/yum, apk index for apk, and serving from the
# /repo/{apt,dnf,apk}/ bucket prefixes — lives in the infra/ repo, not here.
# CI uploads $OUT_DIR as the staged row versions/<version>/pkg/.
#
# Usage: scripts/package-nfpm.sh [--formats deb,rpm,apk]
#
# Env:
#   PKGVER              Required. Promoted semver WITHOUT the v prefix
#                       (X.Y.Z, optional -prerelease/+build tail). Artifacts
#                       are fetched from <bucket>/versions/$PKGVER/ — the
#                       same names the AUR PKGBUILD's source arrays use.
#   NFPM_VERSION        Optional. Must equal the version pinned in
#                       vendor/nfpm/nfpm.lock; it exists to catch a stale
#                       environment, not to override the pin (bump the lock
#                       instead).
#   MINIMAL_BUCKET_URL  Public base URL of the installer bucket
#                       (default: https://storage.googleapis.com/minimal-one)
#   MAINTAINER          Package maintainer identity. Defaults below to the
#                       currently published one; set this to change it
#                       everywhere at once.
#   OUT_DIR             Where the packages land (default: dist/ under the
#                       repo root; a relative path resolves there too).
#
# Requires: bash, curl, tar, and sha256sum (or shasum on macOS). A Linux
# amd64 or arm64 host: the completions step runs the staged `min` binary, so
# the host must be able to execute one of them.
#
set -euo pipefail

die() {
    printf 'package-nfpm: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

FORMATS_INPUT="deb,rpm,apk"
while [ $# -gt 0 ]; do
    case "$1" in
        --formats)
            [ $# -ge 2 ] || die "--formats needs a value (e.g. deb,rpm,apk)"
            FORMATS_INPUT="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *)        die "unknown argument: $1 (try --help)" ;;
    esac
done

# Normalize the format list: canonical order, no duplicates, unknown names
# rejected.
FORMATS_OUT=()
seen=""
IFS=',' read -ra fmt_list <<<"$FORMATS_INPUT"
for f in "${fmt_list[@]}"; do
    case "$f" in
        deb|rpm|apk) ;;
        *) die "unknown format '$f' (want a comma-separated subset of deb,rpm,apk)" ;;
    esac
    case " $seen " in
        *" $f "*) die "duplicate format '$f' in --formats" ;;
        *)        seen="$seen$f " ;;
    esac
done
for f in deb rpm apk; do
    case " $seen " in
        *" $f "*) FORMATS_OUT+=("$f") ;;
    esac
done
[ "${#FORMATS_OUT[@]}" -gt 0 ] || die "--formats selected nothing (want a subset of deb,rpm,apk)"

[ -n "${PKGVER:-}" ] || die "PKGVER is required (the promoted semver, without the v prefix)"
case "$PKGVER" in
    v*) die "PKGVER must not carry the v prefix: '$PKGVER' (use ${PKGVER#v})" ;;
esac
printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' \
    || die "PKGVER '$PKGVER' is not a semver X.Y.Z (optional -prerelease/+build)"

BUCKET_URL="${MINIMAL_BUCKET_URL:-https://storage.googleapis.com/minimal-one}"

# nfpm.yaml's maintainer field env-expands this; placeholder default.
MAINTAINER="${MAINTAINER:-minimal <noreply@minimal.dev>}"
export MAINTAINER

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT_DIR"
[ -f "$ROOT/packaging/nfpm.yaml" ] || die "no such config: $ROOT/packaging/nfpm.yaml"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# --- Fetch the pinned nfpm -------------------------------------------------
# vendor/nfpm/nfpm.lock pins the version and per-asset SHA-256, read exactly
# like vendor/gvproxy/gvproxy.lock in scripts/fetch-gvproxy.sh. The tarball
# caches under .scratch/ and is re-verified on every run, so a stale or
# tampered cache entry cannot pass.
lock="$ROOT/vendor/nfpm/nfpm.lock"
[ -f "$lock" ] || die "no nfpm pin: $lock"
locked_version="$(sed -n 's/^version=//p' "$lock")"
[ -n "$locked_version" ] || die "no version= line in $lock"
NFPM_VERSION="${NFPM_VERSION:-$locked_version}"
[ "$NFPM_VERSION" = "$locked_version" ] \
    || die "NFPM_VERSION=$NFPM_VERSION does not match the pin in $lock ($locked_version); bump the lock, not the environment"

case "$(uname -m)" in
    x86_64)        nfpm_host_arch=x86_64 ;;
    aarch64|arm64) nfpm_host_arch=arm64 ;;
    *)             die "unsupported host arch for the nfpm fetch: $(uname -m)" ;;
esac
nfpm_asset="nfpm_${NFPM_VERSION#v}_Linux_${nfpm_host_arch}.tar.gz"
nfpm_want="$(sed -n "s/^${nfpm_asset}=//p" "$lock")"
[ -n "$nfpm_want" ] || die "no pinned digest for ${nfpm_asset} in $lock"

nfpm_cache="$ROOT/.scratch/nfpm"
mkdir -p "$nfpm_cache"
nfpm_tarball="$nfpm_cache/$nfpm_asset"
if [ ! -f "$nfpm_tarball" ]; then
    nfpm_url="https://github.com/goreleaser/nfpm/releases/download/${NFPM_VERSION}/${nfpm_asset}"
    echo "package-nfpm: downloading ${nfpm_url}"
    curl -fsSL --retry 3 -o "$nfpm_tarball.partial" "$nfpm_url" \
        || die "nfpm download failed: $nfpm_url"
    nfpm_got="$(sha256_of "$nfpm_tarball.partial")"
    [ "$nfpm_got" = "$nfpm_want" ] || {
        rm -f "$nfpm_tarball.partial"
        die "SHA-256 mismatch for ${nfpm_asset}: got ${nfpm_got}, want ${nfpm_want}"
    }
    mv -f "$nfpm_tarball.partial" "$nfpm_tarball"
fi
nfpm_got="$(sha256_of "$nfpm_tarball")"
[ "$nfpm_got" = "$nfpm_want" ] || {
    rm -f "$nfpm_tarball"
    die "cached $nfpm_tarball fails verification (got ${nfpm_got}, want ${nfpm_want}); delete $nfpm_cache and re-fetch"
}

nfpm_bin="$nfpm_cache/nfpm-${NFPM_VERSION#v}-${nfpm_host_arch}"
if [ ! -x "$nfpm_bin" ]; then
    # The release tarball also carries LICENSE/README/completions/manpages;
    # extract the binary only.
    nfpm_extract="$nfpm_cache/extract"
    rm -rf "$nfpm_extract"
    mkdir -p "$nfpm_extract"
    tar -xzf "$nfpm_tarball" -C "$nfpm_extract" nfpm
    mv -f "$nfpm_extract/nfpm" "$nfpm_bin"
    rm -rf "$nfpm_extract"
fi
"$nfpm_bin" --version >/dev/null || die "fetched nfpm does not run: $nfpm_bin"
echo "package-nfpm: using ${nfpm_bin}"

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t package-nfpm)"
trap 'rm -rf "$workdir"' EXIT

# --- Download the staged Linux artifacts ------------------------------------
# artifact basename under versions/$PKGVER/ | installed name. Same mapping as
# the PKGBUILD's source arrays (min::minimal-linux-amd64, ...), plus minvmd,
# which every staged row carries — see the file-list decision in
# packaging/nfpm.yaml's header.
ARTIFACTS=(
    "minimal|min"
    "minimald|minimald"
    "mip|mip"
    "minvmd|minvmd"
    "gvproxy|gvproxy-min"
)
artifacts_root="$workdir/artifacts"
for arch in amd64 arm64; do
    art_dir="$artifacts_root/$arch"
    mkdir -p "$art_dir"
    for entry in "${ARTIFACTS[@]}"; do
        IFS='|' read -r staged installed <<<"$entry"
        url="$BUCKET_URL/versions/$PKGVER/${staged}-linux-${arch}"
        curl -fsSL --retry 3 -o "$art_dir/$installed" "$url" \
            || die "cannot download $url — is $PKGVER staged in the bucket? (see stage-release.sh)"
        chmod +x "$art_dir/$installed"
    done
done

# --- Generate completions ----------------------------------------------------
# The technique scripts/dist-build.sh uses: XDG overrides steer the binary's
# user-level install targets into the workdir, ZDOTDIR keeps its
# compinit-dump cleanup off this host's ~, and BASH_COMPLETION_USER_DIR
# forces the bash write (the binary otherwise skips bash when it finds no
# bash-completion loader on the build host — right for an install, wrong for
# a generation run). Generated once from the host-arch binary: completions
# are arch-independent text.
case "$(uname -m)" in
    x86_64)        host_arch=amd64 ;;
    aarch64|arm64) host_arch=arm64 ;;
    *)             die "completions must be generated on amd64 or arm64; got $(uname -m)" ;;
esac
completions_dir="$workdir/completions"
mkdir -p "$completions_dir"
XDG_DATA_HOME="$completions_dir" \
XDG_CONFIG_HOME="$completions_dir" \
ZDOTDIR="$completions_dir/zdotdir" \
BASH_COMPLETION_USER_DIR="$completions_dir" \
    "$artifacts_root/$host_arch/min" completions install --no-input \
        --minimal-dir "$completions_dir/minimal-cache" bash zsh fish
# `completions install` is best-effort per shell (a skip is a warning, not a
# failure) — a shippable package must assert every file actually landed.
for f in \
    "$completions_dir/bash-completion/completions/min" \
    "$completions_dir/zsh/completions/_min" \
    "$completions_dir/fish/completions/min.fish"; do
    [ -f "$f" ] || die "completions install did not write $f; see its warnings above"
done

# --- Materialize the postinstall script --------------------------------------
# packaging/nfpm.yaml's scripts.postinstall points at this fixed .scratch
# location (nfpm does not env-expand script paths), refreshed on every run.
# POSIX sh: it must run under /bin/sh as deb postinst, rpm %post, and apk
# .post-install alike.
postinstall_dir="$ROOT/.scratch/package-nfpm"
mkdir -p "$postinstall_dir"
cat > "$postinstall_dir/postinstall.sh" <<'EOF'
#!/bin/sh
# minimal postinstall: load the minimald AppArmor profile when this host has
# AppArmor. Never hard-fails: most rpm/apk targets have no AppArmor at all,
# and the package must install cleanly there — the daemon warns at runtime
# instead (see docs/reference/linux-host-setup.md).
loader=/usr/share/minimal/apparmor/install-apparmor-profile.sh
if ! command -v apparmor_parser >/dev/null 2>&1; then
    echo "minimal: AppArmor is not available on this host; skipping the minimald profile" >&2
    exit 0
fi
if ! "$loader"; then
    echo "minimal: WARNING: loading the minimald AppArmor profile failed; on restricted hosts minimald sessions may fail to start until this is fixed (see docs/reference/linux-host-setup.md)" >&2
fi
exit 0
EOF

# --- Package ------------------------------------------------------------------
# One nfpm run per (format, arch): the config's ${NFPM_ARCH} and the
# per-arch ${ARTIFACT_DIR} come from the environment, as do the other
# expanded fields (see packaging/nfpm.yaml's header).
for format in "${FORMATS_OUT[@]}"; do
    for arch in amd64 arm64; do
        echo "package-nfpm: $format/$arch -> $OUT_DIR"
        PKGVER="$PKGVER" \
        NFPM_ARCH="$arch" \
        ARTIFACT_DIR="$artifacts_root/$arch" \
        COMPLETIONS_DIR="$completions_dir" \
        APPARMOR_DIR="$ROOT/packaging/apparmor" \
        APPARMOR_LOADER="$ROOT/scripts/install-apparmor-profile.sh" \
            "$nfpm_bin" package \
                --config "$ROOT/packaging/nfpm.yaml" \
                --packager "$format" \
                --target "$OUT_DIR" \
            || die "nfpm package $format/$arch failed"
    done
done

echo "package-nfpm: packages in $OUT_DIR:"
for f in "$OUT_DIR"/*.deb "$OUT_DIR"/*.rpm "$OUT_DIR"/*.apk; do
    if [ -f "$f" ]; then
        echo "  $(basename "$f")"
    fi
done
