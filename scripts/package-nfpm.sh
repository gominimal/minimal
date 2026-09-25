#!/usr/bin/env bash
#
# package-nfpm.sh — build minimal's deb/rpm/apk packages from the staged
# release artifacts.
#
# Two sources of the Linux binaries for both amd64 and arm64:
#
#   * ARTIFACTS_DIR set — the release run's own build output (the
#     platform-suffixed files stage-release.sh is about to hash and upload).
#     Packages are built in the same run as the binaries, before anything is
#     staged, so the .deb/.rpm/.apk ship the exact bytes the run smokes.
#   * otherwise — the staged versions/<ROW>/ row in the installer bucket
#     (scripts/stage-release.sh), each download verified against the row's
#     `components` manifest before use.
#
# One package NAME (`minimal`) serves every channel: on the consuming side a
# channel is a repo/suite (`deb http://… <suite> main`), so a user installs one
# version at a time and there is no file-conflict problem. What the channel
# changes here is only the VERSION STRING, via scripts/package-version.sh: a
# stable semver stays byte-identical, while a dev build's `-dev.<N>.g<sha>`
# tail becomes deb/rpm `~` (sorts below the release, so enabling a channel
# suite never silently upgrades a stable user) and apk `_`. The built version
# is read from the row's staged `version` file rather than re-derived from the
# row name, which for a nightly is a bare sha.
#
# Either way it generates shell completions from the built `min` (the
# scripts/dist-build.sh technique) and runs the pinned nfpm — fetched and
# SHA-256-verified against vendor/nfpm/nfpm.lock, the same pin pattern as
# scripts/fetch-gvproxy.sh — once per format x arch against
# packaging/nfpm.yaml.
#
# This script only produces packages and their per-row layout; it hosts no
# repo trees. CI uploads $OUT_DIR as the staged row versions/<version>/pkg/,
# and the channel a row belongs to is recorded by the channel pointer files
# (scripts/set-channel.sh), not by the package.
#
# Usage:
#   scripts/package-nfpm.sh [--channel stable|unstable|nightly] [--formats deb,rpm,apk]
#
# Env:
#   PKGVER              Required. The ROW the artifacts come from: the semver
#                       WITHOUT the v prefix (X.Y.Z, optional -prerelease/+build
#                       tail) on the stable channel, or the short sha of a
#                       staged nightly/unstable row on a channel. Without
#                       ARTIFACTS_DIR, artifacts are fetched from
#                       <bucket>/versions/$PKGVER/ — the same names the AUR
#                       PKGBUILD's source arrays use.
#   BUILT_VERSION       Optional. The canonical built version string (what the
#                       binaries report, e.g. 0.6.0-dev.10.g8e7e72c2). Set this
#                       in ARTIFACTS_DIR mode on a channel; without it (and
#                       without ARTIFACTS_DIR) the version is read from
#                       <bucket>/versions/$PKGVER/version.
#   ARTIFACTS_DIR       Optional. Directory of local build output holding
#                       <name>-linux-{amd64,arm64} for minimal, minimald,
#                       mip, minvmd, and gvproxy; nothing is downloaded.
#   NFPM_VERSION        Optional. Must equal the version pinned in
#                       vendor/nfpm/nfpm.lock; it exists to catch a stale
#                       environment, not to override the pin (bump the lock
#                       instead).
#   NFPM_BIN            Optional. Path to an already-present nfpm binary; set it
#                       to SKIP the pinned download + SHA-256 verification and
#                       use this binary instead. A testability seam for the
#                       harness (scripts/package-nfpm_test.sh), the same shape
#                       as the prebuilt-binary overrides elsewhere in scripts/
#                       (MINIMALD_BIN, MINVMD_GVPROXY_BIN). NFPM_VERSION is
#                       still checked against the lock, so this cannot smuggle
#                       an unpinned nfpm past the pin.
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

# die <message> — print it with the script prefix on stderr and exit 1.
die() {
    printf 'package-nfpm: %s\n' "$1" >&2
    exit 1
}

# usage [code] — print the header comment block as help and exit.
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

FORMATS_INPUT="deb,rpm,apk"
CHANNEL="stable"
while [ $# -gt 0 ]; do
    case "$1" in
        --formats)
            [ $# -ge 2 ] || die "--formats needs a value (e.g. deb,rpm,apk)"
            FORMATS_INPUT="$2"; shift 2 ;;
        --channel)
            [ $# -ge 2 ] || die "--channel needs a value (stable, unstable, nightly)"
            CHANNEL="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *)        die "unknown argument: $1 (try --help)" ;;
    esac
done

case "$CHANNEL" in
    stable|unstable|nightly) ;;
    *) die "unknown --channel '$CHANNEL' (want stable, unstable, or nightly)" ;;
esac

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

[ -n "${PKGVER:-}" ] || die "PKGVER is required (the row: a semver without the v prefix, or a staged sha)"
case "$PKGVER" in
    v*) die "PKGVER must not carry the v prefix: '$PKGVER' (use ${PKGVER#v})" ;;
esac
# stable is a versioned release: the row IS a released semver. The nfpm caller
# (release.yml) picks the channel by row shape — `stable` for a versioned row,
# `unstable` for a sha row — so a channel row here is always a commit sha: the
# row name alone cannot be the version, and the built version comes from the
# row's `version` file below.
if [ "$CHANNEL" = stable ]; then
    printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' \
        || die "PKGVER '$PKGVER' is not a semver X.Y.Z (optional -prerelease/+build) on the stable channel"
else
    case "$PKGVER" in
        *[!0-9a-f]*) die "PKGVER '$PKGVER' is not a commit sha — release.yml builds channel nfpm packages for sha rows only (it passes --channel stable for a versioned row)" ;;
    esac
    len="${#PKGVER}"
    if [ "$len" -lt 7 ] || [ "$len" -gt 40 ]; then
        die "PKGVER '$PKGVER' is not a 7-40 character commit sha on the $CHANNEL channel"
    fi
fi

BUCKET_URL="${MINIMAL_BUCKET_URL:-https://storage.googleapis.com/minimal-one}"

# ROW is the staged bucket row the artifacts come from; PKGVER (the row) is
# replaced by the per-format package version only at the nfpm invocation below.
ROW="$PKGVER"

# Resolve the canonical built version (what the binaries report) — the source
# of every package version string. It is NEVER re-derived from the row name:
# a dev version is 0.6.0-dev.10.g<sha>, which no row name encodes.
if [ -n "${BUILT_VERSION:-}" ]; then
    VERSION="$BUILT_VERSION"
elif [ -n "${ARTIFACTS_DIR:-}" ]; then
    # Local build output, no staged row to read: stable's version is its row
    # name; a channel must be told the built version (release.yml has it).
    [ "$CHANNEL" = stable ] \
        || die "BUILT_VERSION is required on the $CHANNEL channel in ARTIFACTS_DIR mode (the built version string, e.g. 0.6.0-dev.10.g8e7e72c2)"
    VERSION="$PKGVER"
else
    VERSION="$(curl -fsSL --retry 3 "$BUCKET_URL/versions/$ROW/version")" \
        || die "cannot download $BUCKET_URL/versions/$ROW/version — the row is missing its version file, so there is nothing to name the package after; restore it with scripts/backfill-version-row.sh (see its header)"
fi
printf '%s\n' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+_-]+)?$' \
    || die "resolved version '$VERSION' is not a canonical X.Y.Z (optional -prerelease/+build) version"

# nfpm.yaml's maintainer field env-expands this.
MAINTAINER="${MAINTAINER:-minimal <security@minimal.dev>}"
export MAINTAINER

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT_DIR"
[ -f "$ROOT/packaging/nfpm.yaml" ] || die "no such config: $ROOT/packaging/nfpm.yaml"

# sha256_of <file> — the file's SHA-256 hex digest, via sha256sum or shasum.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# --- Resolve nfpm -----------------------------------------------------------
# The shipped path is a pinned download + SHA-256 verification:
# vendor/nfpm/nfpm.lock pins the version and per-asset digest, read exactly like
# vendor/gvproxy/gvproxy.lock in scripts/fetch-gvproxy.sh, and the tarball
# caches under .scratch/ re-verified on every run, so a stale or tampered cache
# entry cannot pass. NFPM_BIN short-circuits the download with a prebuilt binary
# — the harness seam (see the header) — while the NFPM_VERSION pin check above
# stays in force.
lock="$ROOT/vendor/nfpm/nfpm.lock"
[ -f "$lock" ] || die "no nfpm pin: $lock"
locked_version="$(sed -n 's/^version=//p' "$lock")"
[ -n "$locked_version" ] || die "no version= line in $lock"
NFPM_VERSION="${NFPM_VERSION:-$locked_version}"
[ "$NFPM_VERSION" = "$locked_version" ] \
    || die "NFPM_VERSION=$NFPM_VERSION does not match the pin in $lock ($locked_version); bump the lock, not the environment"

if [ -n "${NFPM_BIN:-}" ]; then
    nfpm_bin="$NFPM_BIN"
    [ -x "$nfpm_bin" ] || die "NFPM_BIN is not an executable file: $nfpm_bin"
else
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
fi
"$nfpm_bin" --version >/dev/null || die "nfpm does not run: $nfpm_bin"
echo "package-nfpm: using ${nfpm_bin}"

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t package-nfpm)"
trap 'rm -rf "$workdir"' EXIT

# --- Gather the Linux artifacts ------------------------------------------------
# artifact basename (under versions/$PKGVER/ or ARTIFACTS_DIR) | installed
# name. Same mapping as the PKGBUILD's source arrays
# (min::minimal-linux-amd64, ...), plus minvmd, which every staged row
# carries — see the file-list decision in packaging/nfpm.yaml's header.
ARTIFACTS=(
    "minimal|min"
    "minimald|minimald"
    "mip|mip"
    "minvmd|minvmd"
    "gvproxy|gvproxy-min"
)
artifacts_root="$workdir/artifacts"

if [ -n "${ARTIFACTS_DIR:-}" ]; then
    # Local build output: the release run's own artifacts, not yet staged.
    # There is no manifest to verify against — stage-release.sh will hash
    # these very files into it — so the only check is that each one exists.
    [ -d "$ARTIFACTS_DIR" ] || die "ARTIFACTS_DIR not found: $ARTIFACTS_DIR"
    echo "package-nfpm: packaging local build output from $ARTIFACTS_DIR"
    for arch in amd64 arm64; do
        art_dir="$artifacts_root/$arch"
        mkdir -p "$art_dir"
        for entry in "${ARTIFACTS[@]}"; do
            IFS='|' read -r staged installed <<<"$entry"
            src="$ARTIFACTS_DIR/${staged}-linux-${arch}"
            [ -f "$src" ] || die "missing local artifact $src (the release build did not produce it?)"
            cp "$src" "$art_dir/$installed"
            chmod +x "$art_dir/$installed"
        done
    done
else
    # --- Download the staged row, verifying before use ------------------------
    # stage-release.sh writes versions/<pkgver>/components with one row per
    # artifact and its SHA-256 — the same manifest the curl|sh installer
    # verifies against, and the bucket's trust root. Every downloaded binary
    # is checked against it BEFORE anything chmods, executes, or packages it:
    # a corrupted, truncated, or wrongly-staged object must fail this job, not
    # enter the .deb/.rpm/.apk that users install.
    manifest_url="$BUCKET_URL/versions/$ROW/components"
    curl -fsSL --retry 3 -o "$workdir/components" "$manifest_url" \
        || die "cannot download $manifest_url — is $ROW staged in the bucket? (see stage-release.sh)"

    declare -A manifest_sha=()
    while IFS= read -r row; do
        case "$row" in '#'*) continue ;; esac
        read -r -a cols <<<"$row"
        # component os arch version sha256 kind dest src
        [ "${#cols[@]}" -eq 8 ] || die "unexpected components row in $manifest_url: $row"
        src="${cols[7]}"
        case "$src" in
            "versions/$ROW/"*) manifest_sha["${src##*/}"]="${cols[4]}" ;;
            *) ;; # symlink rows and other versions' rows carry no artifact here
        esac
    done <"$workdir/components"

    [ "${#manifest_sha[@]}" -gt 0 ] || die "no artifact rows for $ROW in the staged components manifest"

    for arch in amd64 arm64; do
        art_dir="$artifacts_root/$arch"
        mkdir -p "$art_dir"
        for entry in "${ARTIFACTS[@]}"; do
            IFS='|' read -r staged installed <<<"$entry"
            url="$BUCKET_URL/versions/$ROW/${staged}-linux-${arch}"
            curl -fsSL --retry 3 -o "$art_dir/$installed" "$url" \
                || die "cannot download $url — is $ROW staged in the bucket? (see stage-release.sh)"
            want="${manifest_sha[${staged}-linux-${arch}]:-}"
            [ -n "$want" ] \
                || die "no digest for ${staged}-linux-${arch} in the staged components manifest — refusing to package an unverified artifact"
            got="$(sha256_of "$art_dir/$installed")"
            [ "$got" = "$want" ] \
                || die "SHA-256 mismatch for ${staged}-linux-${arch}: got $got, the staged manifest says $want"
            chmod +x "$art_dir/$installed"
        done
    done
fi

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
# expanded fields (see packaging/nfpm.yaml's header). ${PKGVER} is the
# PACKAGE version, not the row: it is the canonical built version normalized
# into this format's charset by scripts/package-version.sh (`~` for deb/rpm,
# `_` for apk). For a released semver that normalization is the identity.
for format in "${FORMATS_OUT[@]}"; do
    pkg_version="$("$ROOT/scripts/package-version.sh" --format "$format" "$VERSION")" \
        || die "cannot normalize version '$VERSION' for $format"
    for arch in amd64 arm64; do
        echo "package-nfpm: $format/$arch version $pkg_version (row $ROW) -> $OUT_DIR"
        PKGVER="$pkg_version" \
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
