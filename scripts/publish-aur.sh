#!/usr/bin/env bash
#
# publish-aur.sh — clone an AUR channel repo, stamp the PKGBUILD, push.
#
# The monorepo is the source of truth for the AUR packages; the AUR repos are
# generated output. Each run shallow-clones a fresh copy, downloads the 13
# artifacts from the installer bucket to compute their sha256s, renders
# packaging/arch/PKGBUILD-bin.tmpl into PKGBUILD, copies the pacman install
# hook and LICENSE, regenerates .SRCINFO, and commits + pushes.
#
# Channels map to AUR package names:
#   stable   -> minimal-bin            (a promoted semver release)
#   unstable -> minimal-unstable-bin   (a sha row)
#   nightly  -> minimal-nightly-bin     (a sha row)
#
# Usage:
#   scripts/publish-aur.sh [--channel stable|unstable|nightly] [--dry-run] [--verify-build]
#
# Env:
#   PKGVER              Required. The bucket row to publish.
#                       On the stable channel: a RELEASED semver WITHOUT the v
#                       prefix (X.Y.Z, optional +build tail). Artifacts are
#                       fetched from <bucket>/versions/$PKGVER/. A bare short
#                       SHA is rejected, and so is a prerelease (-rc.1 tail):
#                       pacman forbids hyphens in pkgver, so an RC could never
#                       be published here anyway. The AUR stable package tracks
#                       promoted semver releases.
#                       On the unstable/nightly channels: the 7-40 char
#                       lowercase-hex sha row. A semver row is refused — a
#                       versioned row is represented by the stable package.
#   AUR_REPO_URL        git URL to clone/push
#                       (default: ssh://aur@aur.archlinux.org/$PKGNAME.git).
#                       --dry-run without credentials falls back to the public
#                       read-only https mirror so a rehearsal needs no key.
#   MINIMAL_BUCKET_URL  Public base URL of the installer bucket
#                       (default: https://storage.googleapis.com/minimal-one)
#   MAINTAINER          PKGBUILD maintainer line. Defaults below to the
#                       project contact; set this to override. Personal
#                       addresses are not checked into this repo.
#
# Version resolution:
#   Every channel reads <bucket>/versions/$ROW/version and refuses a row that
#   lacks it: it must be staged by a build that writes the version file.
#   stable   _row = the promoted semver PKGVER; pkgver is the aur-normalized
#            form of the canonical version, and the file is additionally
#            asserted to equal PKGVER, so a row whose binaries disagree with
#            the tag being published is refused rather than packaged.
#   channel  _row = PKGVER (the sha row); pkgver is the aur-normalized form of
#            the canonical version read from that file
#            (scripts/package-version.sh --format aur).
#
# Credentials (env/ssh-agent only — never hardcoded or echoed here):
#   - an ssh-agent holding the bot's AUR key (SSH_AUTH_SOCK set), or
#   - AUR_SSH_PRIVATE_KEY in the environment (PEM text); it is written to a
#     0600 file in the temp workdir for the run and removed with it.
#   The bot AUR account must be a co-maintainer of the package. AUR has no
#   key-management API: generate a dedicated keypair, put the public key on
#   the account, store the private key in the CI secret AUR_SSH_PRIVATE_KEY,
#   and keep the account password/recovery email in a shared vault.
#   --dry-run does not push, so it does not need a key: without one it reads
#   the public https mirror instead.
#
# --dry-run does everything up to the commit and prints the would-be diff.
#
# --verify-build additionally runs a real `makepkg -f` build of the rendered
# PKGBUILD (in a throwaway copy) before committing, so a publish proves the
# package actually builds, not merely that its metadata parses. The CI publish
# jobs use it.
#
# Requires: bash, git, curl, and a sha256 tool (sha256sum, shasum, or openssl);
# makepkg (Arch) for .SRCINFO — without
# it, .SRCINFO is skipped with a warning (the CI container is
# archlinux:base-devel, which has it).

set -euo pipefail

die() {
    printf 'publish-aur: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

DRY_RUN=0
VERIFY_BUILD="${VERIFY_BUILD:-0}"
CHANNEL="stable"
while [ $# -gt 0 ]; do
    case "$1" in
        --channel)
            [ -n "${2:-}" ] || die "--channel needs a value (stable, unstable, nightly)"
            CHANNEL="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --verify-build) VERIFY_BUILD=1; shift ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $1 (try --help)" ;;
    esac
done

# The channel fixes the AUR package name; everything downstream (repo URL,
# install hook, conflicts) derives from it.
case "$CHANNEL" in
    stable)   PKGNAME="minimal-bin" ;;
    unstable) PKGNAME="minimal-unstable-bin" ;;
    nightly)  PKGNAME="minimal-nightly-bin" ;;
    *)        die "unknown --channel '$CHANNEL' (want stable, unstable, or nightly)" ;;
esac

# conflicts names every AUR channel package but this one: they all install the
# same /usr/bin files, so pacman must refuse two of them at once. The template
# stamps the quoted list as-is (the renderer requires it non-empty).
CONFLICTS=""
for name in minimal-bin minimal-unstable-bin minimal-nightly-bin; do
    [ "$name" = "$PKGNAME" ] && continue
    # The single quotes are literal PKGBUILD array syntax, not shell quoting:
    # they must survive into conflicts=(...) via the renderer.
    # shellcheck disable=SC2089
    CONFLICTS="${CONFLICTS:+$CONFLICTS }'$name'"
done

[ -n "${PKGVER:-}" ] || die "PKGVER is required (the bucket row to publish: a released semver, or a sha row on a channel)"

# The PKGBUILD maintainer line.
MAINTAINER="${MAINTAINER:-minimal <security@minimal.dev>}"
export MAINTAINER

AUR_REPO_URL="${AUR_REPO_URL:-ssh://aur@aur.archlinux.org/$PKGNAME.git}"
# The public read-only mirror. Same repo, no credentials — a --dry-run needs
# to clone to produce its diff, and demanding the bot key for a rehearsal made
# dry-runs unreachable outside CI.
AUR_PUBLIC_URL="https://aur.archlinux.org/$PKGNAME.git"
BUCKET_URL="${MINIMAL_BUCKET_URL:-https://storage.googleapis.com/minimal-one}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/packaging/arch/PKGBUILD-bin.tmpl"
INSTALL_HOOK="$ROOT/packaging/arch/minimal-bin.install"
# The AUR repo needs the license text beside the PKGBUILD; the repository's
# own Apache-2.0 LICENSE is the single source of truth (no packaging copy to
# drift from it).
LICENSE_FILE="$ROOT/LICENSE"
RENDER="$ROOT/scripts/render-packaging.sh"
VERSION_HELPER="$ROOT/scripts/package-version.sh"
[ -f "$TEMPLATE" ] || die "no such template: $TEMPLATE"
[ -f "$INSTALL_HOOK" ] || die "no such install hook: $INSTALL_HOOK"
[ -f "$LICENSE_FILE" ] || die "no such LICENSE: $LICENSE_FILE"
[ -x "$RENDER" ] || die "renderer missing or not executable: $RENDER"
[ -x "$VERSION_HELPER" ] || die "version helper missing or not executable: $VERSION_HELPER"

# Resolve the bucket row. Both channels then read the row's canonical `version`
# file below — stable included.
case "$CHANNEL" in
    stable)
        # Today's behavior: pkgver IS the promoted semver, and the row is it.
        case "$PKGVER" in
            v*) die "PKGVER must not carry the v prefix: '$PKGVER' (use ${PKGVER#v})" ;;
        esac
        # A release only: pacman's pkgver forbids hyphens, so a prerelease tail
        # (-rc.1) could never publish — reject it here with that named, instead
        # of letting makepkg's lint blame the template. A +build tail is a
        # valid release version and passes.
        printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(\+[0-9A-Za-z.-]+)?$' \
            || die "PKGVER '$PKGVER' is not a RELEASED semver X.Y.Z (optional +build; prereleases and shas are rejected: pacman's pkgver forbids hyphens)"
        ROW="$PKGVER"
        ;;
    *)
        # Channel: PKGVER is the sha row. A versioned row is the stable
        # package's job, so refuse one by name rather than downloading it.
        if printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'; then
            die "PKGVER '$PKGVER' is a versioned row; --channel $CHANNEL publishes sha rows only (a versioned row is represented by the stable minimal-bin package)"
        fi
        printf '%s\n' "$PKGVER" | grep -qE '^[0-9a-f]{7,40}$' \
            || die "PKGVER '$PKGVER' is not a 7-40 char lowercase-hex sha row"
        ROW="$PKGVER"
        ;;
esac

# The canonical built version lives beside the row's artifacts, on EVERY
# channel. A row staged without it predates channel packaging and cannot
# publish: pkgver would fall back to the raw sha, which pacman rejects. On
# stable the read doubles as an assertion that the row agrees with the semver
# being published — the row is already required by the artifact fetches below,
# so this adds no new dependency.
version_url="$BUCKET_URL/versions/$ROW/version"
VERSION="$(curl -fsSL --retry 3 "$version_url")" \
    || die "cannot download $version_url — row '$ROW' must be staged by a build that writes the version file"
[ -n "$VERSION" ] || die "empty version file at $version_url for row '$ROW'"
if [ "$CHANNEL" = "stable" ] && [ "$VERSION" != "$PKGVER" ]; then
    die "row '$ROW' holds binaries reporting '$VERSION', not '$PKGVER' — refusing to publish a package whose version contradicts what it installs"
fi

# pkgver must be pacman-legal: the helper turns a dev build's `-` into `.`
# (identity for a released semver), so both channels pass through it. VERSION
# is the canonical string; PKGVER is what the PKGBUILD stamps.
PKGVER="$("$VERSION_HELPER" --format aur "$VERSION")"

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t publish-aur)"
trap 'rm -rf "$workdir"' EXIT

# Bare lowercase hex digest of file $1. sha256sum (Linux CI), shasum (macOS),
# or openssl anywhere — a publish run should work from a Mac too. Mirrors
# publish-brew.sh's helper.
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

# artifact basename under versions/$ROW/ | env var holding its sha256.
# The variable names must match the @@SHA_*@@ tokens the template stamps; the
# list order is irrelevant (each sha lands in its named variable, and the
# PKGBUILD keeps its own source/checksum arrays aligned).
ARTIFACTS=(
    "minimald.apparmor|SHA_APPARMOR"
    "minimald.apparmor-tunable|SHA_APPARMOR_TUNABLE"
    "install-apparmor-profile.sh|SHA_APPARMOR_LOADER"
    "minimal-linux-amd64|SHA_MIN_X86_64"
    "minimald-linux-amd64|SHA_MINIMALD_X86_64"
    "mip-linux-amd64|SHA_MIP_X86_64"
    "gvproxy-linux-amd64|SHA_GVPROXY_X86_64"
    "minvmd-linux-amd64|SHA_MINVMD_X86_64"
    "minimal-linux-arm64|SHA_MIN_AARCH64"
    "minimald-linux-arm64|SHA_MINIMALD_AARCH64"
    "mip-linux-arm64|SHA_MIP_AARCH64"
    "gvproxy-linux-arm64|SHA_GVPROXY_AARCH64"
    "minvmd-linux-arm64|SHA_MINVMD_AARCH64"
)

dist="$workdir/dist"
mkdir -p "$dist"
for entry in "${ARTIFACTS[@]}"; do
    IFS='|' read -r name var <<<"$entry"
    url="$BUCKET_URL/versions/$ROW/$name"
    curl -fsSL --retry 3 -o "$dist/$name" "$url" \
        || die "cannot download $url — is row $ROW staged in the bucket? (see stage-release.sh)"
    # Assign through a variable so a missing sha256 tool fails HERE rather than
    # stamping an empty SHA_* and dying later in the renderer with a message
    # that names the wrong thing (a command substitution's status cannot reach
    # printf -v).
    sha="$(sha256_file "$dist/$name")" || die "cannot sha256 $dist/$name"
    [ -n "$sha" ] || die "empty sha256 for $dist/$name"
    printf -v "$var" '%s' "$sha"
done

# The renderer stamps from the environment. BUCKET_URL is the token behind
# the PKGBUILD's _bucket: a MINIMAL_BUCKET_URL override must change the source
# URLs along with the checksums fetched from them, or the two diverge silently.
# PKGVER is the normalized pkgver, ROW the bucket row, and PKGNAME/CONFLICTS
# the channel-specific package identity.
# shellcheck disable=SC2090  # CONFLICTS carries literal PKGBUILD quotes by design (see above)
export PKGNAME PKGVER ROW CONFLICTS BUCKET_URL
export SHA_APPARMOR SHA_APPARMOR_TUNABLE SHA_APPARMOR_LOADER \
       SHA_MIN_X86_64 SHA_MINIMALD_X86_64 SHA_MIP_X86_64 SHA_GVPROXY_X86_64 \
       SHA_MINVMD_X86_64 \
       SHA_MIN_AARCH64 SHA_MINIMALD_AARCH64 SHA_MIP_AARCH64 SHA_GVPROXY_AARCH64 \
       SHA_MINVMD_AARCH64

# Credentials: an agent-loaded key first, else AUR_SSH_PRIVATE_KEY from the
# environment. Never print the key material. A dry run may proceed without
# either by cloning the public mirror (it never pushes).
keyfile=""
if [ -n "${SSH_AUTH_SOCK:-}" ] && ssh-add -l >/dev/null 2>&1; then
    echo "publish-aur: using ssh-agent key"
elif [ -n "${AUR_SSH_PRIVATE_KEY:-}" ]; then
    keyfile="$workdir/aur-key"
    printf '%s\n' "$AUR_SSH_PRIVATE_KEY" >"$keyfile"
    chmod 600 "$keyfile"
    echo "publish-aur: using AUR_SSH_PRIVATE_KEY"
elif [ "$DRY_RUN" -eq 1 ]; then
    echo "publish-aur: [dry-run] no credentials; cloning the public https mirror"
    AUR_REPO_URL="$AUR_PUBLIC_URL"
else
    die "no AUR credentials: load the bot's key into an ssh-agent, or set AUR_SSH_PRIVATE_KEY (see the header)"
fi

# Ephemeral CI containers have no known_hosts entry for aur.archlinux.org;
# accept-new still verifies an existing entry, it only records the first sight.
ssh_base="${GIT_SSH_COMMAND:-ssh}"
[ -n "$keyfile" ] && ssh_base="$ssh_base -i $keyfile"
export GIT_SSH_COMMAND="$ssh_base -o StrictHostKeyChecking=accept-new"

git clone --depth 1 "$AUR_REPO_URL" "$workdir/aur" \
    || die "clone of $AUR_REPO_URL failed (check AUR credentials; see the header)"

"$RENDER" "$TEMPLATE" "$workdir/aur/PKGBUILD"
# The install hook is renamed to the channel package's name: it must match the
# PKGBUILD's install= line (pacman errors if it cannot find the file).
cp "$INSTALL_HOOK" "$workdir/aur/$PKGNAME.install"
# The AUR rules of submission require the license text beside the PKGBUILD.
cp "$LICENSE_FILE" "$workdir/aur/LICENSE"

# run_makepkg <dir> <writable> <makepkg args...> — run makepkg over a throwaway
# COPY of the package files, never the clone itself (a build must not leave its
# src/pkg trees in the repo we are about to `git add -A`). makepkg refuses to
# run as root outright (its EUID == 0 guard fires before the --printsrcinfo
# early-return; FS#67158, Arch declined to exempt it) — which is every
# container job. When root, run it as an unprivileged user over that copy (the
# workdir itself is 0700, so the copy must live outside it to be traversable).
# `writable` hands the copy to the stand-in too, which a real build (not
# --printsrcinfo) needs for its src/ and pkg/ trees.
run_makepkg() {
    local dir="$1" writable="$2" rundir rc; shift 2
    rundir="$(mktemp -d "${TMPDIR:-/tmp}/makepkg.XXXXXX")" || return 1
    [ -n "$rundir" ] || return 1
    cp "$dir/PKGBUILD" "$rundir/" || { rm -rf "$rundir"; return 1; }
    if [ -f "$dir/$PKGNAME.install" ]; then
        cp "$dir/$PKGNAME.install" "$rundir/" || { rm -rf "$rundir"; return 1; }
    fi
    local args
    args="$(printf '%q ' "$@")"
    if [ "$(id -u)" -ne 0 ]; then
        # Unprivileged (a dev host, a non-root CI runner): makepkg runs directly.
        (cd "$rundir" && makepkg "$@")
        rc=$?
    elif [ "$writable" = 1 ]; then
        chown -R nobody "$rundir" || { rm -rf "$rundir"; return 1; }
    else
        chmod -R a+rX "$rundir"
    fi
    if [ "$(id -u)" -eq 0 ]; then
        # runuser (util-linux) is the purpose-built root form — no PAM auth path
        # to trip over; su is the fallback. Both rewrite HOME/PATH toward the
        # target account (runuser also resets PATH to the login.defs default),
        # so the payload re-exports the caller's PATH — where makepkg, and any
        # harness stub shadowing it, live — and the scratch HOME explicitly.
        if id nobody >/dev/null 2>&1; then
            if command -v runuser >/dev/null 2>&1; then
                runuser -u nobody -- bash -c "export PATH=\"$PATH\" HOME='$rundir'; cd '$rundir' && makepkg $args" </dev/null
                rc=$?
            elif command -v su >/dev/null 2>&1; then
                su -s /bin/bash nobody -c "export PATH=\"$PATH\" HOME='$rundir'; cd '$rundir' && makepkg $args" </dev/null
                rc=$?
            else
                echo "publish-aur: neither runuser nor su available to run makepkg as root's stand-in" >&2
                rc=1
            fi
        else
            echo "publish-aur: no unprivileged user to run makepkg as root's stand-in" >&2
            rc=1
        fi
    fi
    rm -rf "$rundir"
    return "$rc"
}

# generate_srcinfo <dir> — print the .SRCINFO for the PKGBUILD in dir.
generate_srcinfo() {
    run_makepkg "$1" 0 --printsrcinfo
}

if command -v makepkg >/dev/null 2>&1; then
    # Write-then-rename: a failure must leave the cloned .SRCINFO intact, not
    # truncated by the redirect that was supposed to overwrite it.
    srcinfo_next="$workdir/.SRCINFO.next"
    if generate_srcinfo "$workdir/aur" >"$srcinfo_next"; then
        mv "$srcinfo_next" "$workdir/aur/.SRCINFO"
        echo "publish-aur: regenerated .SRCINFO"
    else
        rm -f "$srcinfo_next"
        die "makepkg --printsrcinfo failed — the rendered PKGBUILD is invalid"
    fi
else
    echo "publish-aur: makepkg not found; skipping .SRCINFO regeneration (run on an Arch host)" >&2
fi

# --- Real build of the rendered PKGBUILD (--verify-build) --------------------
# A .SRCINFO generation proves the PKGBUILD parses; it does not prove it
# BUILDS. --verify-build runs the real `makepkg -f` over the rendered package
# (sources downloaded from the bucket, package() running the packaged binaries
# to generate completions) before anything is pushed, so a channel publish
# cannot land a PKGBUILD that only Arch users find broken. The build happens in
# a throwaway copy, so nothing lands in the repo being committed.
# It is opt-in because it downloads and runs the release binaries: the CI
# publish jobs pass it, `just`/local rehearsals need not.
if [ "$VERIFY_BUILD" -eq 1 ]; then
    command -v makepkg >/dev/null 2>&1 \
        || die "--verify-build needs makepkg on PATH (run in an Arch container)"
    echo "publish-aur: --verify-build: building $PKGNAME $PKGVER with makepkg"
    if ! run_makepkg "$workdir/aur" 1 -f --noconfirm; then
        die "makepkg -f failed on the rendered PKGBUILD — refusing to publish a package that does not build"
    fi
    echo "publish-aur: --verify-build: makepkg build succeeded"
fi

cd "$workdir/aur"

# The AUR server does not check commit identity; default it so a fresh CI
# container (no global git config) still commits. An existing identity wins.
git config user.name  >/dev/null || git config user.name "minimal-ci"
git config user.email >/dev/null || git config user.email "minimal-ci@users.noreply.archlinux.com"

git add -A

if [ "$DRY_RUN" -eq 1 ]; then
    echo "publish-aur: [dry-run] diff that would be committed as 'Update to $VERSION':"
    # --no-ext-diff: the diff is machine-checked output for a human to review
    # before a push; an ambient diff.external (difftastic et al.) would change
    # its shape per runner config.
    git --no-pager diff --cached --no-ext-diff
    echo "publish-aur: [dry-run] nothing committed, nothing pushed"
    exit 0
fi

if git diff --cached --quiet; then
    echo "publish-aur: AUR repo already at $VERSION; nothing to push"
    exit 0
fi

git commit -m "Update to $VERSION"

# Sanity guard: only ever push to the AUR remote itself.
remote_url="$(git remote get-url origin)"
case "$remote_url" in
    ssh://aur@aur.archlinux.org/*|git@aur.archlinux.org:*|aur@aur.archlinux.org:*) ;;
    *) die "refusing to push: origin '$remote_url' is not the AUR remote" ;;
esac
git push origin HEAD:master

echo "publish-aur: pushed $PKGNAME $VERSION to $remote_url"
