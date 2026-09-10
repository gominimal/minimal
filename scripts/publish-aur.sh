#!/usr/bin/env bash
#
# publish-aur.sh — clone the minimal-bin AUR repo, stamp the PKGBUILD, push.
#
# The monorepo is the source of truth for the AUR package; the AUR repo is
# generated output. Each run shallow-clones a fresh copy, downloads the 13
# versioned artifacts from the installer bucket to compute their sha256s,
# renders packaging/arch/PKGBUILD-bin.tmpl into PKGBUILD, copies the pacman
# install hook, regenerates .SRCINFO, and commits + pushes.
#
# Usage: scripts/publish-aur.sh [--dry-run]
#
# Env:
#   PKGVER              Required. A RELEASED semver WITHOUT the v prefix
#                       (X.Y.Z, optional +build tail). Artifacts are fetched
#                       from <bucket>/versions/$PKGVER/ — the same names the
#                       PKGBUILD's source arrays use. A bare short SHA is
#                       rejected, and so is a prerelease (-rc.1 tail): pacman
#                       forbids hyphens in pkgver, so an RC could never be
#                       published here anyway. The AUR package tracks
#                       promoted semver releases, not nightly builds.
#   AUR_REPO_URL        git URL to clone/push
#                       (default: ssh://aur@aur.archlinux.org/minimal-bin.git).
#                       --dry-run without credentials falls back to the public
#                       read-only https mirror so a rehearsal needs no key.
#   MINIMAL_BUCKET_URL  Public base URL of the installer bucket
#                       (default: https://storage.googleapis.com/minimal-one)
#   MAINTAINER          PKGBUILD maintainer line. Defaults below to the
#                       project contact; set this to override. Personal
#                       addresses are not checked into this repo.
#
# Credentials (env/ssh-agent only — never hardcoded or echoed here):
#   - an ssh-agent holding the bot's AUR key (SSH_AUTH_SOCK set), or
#   - AUR_SSH_PRIVATE_KEY in the environment (PEM text); it is written to a
#     0600 file in the temp workdir for the run and removed with it.
#   The bot AUR account must be a co-maintainer of minimal-bin. AUR has no
#   key-management API: generate a dedicated keypair, put the public key on
#   the account, store the private key in the CI secret AUR_SSH_PRIVATE_KEY,
#   and keep the account password/recovery email in a shared vault.
#   --dry-run does not push, so it does not need a key: without one it reads
#   the public https mirror instead.
#
# --dry-run does everything up to the commit and prints the would-be diff.
#
# Requires: bash, git, curl, sha256sum; makepkg (Arch) for .SRCINFO — without
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
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $arg (try --help)" ;;
    esac
done

[ -n "${PKGVER:-}" ] || die "PKGVER is required (the promoted semver, without the v prefix)"

# The PKGBUILD maintainer line.
MAINTAINER="${MAINTAINER:-minimal <security@minimal.dev>}"
export MAINTAINER
case "$PKGVER" in
    v*) die "PKGVER must not carry the v prefix: '$PKGVER' (use ${PKGVER#v})" ;;
esac
# A release only: pacman's pkgver forbids hyphens, so a prerelease tail
# (-rc.1) could never publish — reject it here with that named, instead of
# letting makepkg's lint blame the template. A +build tail is a valid release
# version and passes.
printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(\+[0-9A-Za-z.-]+)?$' \
    || die "PKGVER '$PKGVER' is not a RELEASED semver X.Y.Z (optional +build; prereleases and shas are rejected: pacman's pkgver forbids hyphens)"

AUR_REPO_URL="${AUR_REPO_URL:-ssh://aur@aur.archlinux.org/minimal-bin.git}"
# The public read-only mirror. Same repo, no credentials — a --dry-run needs
# to clone to produce its diff, and demanding the bot key for a rehearsal made
# dry-runs unreachable outside CI.
AUR_PUBLIC_URL="https://aur.archlinux.org/minimal-bin.git"
BUCKET_URL="${MINIMAL_BUCKET_URL:-https://storage.googleapis.com/minimal-one}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/packaging/arch/PKGBUILD-bin.tmpl"
INSTALL_HOOK="$ROOT/packaging/arch/minimal-bin.install"
RENDER="$ROOT/scripts/render-packaging.sh"
[ -f "$TEMPLATE" ] || die "no such template: $TEMPLATE"
[ -f "$INSTALL_HOOK" ] || die "no such install hook: $INSTALL_HOOK"
[ -x "$RENDER" ] || die "renderer missing or not executable: $RENDER"

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t publish-aur)"
trap 'rm -rf "$workdir"' EXIT

# artifact basename under versions/$PKGVER/ | env var holding its sha256.
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
    url="$BUCKET_URL/versions/$PKGVER/$name"
    curl -fsSL --retry 3 -o "$dist/$name" "$url" \
        || die "cannot download $url — is $PKGVER staged in the bucket? (see stage-release.sh)"
    printf -v "$var" '%s' "$(sha256sum "$dist/$name" | cut -d' ' -f1)"
done

# The renderer stamps from the environment. BUCKET_URL is the token behind
# the PKGBUILD's _bucket: a MINIMAL_BUCKET_URL override must change the source
# URLs along with the checksums fetched from them, or the two diverge silently.
export PKGVER BUCKET_URL
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
cp "$INSTALL_HOOK" "$workdir/aur/minimal-bin.install"

# makepkg --printsrcinfo refuses to run as root outright (its EUID == 0 guard
# fires before the printsrcinfo early-return; FS#67158, Arch declined to
# exempt it) — which is every container job. When root, run it as an
# unprivileged user over a world-readable copy of the package files (the
# workdir itself is 0700, so the copy must live outside it to be traversable).
# Prints the .SRCINFO on stdout.
generate_srcinfo() {
    local dir="$1" rundir rc
    # Unprivileged (a dev host, a non-root CI runner): makepkg runs directly.
    if [ "$(id -u)" -ne 0 ]; then
        (cd "$dir" && makepkg --printsrcinfo)
        return
    fi
    rundir="$(mktemp -d "${TMPDIR:-/tmp}/srcinfo.XXXXXX")" || return 1
    [ -n "$rundir" ] || return 1
    cp "$dir/PKGBUILD" "$rundir/" || { rm -rf "$rundir"; return 1; }
    if [ -f "$dir/minimal-bin.install" ]; then
        cp "$dir/minimal-bin.install" "$rundir/" || { rm -rf "$rundir"; return 1; }
    fi
    chmod -R a+rX "$rundir"
    # runuser (util-linux) is the purpose-built root form — no PAM auth path
    # to trip over; su is the fallback. Both rewrite HOME/PATH toward the
    # target account (runuser also resets PATH to the login.defs default),
    # so the payload re-exports the caller's PATH — where makepkg, and any
    # harness stub shadowing it, live — and the scratch HOME explicitly.
    if id nobody >/dev/null 2>&1; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u nobody -- bash -c "export PATH=\"$PATH\" HOME='$rundir'; cd '$rundir' && makepkg --printsrcinfo" </dev/null
            rc=$?
        elif command -v su >/dev/null 2>&1; then
            su -s /bin/bash nobody -c "export PATH=\"$PATH\" HOME='$rundir'; cd '$rundir' && makepkg --printsrcinfo" </dev/null
            rc=$?
        else
            echo "publish-aur: neither runuser nor su available to run makepkg as root's stand-in; skipping .SRCINFO" >&2
            rc=1
        fi
    else
        echo "publish-aur: no unprivileged user to run makepkg as root's stand-in; skipping .SRCINFO" >&2
        rc=1
    fi
    rm -rf "$rundir"
    return "$rc"
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

cd "$workdir/aur"

# The AUR server does not check commit identity; default it so a fresh CI
# container (no global git config) still commits. An existing identity wins.
git config user.name  >/dev/null || git config user.name "minimal-ci"
git config user.email >/dev/null || git config user.email "minimal-ci@users.noreply.archlinux.com"

git add -A

if [ "$DRY_RUN" -eq 1 ]; then
    echo "publish-aur: [dry-run] diff that would be committed as 'Update to $PKGVER':"
    # --no-ext-diff: the diff is machine-checked output for a human to review
    # before a push; an ambient diff.external (difftastic et al.) would change
    # its shape per runner config.
    git --no-pager diff --cached --no-ext-diff
    echo "publish-aur: [dry-run] nothing committed, nothing pushed"
    exit 0
fi

if git diff --cached --quiet; then
    echo "publish-aur: AUR repo already at $PKGVER; nothing to push"
    exit 0
fi

git commit -m "Update to $PKGVER"

# Sanity guard: only ever push to the AUR remote itself.
remote_url="$(git remote get-url origin)"
case "$remote_url" in
    ssh://aur@aur.archlinux.org/*|git@aur.archlinux.org:*|aur@aur.archlinux.org:*) ;;
    *) die "refusing to push: origin '$remote_url' is not the AUR remote" ;;
esac
git push origin HEAD:master

echo "publish-aur: pushed minimal-bin $PKGVER to $remote_url"
