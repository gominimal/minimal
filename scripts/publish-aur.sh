#!/usr/bin/env bash
#
# publish-aur.sh — clone the minimal-bin AUR repo, stamp the PKGBUILD, push.
#
# The monorepo is the source of truth for the AUR package; the AUR repo is
# generated output. Each run shallow-clones a fresh copy, downloads the 11
# versioned artifacts from the installer bucket to compute their sha256s,
# renders packaging/arch/PKGBUILD-bin.tmpl into PKGBUILD, copies the pacman
# install hook, regenerates .SRCINFO, and commits + pushes.
#
# Usage: scripts/publish-aur.sh [--dry-run]
#
# Env:
#   PKGVER              Required. Promoted semver WITHOUT the v prefix
#                       (X.Y.Z, optional -prerelease/+build tail). Artifacts
#                       are fetched from <bucket>/versions/$PKGVER/ — the
#                       same names the PKGBUILD's source arrays use. A bare
#                       short SHA is rejected: the AUR package tracks
#                       promoted semver releases, not nightly builds.
#   AUR_REPO_URL        git URL to clone/push
#                       (default: ssh://aur@aur.archlinux.org/minimal-bin.git)
#   MINIMAL_BUCKET_URL  Public base URL of the installer bucket
#                       (default: https://storage.googleapis.com/minimal-one)
#   MAINTAINER          PKGBUILD maintainer line. Defaults below to the
#                       noreply placeholder until an official contact exists;
#                       set this to override. Personal addresses are not
#                       checked into this repo.
#
# Credentials (env/ssh-agent only — never hardcoded or echoed here):
#   - an ssh-agent holding the bot's AUR key (SSH_AUTH_SOCK set), or
#   - AUR_SSH_PRIVATE_KEY in the environment (PEM text); it is written to a
#     0600 file in the temp workdir for the run and removed with it.
#   The bot AUR account must be a co-maintainer of minimal-bin. AUR has no
#   key-management API: generate a dedicated keypair, put the public key on
#   the account, store the private key in the CI secret AUR_SSH_PRIVATE_KEY,
#   and keep the account password/recovery email in a shared vault.
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

# The PKGBUILD maintainer line; placeholder until an official contact exists.
MAINTAINER="${MAINTAINER:-minimal <noreply@minimal.dev>}"
export MAINTAINER
case "$PKGVER" in
    v*) die "PKGVER must not carry the v prefix: '$PKGVER' (use ${PKGVER#v})" ;;
esac
printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' \
    || die "PKGVER '$PKGVER' is not a semver X.Y.Z (optional -prerelease/+build)"

AUR_REPO_URL="${AUR_REPO_URL:-ssh://aur@aur.archlinux.org/minimal-bin.git}"
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
# Same order as the PKGBUILD's source arrays, so makepkg's positional
# sha256sums stay aligned.
ARTIFACTS=(
    "minimald.apparmor|SHA_APPARMOR"
    "minimald.apparmor-tunable|SHA_APPARMOR_TUNABLE"
    "install-apparmor-profile.sh|SHA_APPARMOR_LOADER"
    "minimal-linux-amd64|SHA_MIN_X86_64"
    "minimald-linux-amd64|SHA_MINIMALD_X86_64"
    "mip-linux-amd64|SHA_MIP_X86_64"
    "gvproxy-linux-amd64|SHA_GVPROXY_X86_64"
    "minimal-linux-arm64|SHA_MIN_AARCH64"
    "minimald-linux-arm64|SHA_MINIMALD_AARCH64"
    "mip-linux-arm64|SHA_MIP_AARCH64"
    "gvproxy-linux-arm64|SHA_GVPROXY_AARCH64"
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

# The renderer stamps from the environment.
export PKGVER
export SHA_APPARMOR SHA_APPARMOR_TUNABLE SHA_APPARMOR_LOADER \
       SHA_MIN_X86_64 SHA_MINIMALD_X86_64 SHA_MIP_X86_64 SHA_GVPROXY_X86_64 \
       SHA_MIN_AARCH64 SHA_MINIMALD_AARCH64 SHA_MIP_AARCH64 SHA_GVPROXY_AARCH64

# Credentials: an agent-loaded key first, else AUR_SSH_PRIVATE_KEY from the
# environment. Never print the key material.
keyfile=""
if [ -n "${SSH_AUTH_SOCK:-}" ] && ssh-add -l >/dev/null 2>&1; then
    echo "publish-aur: using ssh-agent key"
elif [ -n "${AUR_SSH_PRIVATE_KEY:-}" ]; then
    keyfile="$workdir/aur-key"
    printf '%s\n' "$AUR_SSH_PRIVATE_KEY" >"$keyfile"
    chmod 600 "$keyfile"
    echo "publish-aur: using AUR_SSH_PRIVATE_KEY"
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

if command -v makepkg >/dev/null 2>&1; then
    (cd "$workdir/aur" && makepkg --printsrcinfo > .SRCINFO) \
        || die "makepkg --printsrcinfo failed — the rendered PKGBUILD is invalid"
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
    git --no-pager diff --cached
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
