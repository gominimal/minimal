#!/usr/bin/env bash
#
# publish-brew.sh — clone the gominimal/homebrew-minimal tap, stamp the
# Formula, push.
#
# The monorepo is the source of truth for the Homebrew formula; the tap repo
# is generated output. Each run shallow-clones a fresh copy, downloads the
# four macOS arm64 assets (min, minvmd, gvproxy, and the libkrun dylib) from
# the GitHub Release v$PKGVER to compute their sha256s, renders
# packaging/homebrew/minimal.rb.tmpl into Formula/minimal.rb, and commits +
# pushes.
#
# Usage: scripts/publish-brew.sh [--dry-run]
#
# Env:
#   PKGVER              Required. A RELEASED semver WITHOUT the v prefix
#                       (X.Y.Z, optional +build tail). Assets are fetched from
#                       the GitHub Release v$PKGVER of gominimal/minimal. A
#                       bare short SHA is rejected: the tap tracks promoted
#                       semver releases, not nightly builds. A prerelease
#                       (-rc.1 tail) is rejected too: Homebrew has no
#                       channels, so an RC would overwrite the only formula
#                       for every user with no way to opt out.
#   BREW_TAP_REPO       git URL to clone/push
#                       (default: git@github.com:gominimal/homebrew-minimal.git)
#   MINIMAL_RELEASE_URL Base URL the release assets are fetched from
#                       (default: the GitHub Release download URL for
#                       gominimal/minimal v$PKGVER). Overridable so a local
#                       fixture can drive --dry-run without network access.
#
# Credentials (env/ssh-agent only — never hardcoded or echoed here):
#   - an ssh-agent holding a key with push access to the tap (for the SSH
#     default URL), e.g. a dedicated SSH deploy key added to the tap repo;
#   - or GITHUB_TOKEN in the environment (a fine-grained PAT with write
#     access, or the Actions token), used with an https:// repo URL through
#     a one-shot askpass helper that lives in the temp workdir and is removed
#     with it, so the token never appears in argv, the remote URL, or an
#     error message.
#   A bare developer GitHub key on the ssh-agent or an https credential
#   helper also work — no special setup is enforced; a failed clone is
#   reported with the likely causes.
#
# First run: the tap repo must exist (user action) — create a new empty
# repository at https://github.com/gominimal/homebrew-minimal, then run this.
#
# --dry-run does everything up to the commit and prints the would-be diff.
#
# Requires: bash, git, curl, and a SHA-256 tool (sha256sum, shasum, or
# openssl).

set -euo pipefail

die() {
    printf 'publish-brew: %s\n' "$1" >&2
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
case "$PKGVER" in
    v*) die "PKGVER must not carry the v prefix: '$PKGVER' (use ${PKGVER#v})" ;;
esac
# A release only: no prerelease tail (Homebrew has no channels — an RC would
# overwrite the one formula for every user), no bare sha. A +build tail is a
# valid release version and passes.
printf '%s\n' "$PKGVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(\+[0-9A-Za-z.-]+)?$' \
    || die "PKGVER '$PKGVER' is not a RELEASED semver X.Y.Z (optional +build; prereleases and shas are rejected: Homebrew has no channels)"

BREW_TAP_REPO="${BREW_TAP_REPO:-git@github.com:gominimal/homebrew-minimal.git}"
RELEASE_URL_BASE="${MINIMAL_RELEASE_URL:-https://github.com/gominimal/minimal/releases/download/v$PKGVER}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/packaging/homebrew/minimal.rb.tmpl"
RENDER="$ROOT/scripts/render-packaging.sh"
[ -f "$TEMPLATE" ] || die "no such template: $TEMPLATE"
[ -x "$RENDER" ] || die "renderer missing or not executable: $RENDER"

# One release asset per sha256 the Formula declares: the url asset plus each
# resource. Same names as the GitHub Release (release.yml's release job
# uploads the release artifacts flat, basenames unchanged).
# asset basename | env var holding its sha256 (the template's @@TOKEN@@)
ASSETS=(
    "minimal-macos-arm64|SHA256"
    "minvmd-macos-arm64|SHA_MINVMD"
    "gvproxy-darwin-arm64|SHA_GVPROXY"
    "libkrun-macos-arm64.dylib|SHA_LIBKRUN"
)

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t publish-brew)"
trap 'rm -rf "$workdir"' EXIT

# Bare lowercase hex digest of file $1. sha256sum (Linux CI), shasum (macOS),
# or openssl anywhere — a publish run should work from a Mac too.
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

dist="$workdir/dist"
mkdir -p "$dist"
for entry in "${ASSETS[@]}"; do
    IFS='|' read -r name var <<<"$entry"
    url="$RELEASE_URL_BASE/$name"
    curl -fsSL --retry 3 -o "$dist/$name" "$url" \
        || die "cannot download $url — is v$PKGVER a GitHub Release of gominimal/minimal carrying the macOS arm64 assets?"
    printf -v "$var" '%s' "$(sha256_file "$dist/$name")"
done

# The renderer stamps from the environment (VERSION for the @@VERSION@@
# token; PKGVER stays for error messages).
export PKGVER
export VERSION="$PKGVER"
export SHA256 SHA_MINVMD SHA_GVPROXY SHA_LIBKRUN

# Never let git hang on an interactive https credential prompt.
export GIT_TERMINAL_PROMPT=0

# Credentials: an agent-loaded key (or the system's default) for the SSH
# repo URL; GITHUB_TOKEN for an https URL. Never print the key material.
if [ -n "${GITHUB_TOKEN:-}" ]; then
    case "$BREW_TAP_REPO" in
        https://*) ;;
        *) die "GITHUB_TOKEN is set but $BREW_TAP_REPO is not an https URL — use the https:// form, or drop GITHUB_TOKEN and use an ssh-agent key" ;;
    esac
    # One-shot askpass: git invokes it for the username/password pair; the
    # token is read from the environment at that moment, never written out.
    askpass="$workdir/askpass.sh"
    cat >"$askpass" <<'EOF'
#!/bin/sh
case "$1" in
    *Username*) printf '%s\n' "x-access-token" ;;
    *Password*) printf '%s\n' "$GITHUB_TOKEN" ;;
esac
EOF
    chmod 700 "$askpass"
    export GIT_ASKPASS="$askpass"
    echo "publish-brew: using GITHUB_TOKEN (https)"
elif [ -n "${SSH_AUTH_SOCK:-}" ] && ssh-add -l >/dev/null 2>&1; then
    echo "publish-brew: using ssh-agent key"
fi

clone_err="$workdir/clone.err"
if ! git clone --depth 1 "$BREW_TAP_REPO" "$workdir/tap" 2>"$clone_err"; then
    # For a github.com remote, tell "the repo does not exist (yet)" apart
    # from "no access": a public API probe distinguishes a 404 (create it)
    # from a 403 (credentials). A failed probe is not conclusive — say so.
    case "$BREW_TAP_REPO" in
        git@github.com:*|https://github.com/*)
            repo_path="${BREW_TAP_REPO#git@github.com:}"
            repo_path="${repo_path#https://github.com/}"
            repo_path="${repo_path%.git}"
            status="$(curl -s -o /dev/null -w '%{http_code}' \
                "https://api.github.com/repos/$repo_path" || true)"
            case "$status" in
                404)
                    die "clone failed: $repo_path does not exist (yet) or is private — create it first (user action): a new public repository at https://github.com/$repo_path, then rerun"
                    ;;
                403)
                    die "clone failed: $repo_path exists but this identity has no access — check credentials (see the header)"
                    ;;
                *)
                    tail -n 3 "$clone_err" >&2
                    die "clone failed (probe inconclusive) — check the repo exists and credentials (see the header)"
                    ;;
            esac
            ;;
    esac
    tail -n 3 "$clone_err" >&2
    die "clone of $BREW_TAP_REPO failed — check the repo exists and credentials (see the header)"
fi

mkdir -p "$workdir/tap/Formula"
"$RENDER" "$TEMPLATE" "$workdir/tap/Formula/minimal.rb"

cd "$workdir/tap"

# A fresh CI container (no global git config) must still commit; an existing
# identity wins.
git config user.name  >/dev/null || git config user.name "minimal-ci"
git config user.email >/dev/null || git config user.email "minimal-ci@users.noreply.github.com"

git add -A

if [ "$DRY_RUN" -eq 1 ]; then
    echo "publish-brew: [dry-run] diff that would be committed as 'minimal $PKGVER':"
    # --no-ext-diff: machine-checked output, shape must not depend on the
    # runner's git config (see publish-aur.sh).
    git --no-pager diff --cached --no-ext-diff
    echo "publish-brew: [dry-run] nothing committed, nothing pushed"
    exit 0
fi

if git diff --cached --quiet; then
    echo "publish-brew: tap already at $PKGVER; nothing to push"
    exit 0
fi

git commit -m "minimal $PKGVER"

# Sanity guard: only ever push to the tap repo we cloned.
remote_url="$(git remote get-url origin)"
[ "$remote_url" = "$BREW_TAP_REPO" ] \
    || die "refusing to push: origin '$remote_url' is not $BREW_TAP_REPO"
# The tap's default branch; GitHub repos default to main (an empty repo takes
# the name of the first push).
git push origin HEAD:refs/heads/main

echo "publish-brew: pushed minimal $PKGVER to $remote_url"
