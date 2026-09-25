#!/usr/bin/env bash
#
# publish-smoke.sh — install the AUR package and the Homebrew formula a stable
# promotion would publish for a staged versioned release, before anything is
# published.
#
# The publishers (scripts/publish-aur.sh, scripts/publish-brew.sh) are driven
# in --dry-run mode against the real public remotes, which needs no
# credentials. The diff each one prints is exactly what it would push; this
# script applies that diff to a fresh clone of the same remote and installs
# the result:
#
#   aur   Arch Linux (x86_64). `makepkg -si` builds and installs minimal-bin
#         from the rendered PKGBUILD, whose sources are the staged
#         versions/$PKGVER/ row. Asserts pacman records the version, every
#         packaged path exists, `min`/`mip`/`minimald` run and report
#         $PKGVER, then removes the package again. Off Arch, the script
#         re-runs itself in an archlinux:base-devel container (docker; the
#         image is amd64-only, so Apple Silicon runs it emulated).
#   brew  macOS arm64 with Homebrew. Installs the rendered formula from a
#         throwaway local tap, runs `brew test`, asserts the keg layout and
#         that `min` reports $PKGVER, then uninstalls and untaps. The formula
#         downloads from the GitHub Release, which is still a draft before
#         publishing, so the test copy points its URLs at the staged row
#         (same bytes, same sha256s) and pins `version` explicitly. The real
#         URLs are proved only by `brew install gominimal/minimal/minimal`
#         after publishing. Refuses to run when a `minimal` formula is
#         already installed. Installing pulls in slp/krun/libkrun (the
#         formula's dependency), which stays installed afterwards.
#
# Usage: PKGVER=X.Y.Z scripts/publish-smoke.sh aur|brew
#
# Env:
#   PKGVER              Required. The staged semver, without the v prefix. The
#                       publishers reject shas and prereleases.
#   MINIMAL_BUCKET_URL  Installer bucket base URL
#                       (default: https://storage.googleapis.com/minimal-one).
#                       A file:// mirror works for local rehearsal; the aur
#                       container mounts it at the same path.
#
# Exit 0 when every check passed; non-zero otherwise.
#
# Requires: bash, git, curl. aur: pacman + makepkg (Arch), or docker. brew:
# macOS arm64 and brew.

set -euo pipefail

die() { printf 'publish-smoke: error: %s\n' "$*" >&2; exit 1; }
say() { printf 'publish-smoke: %s\n' "$*"; }
usage() { sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-}" in
    aur|brew) MODE="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "expected 'aur' or 'brew'" ;;
esac

[ -n "${PKGVER:-}" ] || die "PKGVER is required (the staged semver, without the v prefix)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUCKET_URL="${MINIMAL_BUCKET_URL:-https://storage.googleapis.com/minimal-one}"
AUR_URL="https://aur.archlinux.org/minimal-bin.git"
TAP_URL="https://github.com/gominimal/homebrew-minimal.git"

# The row must be staged; fail here with a clear message instead of deep in
# a publisher's download loop.
curl -fsS -o /dev/null "$BUCKET_URL/versions/$PKGVER/components" \
    || die "versions/$PKGVER is not staged at $BUCKET_URL (run release.yml with versioned: true first)"

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t publish-smoke)"
trap 'rm -rf "$workdir"' EXIT

# render PUBLISHER REMOTE DEST [ENV=VALUE...]: run the publisher's dry run,
# cut the would-be diff out of its output, and apply it to a fresh clone of
# REMOTE at DEST. An empty diff means the remote is already at $PKGVER.
render() {
    local publisher="$1" remote="$2" dest="$3"
    shift 3
    local log
    log="$workdir/$(basename "$publisher").log"
    env "$@" PKGVER="$PKGVER" "$publisher" --dry-run >"$log" 2>&1 \
        || { cat "$log" >&2; die "$(basename "$publisher") --dry-run failed"; }
    awk '/\[dry-run\] nothing committed/ {p=0} p {print} /\[dry-run\] diff that would be committed/ {p=1}' \
        "$log" >"$workdir/publish.patch"
    git clone -q --depth 1 "$remote" "$dest" 2>/dev/null \
        || die "clone of $remote failed"
    if [ -s "$workdir/publish.patch" ]; then
        git -C "$dest" apply --index "$workdir/publish.patch" \
            || die "the $(basename "$publisher") diff does not apply to $remote"
    else
        say "$remote is already at $PKGVER; testing it as is"
    fi
}

# check_version BIN...: each binary runs and reports $PKGVER.
check_version() {
    local bin out
    for bin in "$@"; do
        out="$("$bin" --version 2>&1)" || die "$bin --version failed: $out"
        case "$out" in
            *"$PKGVER"*) say "ok: $bin --version -> $out" ;;
            *) die "$bin reports '$out', expected $PKGVER" ;;
        esac
    done
}

smoke_aur() {
    if ! command -v pacman >/dev/null 2>&1; then
        command -v docker >/dev/null 2>&1 \
            || die "aur needs an Arch host or docker (for archlinux:base-devel)"
        local mounts=(-v "$ROOT:/src:ro")
        case "$BUCKET_URL" in
            file://*) mounts+=(-v "${BUCKET_URL#file://}:${BUCKET_URL#file://}:ro") ;;
        esac
        say "not on Arch; re-running in archlinux:base-devel (linux/amd64)"
        # pacman's download sandbox (seccomp + the alpm user) fails under
        # qemu emulation; the container is throwaway, so switch it off there.
        exec docker run --rm --platform linux/amd64 "${mounts[@]}" \
            -e PKGVER="$PKGVER" -e MINIMAL_BUCKET_URL="$BUCKET_URL" \
            archlinux:base-devel bash -c \
            "sed -i '/^\\[options\\]/a DisableSandbox' /etc/pacman.conf &&
             pacman -Syu --noconfirm --needed git openssh >/dev/null &&
             /src/scripts/publish-smoke.sh aur"
    fi
    command -v makepkg >/dev/null 2>&1 || die "makepkg not found (install base-devel)"

    # No credentials on purpose: the dry run then clones the public mirror,
    # the same remote rendered here.
    render "$ROOT/scripts/publish-aur.sh" "$AUR_URL" "$workdir/aur" \
        -u SSH_AUTH_SOCK -u AUR_SSH_PRIVATE_KEY MINIMAL_BUCKET_URL="$BUCKET_URL"

    # makepkg refuses to run as root; build as a throwaway user with sudo.
    local build=(bash -c)
    if [ "$(id -u)" -eq 0 ]; then
        id publish-smoke >/dev/null 2>&1 || useradd -m publish-smoke
        printf 'publish-smoke ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/publish-smoke
        chmod 440 /etc/sudoers.d/publish-smoke
        chmod 755 "$workdir"
        chown -R publish-smoke "$workdir/aur"
        build=(runuser -u publish-smoke -- bash -c)
    fi
    "${build[@]}" "cd '$workdir/aur' && makepkg -si --noconfirm" \
        || die "makepkg -si failed for the rendered PKGBUILD"

    local recorded
    recorded="$(pacman -Q minimal-bin)"
    case "$recorded" in
        "minimal-bin 1:$PKGVER-"*) say "ok: pacman records $recorded" ;;
        *) die "pacman records '$recorded', expected minimal-bin 1:$PKGVER-*" ;;
    esac
    local path
    for path in /usr/bin/min /usr/bin/minimald /usr/bin/mip /usr/bin/minvmd \
        /usr/bin/gvproxy-min /usr/bin/git-remote-min \
        /usr/share/minimal/apparmor/minimald \
        /usr/share/minimal/apparmor/tunables/minimald \
        /usr/share/minimal/apparmor/install-apparmor-profile.sh \
        /usr/share/bash-completion/completions/min \
        /usr/share/zsh/site-functions/_min \
        /usr/share/fish/vendor_completions.d/min.fish; do
        [ -e "$path" ] || die "missing after install: $path"
    done
    say "ok: every packaged path exists"
    check_version /usr/bin/min /usr/bin/mip /usr/bin/minimald

    local sudo=()
    [ "$(id -u)" -eq 0 ] || sudo=(sudo)
    "${sudo[@]}" pacman -R --noconfirm minimal-bin >/dev/null
    [ ! -e /usr/bin/min ] || die "/usr/bin/min survived pacman -R"
    say "ok: pacman -R removed the package"
    say "aur: minimal-bin $PKGVER passed"
}

smoke_brew() {
    [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || die "brew needs macOS arm64 (the formula is arm64-only)"
    command -v brew >/dev/null 2>&1 || die "brew not found"
    if brew list --formula --versions minimal >/dev/null 2>&1; then
        die "a 'minimal' formula is already installed; uninstall it first"
    fi

    local rel="$BUCKET_URL/versions/$PKGVER"
    render "$ROOT/scripts/publish-brew.sh" "$TAP_URL" "$workdir/tap" \
        -u GITHUB_TOKEN BREW_TAP_REPO="$TAP_URL" MINIMAL_RELEASE_URL="$rel"

    # Test copy: download from the staged row, not the draft release.
    local formula="$workdir/tap/Formula/minimal.rb"
    # awk, not sed: BSD sed has no first-match-only address.
    awk -v from="https://github.com/gominimal/minimal/releases/download/v$PKGVER" \
        -v to="$rel" -v ver="$PKGVER" '
        { while ((i = index($0, from)) > 0) $0 = substr($0, 1, i - 1) to substr($0, i + length(from)) }
        { print }
        !done && /^  url / { print "  version \"" ver "\""; done = 1 }
    ' "$formula" >"$workdir/minimal.rb"
    grep -q 'releases/download' "$workdir/minimal.rb" \
        && die "a GitHub Release URL survived the rewrite"

    local tap="publish-smoke/local"
    export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1
    brew untap "$tap" >/dev/null 2>&1 || true
    brew tap-new --no-git "$tap" >/dev/null
    trap 'brew uninstall --formula "$tap/minimal" >/dev/null 2>&1 || true; brew untap "$tap" >/dev/null 2>&1 || true; rm -rf "$workdir"' EXIT
    cp "$workdir/minimal.rb" "$(brew --repository "$tap")/Formula/minimal.rb"

    brew install --formula "$tap/minimal" || die "brew install failed"
    brew test "$tap/minimal" || die "brew test failed"

    local prefix
    prefix="$(brew --prefix "$tap/minimal")"
    local path
    for path in bin/min bin/minvmd bin/gvproxy-min bin/git-remote-min lib/libkrun.1.dylib; do
        [ -e "$prefix/$path" ] || die "missing in the keg: $path"
    done
    say "ok: keg layout (bin/min, bin/minvmd, bin/gvproxy-min, bin/git-remote-min, lib/libkrun.1.dylib)"
    check_version "$prefix/bin/min"
    # minvmd links libkrun through @loader_path/../lib; running it proves the
    # dylib resolves from the keg.
    "$prefix/bin/minvmd" --version >/dev/null 2>&1 \
        || die "minvmd does not start from the keg (libkrun linkage?)"
    say "ok: minvmd starts and loads libkrun from the keg"
    say "brew: minimal $PKGVER passed"
}

"smoke_$MODE"
