#!/usr/bin/env bash
#
# pkg-smoke.sh — install-smoke the .deb/.rpm/.apk that scripts/package-nfpm.sh
# built, in disposable distrobox containers, before anything is published.
#
# For each requested format it creates a throwaway box named
# min-test-{deb,rpm,apk}, installs the package for this host's architecture,
# and asserts the contract the packages ship (see packaging/nfpm.yaml):
#
#   - the package manager accepts the install and records the exact version
#   - every shipped path exists: the 5 binaries, the git-remote-min symlink,
#     the AppArmor triplet, and the bash/zsh/fish completions
#   - the binaries execute on the box's libc (glibc for deb/rpm, musl for apk)
#   - an uninstall round-trip removes the binaries again
#
# With --apparmor the deb box additionally installs the apparmor package first,
# so the postinstall exercises its parser-present branch, and the packaged
# profile must still parse (`install-apparmor-profile.sh --check`). The kernel
# load itself is never asserted: a distrobox box is unprivileged (no
# CAP_MAC_ADMIN) and kernels without AppArmor cannot take a profile at all —
# the package must install cleanly either way, which is the invariant here.
#
# Usage:
#   scripts/pkg-smoke.sh [--pkg-dir DIR] [--formats deb,rpm,apk]
#                        [--apparmor] [--keep-boxes]
#
#   --pkg-dir DIR   Where the packages are (default: dist/, package-nfpm.sh's
#                   OUT_DIR default). Passed through as an absolute path, so
#                   keep it under $HOME for the box to see it.
#   --formats LIST  Comma-separated subset of deb,rpm,apk (default: all three).
#   --apparmor      Also run the deb box with apparmor installed (see above).
#   --keep-boxes    Leave the boxes behind for manual poking (default: removed
#                   even on failure, so reruns start clean).
#
# Exit 0 if every requested format passed its checks; 1 otherwise. Boxes are
# named min-test-* so they are easy to spot in `distrobox list` and to reap by
# hand after a --keep-boxes run.
set -euo pipefail

die() { printf 'pkg-smoke: error: %s\n' "$*" >&2; exit 1; }
note() { printf 'pkg-smoke: %s\n' "$*"; }

usage() { sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'; }

pkg_dir="dist"
formats="deb,rpm,apk"
apparmor=0
keep_boxes=0
while [ $# -gt 0 ]; do
    case "$1" in
        --pkg-dir)   [ $# -ge 2 ] || die "--pkg-dir needs a directory"
                     pkg_dir="$2"; shift 2 ;;
        --formats)   [ $# -ge 2 ] || die "--formats needs a value (e.g. deb,rpm)"
                     formats="$2"; shift 2 ;;
        --apparmor)  apparmor=1; shift ;;
        --keep-boxes) keep_boxes=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown argument: $1 (see --help)" ;;
    esac
done

command -v distrobox >/dev/null 2>&1 ||
    die "distrobox not found on PATH"

# Host arch → package arch. The aarch64 variants only install on an arm64 host;
# a cross smoke would need an arm64 box image, which distrobox cannot fake.
case "$(uname -m)" in
    x86_64)  pkg_arch=amd64; box_arch=x86_64 ;;
    aarch64) pkg_arch=arm64; box_arch=aarch64 ;;
    *)       die "unsupported host arch: $(uname -m) (need x86_64 or aarch64)" ;;
esac

pkg_dir="$(cd "$pkg_dir" 2>/dev/null && pwd)" ||
    die "no such package directory: $pkg_dir"

if [ "$apparmor" -eq 1 ]; then
    printf '%s' "$formats" | grep -q deb ||
        die "--apparmor needs the deb box; include deb in --formats"
fi

# Every requested format must have its artifact before any box is created, so
# a half-built dist/ fails fast instead of smoke-testing a subset. Filenames
# are minimal_<v>_<arch>.{deb,apk} and minimal-<v>.<arch>.rpm, with v carrying
# the packaging revision (0.5.3-1 deb/rpm, 0.5.3-r1 apk).
artifacts=()
fmts=()
for f in $(printf '%s' "$formats" | tr ',' ' '); do
    case "$f" in
        deb) glob="minimal_*_${pkg_arch}.deb" ;;
        rpm) glob="minimal-*.${box_arch}.rpm" ;;
        apk) glob="minimal_*_${box_arch}.apk" ;;
        *)   die "unknown format: $f (deb, rpm, apk)" ;;
    esac
    # shellcheck disable=SC2206  # the unquoted glob is the point
    matches=("$pkg_dir"/$glob)
    [ -f "${matches[0]}" ] ||
        die "no $f artifact in $pkg_dir (looked for $glob; built the packages yet?)"
    artifacts+=("${matches[0]}")
    fmts+=("$f")
done

versions_expected=()
for i in "${!artifacts[@]}"; do
    base="$(basename "${artifacts[$i]}")"
    case "${fmts[$i]}" in
        deb) base="${base#minimal_}";  base="${base%_"${pkg_arch}".deb}" ;;
        rpm) base="${base#minimal-}";  base="${base%."${box_arch}".rpm}" ;;
        apk) base="${base#minimal_}";  base="${base%_"${box_arch}".apk}" ;;
    esac
    versions_expected+=("$base")
done

declare -a boxes=() images=() installs=() uninstalls=() version_probes=()
for i in "${!fmts[@]}"; do
    case "${fmts[$i]}" in
        deb)
            boxes+=("min-test-deb")
            images+=("debian:latest")
            installs+=("sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y")
            uninstalls+=("sudo dpkg -r minimal")
            # The expected version string is checked against the manager's own
            # record. dpkg-query's default output is TAB-delimited
            # "<package>	<version>", so cut replaces a --showformat string
            # whose $ escaping has to survive distrobox argument forwarding.
            version_probes+=("dpkg-query -W minimal | cut -f2")
            ;;
        rpm)
            boxes+=("min-test-rpm")
            images+=("fedora:latest")
            installs+=("sudo dnf install -y")
            uninstalls+=("sudo dnf remove -y minimal")
            version_probes+=("rpm -q --qf '%{VERSION}-%{RELEASE}\\n' minimal")
            ;;
        apk)
            boxes+=("min-test-apk")
            images+=("alpine:latest")
            installs+=("sudo apk add --allow-untrusted")
            uninstalls+=("sudo apk del minimal")
            version_probes+=("apk list --installed 2>/dev/null | grep -F 'minimal-'")
            ;;
    esac
done

if [ "$keep_boxes" -eq 0 ]; then
    cleanup() {
        for name in "${created[@]:-}"; do
            [ -n "$name" ] || continue
            distrobox rm --force "$name" >/dev/null 2>&1 || true
        done
    }
else
    cleanup() { :; }
fi
declare -a created=()
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# box <index> <command...> — run a command inside the format's box.
box() {
    local i="$1"; shift
    distrobox enter --name "${boxes[$i]}" -- "$@"
}

# install_pkg <index> — run under the box's passwordless sudo (distrobox maps
# the host user, so the package-manager steps say sudo, not root). Package
# managers serialise on locks a freshly created box may still hold (the Debian
# image runs apt at init), so retry instead of failing a smoke on a race we do
# not care about.
install_pkg() {
    local i="$1" out rc=1 try
    out="$(mktemp)"
    for try in 1 2 3 4 5 6; do
        set +e
        # shellcheck disable=SC2086  # the install command wordsplit is intended
        box "$i" ${installs[$i]} "${artifacts[$i]}" >"$out" 2>&1
        rc=$?
        set -e
        if [ $rc -eq 0 ]; then break; fi
        grep -qi "could not get lock\|another process\|waiting for lock" "$out" ||
            break
        note "${boxes[$i]}: package manager lock held, retrying ($try/6)"
        sleep 10
    done
    if [ $rc -ne 0 ]; then
        sed 's/^/    /' "$out" >&2
        die "${boxes[$i]}: install failed"
    fi
    rm -f "$out"
}

# Every shipped path (packaging/nfpm.yaml's contents). Asserted per format —
# all three formats ship the same set. No single quotes: this runs via sh -c.
check_files() {
    cat <<'PROBE'
set -e
for f in \
    /usr/bin/min /usr/bin/minimald /usr/bin/mip /usr/bin/minvmd \
    /usr/bin/gvproxy-min /usr/bin/git-remote-min \
    /usr/share/bash-completion/completions/min \
    /usr/share/zsh/site-functions/_min \
    /usr/share/fish/vendor_completions.d/min.fish \
    /usr/share/minimal/apparmor/minimald \
    /usr/share/minimal/apparmor/tunables/minimald \
    /usr/share/minimal/apparmor/install-apparmor-profile.sh
do
    [ -e "$f" ] || { echo "missing: $f" >&2; exit 1; }
done
[ -L /usr/bin/git-remote-min ] || { echo "git-remote-min is not a symlink" >&2; exit 1; }
[ "$(readlink /usr/bin/git-remote-min)" = /usr/bin/min ] ||
    { echo "git-remote-min points at $(readlink /usr/bin/git-remote-min)" >&2; exit 1; }
PROBE
}

# The binaries must execute on the box's libc. gvproxy-min has no --version;
# anything that exits 0 on --version or --help counts as runnable.
check_binaries() {
    cat <<'PROBE'
set -e
got="$(/usr/bin/min --version)"
echo "$got" | grep -q "PROBE_VERSION" ||
    { echo "min --version reported '$got', wanted PROBE_VERSION" >&2; exit 1; }
for b in mip minimald minvmd gvproxy-min; do
    "/usr/bin/$b" --version >/dev/null 2>&1 || "/usr/bin/$b" --help >/dev/null 2>&1 ||
        { echo "$b does not run" >&2; exit 1; }
done
PROBE
}

failed=0
for i in "${!boxes[@]}"; do
    name="${boxes[$i]}"
    want="${versions_expected[$i]}"
    note "== $name: creating from ${images[$i]} =="
    # A box left by an interrupted earlier run would fail create; drop it first.
    distrobox rm --force "$name" >/dev/null 2>&1 || true
    distrobox create --name "$name" --image "${images[$i]}" --yes >/dev/null
    created+=("$name")

    note "== $name: installing $(basename "${artifacts[$i]}") =="
    install_pkg "$i"

    note "== $name: verifying version $want =="
    got="$(box "$i" sh -c "${version_probes[$i]}")"
    if ! printf '%s' "$got" | grep -qF -- "$want"; then
        note "$name: version mismatch: reported '$got', wanted $want"
        failed=1
        continue
    fi

    note "== $name: verifying shipped files =="
    if ! box "$i" sh -c "$(check_files)"; then
        note "$name: file check failed"
        failed=1
        continue
    fi

    note "== $name: verifying binaries run =="
    if ! box "$i" sh -c "$(check_binaries | sed "s/PROBE_VERSION/${want%%-*}/")"; then
        note "$name: binary check failed"
        failed=1
        continue
    fi

    if [ "$apparmor" -eq 1 ] && [ "$name" = min-test-deb ]; then
        note "== $name: apparmor installed; re-running the postinstall path =="
        box "$i" sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor >/dev/null
        box "$i" sudo env DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y \
            "${artifacts[$i]}" >/dev/null
        if ! box "$i" /usr/share/minimal/apparmor/install-apparmor-profile.sh --check; then
            note "$name: packaged profile does not parse"
            failed=1
            continue
        fi
    fi

    note "== $name: uninstall round-trip =="
    out="$(box "$i" sh -c "${uninstalls[$i]} && ! [ -e /usr/bin/min ]" 2>&1)" ||
        { printf '%s\n' "$out" | sed 's/^/    /' >&2
          note "$name: uninstall failed or left files behind"
          failed=1
          continue
        }
    note "== $name: PASS =="
done

if [ $failed -ne 0 ]; then
    die "smoke failed (see the notes above)"
fi
note "all requested formats passed: ${fmts[*]}"
