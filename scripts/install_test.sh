#!/bin/sh
#
# install_test.sh — POSIX-sh test harness for scripts/install.sh.
#
# Exercises Units 1–9 of docs/specs/07-spec-installer against a local mock
# bucket and a stubbed downloader, then asserts the spec's proof artifacts.
#
# The downloader is stubbed by prepending a temp dir to PATH containing a fake
# `curl` that maps `<BUCKET>/<path>` to `<mock>/<path>`, copies the file, and
# bumps a per-run download counter — so "zero downloads on rerun" is checkable
# without a network. The installer's own HTTPS/TLS wrapper flags are passed to
# the stub and ignored; real transport security is covered by the end-to-end
# run against the real bucket, not here.
#
# Usage:
#   scripts/install_test.sh             # runs every case, under `sh`
#   scripts/install_test.sh <case>      # runs the one named case
#   sh scripts/install_test.sh          # ditto
# CI additionally runs it under dash (and macOS /bin/sh where available).

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
installer="$here/install.sh"
[ -f "$installer" ] || { echo "cannot find install.sh next to test" >&2; exit 1; }

# The shell the installer-under-test runs in (default sh; CI overrides to dash).
SH="${SH:-sh}"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-installtest)"
trap 'rm -rf "$root"' EXIT

pass=0 fail=0
ok()   { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad()  { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }
check(){ if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (want [$1] got [$2])"; fi; }

# Assertion wrappers over a command: the message is first, the command follows.
# Written as an explicit if/else, not `cmd && ok || bad` (which shellcheck flags
# SC2015 and which silently runs `bad` if `ok` ever returned non-zero).
want_ok()  { _m="$1"; shift; if "$@"; then ok "$_m"; else bad "$_m"; fi; }
want_err() { _m="$1"; shift; if "$@"; then bad "$_m"; else ok "$_m"; fi; }

# want_card_last <message> — true when the run's parting block is the closing
# card (R10.4). Keyed on the card's last content line rather than on `tail -n 1`,
# because the card ends on a blank line for the shell prompt that follows.
want_card_last() {
    case "$(awk 'NF {l=$0} END {print l}' "$OUT")" in
        *docs.minimal.dev*) ok "$1" ;;
        *)                  bad "$1 (last line: $(awk 'NF {l=$0} END {print l}' "$OUT"))" ;;
    esac
}

# A literal ESC, for asserting that redirected output carries no SGR sequences.
esc="$(printf '\033')"

# record_has <component> <path> <record> — true when the install record holds a
# row pairing that component with that exact path (columns 1 and 2).
record_has() {
    awk -v c="$1" -v p="$2" '$1==c && $2==p {hit=1} END{exit !hit}' "$3"
}

# record_has_comp <component> <record> — true when the install record lists the
# named component at any path (used to assert every VM-stack part is recorded).
record_has_comp() {
    awk -v c="$1" '$1==c {hit=1} END{exit !hit}' "$2"
}

# manifest_has <component> <os> <arch> [manifest] — true when the release
# component table holds a row for that component/os/arch. The default manifest
# is the one the installer just fetched.
manifest_has() {
    _mh="${4:-$mock/versions/v1/components}"
    awk -v c="$1" -v o="$2" -v a="$3" \
        '!/^#/ && NF && $1==c && $2==o && $3==a {hit=1} END{exit !hit}' "$_mh"
}

# The harness computes expected hashes with whatever SHA-256 tool the host has.
# macOS ships `shasum`, not `sha256sum`, so pick portably (same order the
# installer under test uses) — otherwise the macOS lane fails in the harness
# rather than exercising the installer.
if command -v sha256sum >/dev/null 2>&1; then
    hash_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v openssl >/dev/null 2>&1; then
    hash_file() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
else
    echo "install_test: no SHA-256 tool available for the harness" >&2; exit 1
fi

# --- Mock bucket -----------------------------------------------------------

BUCKET_HOST="https://mock.invalid/minimal-one"
mock="$root/bucket"
mkdir -p "$mock/versions/v1"

# write_min_stub <path> [label] — the stand-in for the real binary at every
# point install.sh runs it: `completions install <shell>` (R9.3), `ls` and
# `stop` for the live-session prompt (R5.5). The completions arm implements the
# same contract the real command does — write the shell's file under its
# XDG-derived path, print that path on stdout, warn on stderr and still exit 0
# when the directory is not writable, drop a stale compinit dump for zsh —
# because the installer now delegates all of it and only reads the printed
# paths.
write_min_stub() {
    printf '#!/bin/sh\n# mock min (%s)\n' "${2:-previous release}" >"$1"
    cat >>"$1" <<'MOCKEOF'
comp_target() {
    case "$1" in
        bash) printf '%s/bash-completion/completions/min\n' "${XDG_DATA_HOME:-$HOME/.local/share}" ;;
        zsh)  printf '%s/zsh/completions/_min\n'            "${XDG_DATA_HOME:-$HOME/.local/share}" ;;
        fish) printf '%s/fish/completions/min.fish\n'       "${XDG_CONFIG_HOME:-$HOME/.config}" ;;
    esac
}
comp_install() {
    _t="$(comp_target "$1")"
    _d="${_t%/*}"
    if ! ( mkdir -p "$_d" && : >"$_t.tmp.$$" ) 2>/dev/null; then
        echo "warning: failed to install $1 completions ($_d is not writable)" >&2
        return 0
    fi
    printf '# mock min completions for %s\n' "$1" >"$_t.tmp.$$"
    mv -f "$_t.tmp.$$" "$_t"
    printf '%s\n' "$_t"
    if [ "$1" = zsh ]; then
        _dump="${ZDOTDIR:-$HOME}/.zcompdump"
        if [ -f "$_dump" ] && rm -f "$_dump" 2>/dev/null; then
            echo "cleared compinit dump cache $_dump" >&2
        fi
    fi
}
case "${1:-}" in
    completions)
        shift
        [ "${1:-}" = install ] || { echo "mock min: no such completions verb: ${1:-}" >&2; exit 2; }
        shift
        [ $# -gt 0 ] || set -- bash zsh fish
        for _s in "$@"; do comp_install "$_s"; done
        ;;
    ls)          printf 'session-alpha  running\n' ;;
    stop)
        printf '%s\n' "$*" >>"$HOME/stop.calls"
        if [ -f "$HOME/sessions.live" ] && [ "${2:-}" != "--force" ]; then
            echo "daemon has active sessions; pass --force to shut down anyway" >&2
            exit 1
        fi
        ;;
esac
MOCKEOF
    chmod +x "$1"
}

# Platform-diverse artifacts with padded columns and comment/blank lines, to
# prove awk field-splitting survives padding (R3.1/R3.3). The `minimal` CLI
# artifacts are runnable sh scripts that answer `completions install <shell>`,
# because the installer installs completions by executing the installed bin/min
# (R9.3); the other artifacts stay opaque bodies.
# Linux amd64 release artifacts, including the VM stack (NET-048).
printf 'linux-amd64-minimald-body\n'     >"$mock/versions/v1/minimald-linux-amd64"
write_min_stub "$mock/versions/v1/minimal-linux-amd64"  linux-amd64
# The answerer NET-122's advisory copies from beside min (NET-122).
printf 'linux-amd64-answerer-body\n'    >"$mock/versions/v1/minzoned-linux-amd64"
printf 'linux-amd64-minvmd-body\n'       >"$mock/versions/v1/minvmd-linux-amd64"
printf 'linux-amd64-initramfs-body\n'   >"$mock/versions/v1/initramfs-amd64.cpio"
printf 'linux-amd64-rootfs-body\n'      >"$mock/versions/v1/rootfs-amd64.img"
printf 'linux-amd64-vmlinuz-body\n'     >"$mock/versions/v1/vmlinuz-amd64"
# The switch binary the daemon spawns for own-IP sessions (NET-041); shipped
printf 'mock-gvproxy-switch-body\n'      >"$mock/versions/v1/gvproxy-min-linux-amd64"
# as bin/gvproxy-min so the installer has a row to verify.

# Linux arm64 release artifacts, including the VM stack (NET-050).
printf 'linux-arm64-minimald-body\n'    >"$mock/versions/v1/minimald-linux-arm64"
write_min_stub "$mock/versions/v1/minimal-linux-arm64" linux-arm64
printf 'linux-arm64-answerer-body\n'    >"$mock/versions/v1/minzoned-linux-arm64"
printf 'linux-arm64-minvmd-body\n'      >"$mock/versions/v1/minvmd-linux-arm64"
printf 'linux-arm64-initramfs-body\n'    >"$mock/versions/v1/initramfs-arm64.cpio"
printf 'linux-arm64-rootfs-body\n'       >"$mock/versions/v1/rootfs-arm64.img"
printf 'linux-arm64-vmlinuz-body\n'      >"$mock/versions/v1/vmlinuz-arm64"
printf 'mock-gvproxy-switch-arm64-body\n' >"$mock/versions/v1/gvproxy-min-linux-arm64"

# macOS arm64 guest payload (kept distinct from the linux arm64 rootfs so each
# architecture is exercised with its own artifact and hash).
write_min_stub "$mock/versions/v1/minimal-darwin-arm64" darwin-arm64
printf 'darwin-arm64-answerer-body\n'    >"$mock/versions/v1/minzoned-macos-arm64"
printf 'darwin-arm64-rootfs-body\n'      >"$mock/versions/v1/rootfs-darwin-arm64.img"

# AppArmor components: noarch text (the loader is a runnable stub here), shipped
# to Linux hosts under the data prefix (see stage-release.sh).
printf 'mock-apparmor-profile-body\n'  >"$mock/versions/v1/minimald.apparmor"
printf 'mock-apparmor-tunable-body\n'  >"$mock/versions/v1/minimald.apparmor-tunable"
printf '#!/bin/sh\n# mock apparmor loader\n' >"$mock/versions/v1/install-apparmor-profile.sh"

# Hashes for every artifact referenced by the component table below.
h_minimald="$(hash_file "$mock/versions/v1/minimald-linux-amd64")"
h_minimal="$(hash_file "$mock/versions/v1/minimal-linux-amd64")"
h_answerer="$(hash_file "$mock/versions/v1/minzoned-linux-amd64")"
h_minvmd="$(hash_file "$mock/versions/v1/minvmd-linux-amd64")"
h_initramfs="$(hash_file "$mock/versions/v1/initramfs-amd64.cpio")"
h_rootfs="$(hash_file "$mock/versions/v1/rootfs-amd64.img")"
h_vmlinuz="$(hash_file "$mock/versions/v1/vmlinuz-amd64")"
h_gvmin="$(hash_file "$mock/versions/v1/gvproxy-min-linux-amd64")"

h_minimald_arm="$(hash_file "$mock/versions/v1/minimald-linux-arm64")"
h_minimal_arm="$(hash_file "$mock/versions/v1/minimal-linux-arm64")"
h_answerer_arm="$(hash_file "$mock/versions/v1/minzoned-linux-arm64")"
h_minvmd_arm="$(hash_file "$mock/versions/v1/minvmd-linux-arm64")"
h_initramfs_arm="$(hash_file "$mock/versions/v1/initramfs-arm64.cpio")"
h_rootfs_arm="$(hash_file "$mock/versions/v1/rootfs-arm64.img")"
h_vmlinuz_arm="$(hash_file "$mock/versions/v1/vmlinuz-arm64")"
h_gvmin_arm="$(hash_file "$mock/versions/v1/gvproxy-min-linux-arm64")"

h_dmin="$(hash_file "$mock/versions/v1/minimal-darwin-arm64")"
h_danswerer="$(hash_file "$mock/versions/v1/minzoned-macos-arm64")"
h_drootfs="$(hash_file "$mock/versions/v1/rootfs-darwin-arm64.img")"

h_aaprof="$(hash_file "$mock/versions/v1/minimald.apparmor")"
h_aatun="$(hash_file "$mock/versions/v1/minimald.apparmor-tunable")"
h_aaload="$(hash_file "$mock/versions/v1/install-apparmor-profile.sh")"

printf 'v1\n' >"$mock/stable"

write_manifest() {
    fmt="${1:-1}"
    {
        printf '# format: %s\n' "$fmt"
        printf '# component   os      arch    version   sha256   kind   dest   src\n'
        printf '\n'
        # Linux amd64: full CLI, daemon, switch, and VM host stack (NET-048).
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimald linux amd64 v1 "$h_minimald" file bin/minimald versions/v1/minimald-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimal linux amd64 v1 "$h_minimal" file bin/min versions/v1/minimal-linux-amd64
        # The answerer installs beside min on every platform min ships for
        # (NET-122); the installed copy is only the advisory's copy source.
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minzoned linux amd64 v1 "$h_answerer" file bin/minzoned versions/v1/minzoned-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            gvproxy-min linux amd64 v1 "$h_gvmin" file bin/gvproxy-min versions/v1/gvproxy-min-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minvmd linux amd64 v1 "$h_minvmd" file bin/minvmd versions/v1/minvmd-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            initramfs linux amd64 v1 "$h_initramfs" file data/initramfs.cpio versions/v1/initramfs-amd64.cpio
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs linux amd64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-amd64.img
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            vmlinuz linux amd64 v1 "$h_vmlinuz" file data/vmlinuz versions/v1/vmlinuz-amd64
        # Linux arm64: the same VM host stack must ship for arm64 (NET-050).
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimald linux arm64 v1 "$h_minimald_arm" file bin/minimald versions/v1/minimald-linux-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimal linux arm64 v1 "$h_minimal_arm" file bin/min versions/v1/minimal-linux-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minzoned linux arm64 v1 "$h_answerer_arm" file bin/minzoned versions/v1/minzoned-linux-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            gvproxy-min linux arm64 v1 "$h_gvmin_arm" file bin/gvproxy-min versions/v1/gvproxy-min-linux-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minvmd linux arm64 v1 "$h_minvmd_arm" file bin/minvmd versions/v1/minvmd-linux-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            initramfs linux arm64 v1 "$h_initramfs_arm" file data/initramfs.cpio versions/v1/initramfs-arm64.cpio
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs linux arm64 v1 "$h_rootfs_arm" file data/rootfs.img versions/v1/rootfs-arm64.img
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            vmlinuz linux arm64 v1 "$h_vmlinuz_arm" file data/vmlinuz versions/v1/vmlinuz-arm64
        # macOS arm64: VM host stack is macOS-native, guest payload is arm64.
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimal darwin arm64 v1 "$h_dmin" file bin/min versions/v1/minimal-darwin-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minzoned darwin arm64 v1 "$h_danswerer" file bin/minzoned versions/v1/minzoned-macos-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs darwin arm64 v1 "$h_drootfs" file data/rootfs.img versions/v1/rootfs-darwin-arm64.img
        # AppArmor support files ship to every Linux arch.
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-profile linux amd64 v1 "$h_aaprof" file data/apparmor/minimald versions/v1/minimald.apparmor
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-profile linux arm64 v1 "$h_aaprof" file data/apparmor/minimald versions/v1/minimald.apparmor
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-tunable linux amd64 v1 "$h_aatun" file data/apparmor/tunables/minimald versions/v1/minimald.apparmor-tunable
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-tunable linux arm64 v1 "$h_aatun" file data/apparmor/tunables/minimald versions/v1/minimald.apparmor-tunable
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-installer linux amd64 v1 "$h_aaload" file data/apparmor/install-apparmor-profile.sh versions/v1/install-apparmor-profile.sh
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-installer linux arm64 v1 "$h_aaload" file data/apparmor/install-apparmor-profile.sh versions/v1/install-apparmor-profile.sh
        # Symlink rows (R5.6): sha256 is the `-` placeholder, src is the link
        # target relative to dest's directory.
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            git-remote-min linux amd64 v1 - symlink bin/git-remote-min min
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            git-remote-min linux arm64 v1 - symlink bin/git-remote-min min
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            git-remote-min darwin arm64 v1 - symlink bin/git-remote-min min
    } >"$mock/versions/v1/components"
}
write_manifest 1

# The pristine manifest every scenario that rewrites it restores from. Saved
# once, up front, so each case below is self-contained whether it runs alone
# or in the full sweep.
cp "$mock/versions/v1/components" "$root/good-components"

# --- Stubbed downloader (fake curl on PATH) --------------------------------

stubbin="$root/stubbin"
mkdir -p "$stubbin"
dlcount="$root/dlcount"
: >"$dlcount"

cat >"$stubbin/curl" <<STUB
#!/bin/sh
# Fake curl: find the -o OUT and the URL among the installer's flags, map the
# URL to the mock bucket, copy, and count the download.
out= url=
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    https://*|http://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "\$url" ] || { echo "stub curl: no url" >&2; exit 2; }
rel="\${url#$BUCKET_HOST/}"
src="$mock/\$rel"
[ -f "\$src" ] || { echo "stub curl: 404 \$url" >&2; exit 22; }
# Count artifact fetches only, not the pointer or the manifest, so "zero
# downloads on rerun" means "no component re-downloaded" (spec R5.1).
case "\$rel" in
  versions/*/components) : ;;
  versions/*)            printf 'x\n' >>"$dlcount" ;;
esac
if [ -n "\$out" ]; then cp "\$src" "\$out"; else cat "\$src"; fi
STUB
chmod +x "$stubbin/curl"
# Force the wget path off so selection is deterministic across hosts.
cat >"$stubbin/wget" <<'STUB'
#!/bin/sh
echo "stub wget should not be used in tests" >&2
exit 1
STUB
chmod +x "$stubbin/wget"

# Stub `uname` so the host platform the installer sees is fixed by the STUB_UNAME
# env, not the CI runner — the same assertions then hold under Linux and macOS,
# and the darwin-only code path (below) is exercised on every lane.
cat >"$stubbin/uname" <<'STUB'
#!/bin/sh
case "$1" in
  -m) printf '%s\n' "${STUB_UNAME_M:-x86_64}" ;;
  *)  printf '%s\n' "${STUB_UNAME_S:-Linux}" ;;
esac
STUB
chmod +x "$stubbin/uname"

# Stub `xattr`: record the invocation; exit 0 (the installer swallows failure).
cat >"$stubbin/xattr" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$root/xattr.calls"
STUB
chmod +x "$stubbin/xattr"

downloads() { wc -l <"$dlcount" | tr -d ' '; }
reset_dl()  { : >"$dlcount"; }

# --- Run helper ------------------------------------------------------------

# Host platform the installer sees, via the uname stub. Default to linux/amd64;
# the darwin scenario flips these around its run and restores them after.
PLAT_S=Linux
PLAT_M=x86_64

# The login shell the installer sees ($SHELL drives the rc-hook branch, R9.2).
# Scenarios set TEST_SHELL around their runs; empty means /bin/sh (the
# unknown-shell fallback branch).
TEST_SHELL=

# Host userns state the installer sees. Empty leaves both overrides pointing at
# nonexistent paths (a host without the restriction and without a system
# profile), so the AppArmor advisory/prompt stays silent; scenarios point these
# at fixtures to drive it. USERNS_SYSCTL is a file whose contents are the sysctl
# value; APPARMOR_DIR stands in for /etc/apparmor.d.
USERNS_SYSCTL=
APPARMOR_DIR=

# Root the installer looks under for the host paths `min finalize-install` installs.
# Empty points it at a nonexistent directory, so this host's own setup never
# leaks into a scenario; scenarios seed a fake root to drive the offer.
FINALIZE_INSTALL_ROOT=

# Bin prefix the installer sees. Empty means the harness default ($hp/bin — a
# custom MINIMAL_BIN, NOT one of the AppArmor tunable's stock attachment
# paths); scenarios set it to $hp/.local/bin to exercise the default-prefix
# branch of the userns advisory.
BIN_OVERRIDE=

# Stand-in for /dev/tty, where the active-sessions prompt reads its answer
# (R5.5). Empty points the installer at a path that cannot be opened — the
# harness's own terminal must never be read, and every scenario that does not
# stage an answer must behave like a non-interactive run. Scenarios point it at
# a file holding the keystroke. FORCE_STOP fills MINIMAL_INSTALL_FORCE_STOP.
TTY_FILE=
FORCE_STOP=

# run <label> <homeprefix> [args...] ; sets rc, captures combined output in $OUT.
OUT=
run() {
    label="$1"; hp="$2"; shift 2
    OUT="$root/out.$label"
    set +e
    env -i \
        PATH="$stubbin:/usr/bin:/bin" \
        TERM=xterm-256color \
        HOME="$hp" \
        SHELL="${TEST_SHELL:-/bin/sh}" \
        MINIMAL_BIN="${BIN_OVERRIDE:-$hp/bin}" \
        XDG_DATA_HOME="$hp/xdg-data" \
        XDG_STATE_HOME="$hp/xdg-state" \
        XDG_CACHE_HOME="$hp/xdg-cache" \
        XDG_CONFIG_HOME="$hp/xdg-config" \
        MINIMAL_OVERRIDE_INSTALLER_BUCKET="$BUCKET_HOST" \
        STUB_UNAME_S="$PLAT_S" \
        STUB_UNAME_M="$PLAT_M" \
        MINIMAL_OVERRIDE_USERNS_SYSCTL="${USERNS_SYSCTL:-$root/no-such-sysctl}" \
        MINIMAL_OVERRIDE_APPARMOR_DIR="${APPARMOR_DIR:-$root/no-such-apparmor.d}" \
        MINIMAL_OVERRIDE_FINALIZE_INSTALL_ROOT="${FINALIZE_INSTALL_ROOT:-$root/no-such-finalize-install-root}" \
        MINIMAL_OVERRIDE_TTY="${TTY_FILE:-$root/no-such-tty}" \
        MINIMAL_INSTALL_FORCE_STOP="${FORCE_STOP:-}" \
        "$SH" "$installer" "$@" </dev/null >"$OUT" 2>&1
    rc=$?
    set -e
}

# ===========================================================================
echo "# install.sh tests (SH=$SH)"

case_install() {
    # --- Unit 5: install, skip-on-rerun (R5.1), atomic + exec (R5.4) -----------
    H1="$root/h1"; mkdir -p "$H1"
    reset_dl
    run first "$H1"
    check 0 "$rc" "fresh install exits 0"
    want_ok "minimald installed to bin" test -f "$H1/bin/minimald"
    want_ok "bin component is executable (R5.4)" test -x "$H1/bin/minimald"
    check "$h_minimald" "$(hash_file "$H1/bin/minimald")" "installed content matches manifest hash"
    # Only linux/amd64 rows apply on this host: darwin row must not be installed.
    want_err "darwin-only component skipped on linux host" test -e "$H1/data/rootfs.img"
    n1="$(downloads)"; want_ok "first run downloaded ($n1)" test "$n1" -gt 0
    want_ok "symlink component placed as a symlink (R5.6)" test -L "$H1/bin/git-remote-min"
    check "min" "$(readlink "$H1/bin/git-remote-min")" "symlink points at its manifest target (R5.6)"

    # A successful run closes on the card, after every bookkeeping note (here the
    # PATH advisory fires), so the parting block is what the user is left looking
    # at (R10.4).
    want_ok "fresh install emits the closing card (R10.4)" \
        grep -qE "Minimal .+ is ready" "$OUT"
    want_ok "the card names the first command (R10.4)" \
        grep -qE "min +build the sandbox and step inside" "$OUT"
    want_card_last "the card closes a fresh install (R10.4)"
    # Nothing on a redirected stream may carry terminal escapes (R10.1): this
    # output is a file, so a stray SGR here would land in every CI log. `run` sets a
    # terminal-like TERM, so what this pins is the `[ -t 2 ]` half of the guard:
    # with TERM unset the assertion would still pass if that check were dropped.
    want_err "no terminal escapes when stderr is not a terminal (R10.1)" \
        grep -q "$esc" "$OUT"

    reset_dl
    run second "$H1"
    check 0 "$rc" "rerun exits 0"
    check 0 "$(downloads)" "rerun performs zero downloads (R5.1/R2 reruns cheap)"
    want_card_last "the card closes an up-to-date rerun (R10.4)"


    # Corrupt one on-disk binary and retarget the symlink -> only the binary
    # re-fetches (a symlink repair needs no download), and both are restored.
    printf 'tampered\n' >"$H1/bin/minimald"
    rm -f "$H1/bin/git-remote-min"; ln -s minimald "$H1/bin/git-remote-min"
    reset_dl
    run third "$H1"
    check 0 "$rc" "rerun after tamper exits 0"
    check 1 "$(downloads)" "only the changed component re-downloads"
    check "$h_minimald" "$(hash_file "$H1/bin/minimald")" "tampered binary restored"
    check "min" "$(readlink "$H1/bin/git-remote-min")" "retargeted symlink repaired without a download (R5.6)"
}

case_apparmor() {
    # --- AppArmor components + Ubuntu 24.04+ advisory --------------------------
    # The components and the advisory both assert over a home holding a completed
    # install, so this case seeds its own instead of inheriting another case's.
    H_A="$root/ha"; mkdir -p "$H_A"
    run aa_seed "$H_A"
    check 0 "$rc" "apparmor seed install exits 0"
    # The three noarch apparmor components install under the data prefix on Linux.
    aa_root="$H_A/xdg-data/minimal/apparmor"
    want_ok "apparmor profile installed under data prefix"  test -f "$aa_root/minimald"
    want_ok "apparmor tunable installed under data prefix"  test -f "$aa_root/tunables/minimald"
    want_ok "apparmor loader installed under data prefix"   test -f "$aa_root/install-apparmor-profile.sh"

    # The advisory fires only when the userns restriction is active (sysctl reads 1),
    # points at the shipped loader, and never elevates — install still exits 0.
    printf '1\n' >"$root/sysctl-on"
    printf '0\n' >"$root/sysctl-off"

    USERNS_SYSCTL="$root/sysctl-on"
    run aa_restricted "$H_A"
    USERNS_SYSCTL=
    check 0 "$rc" "install on a restricted host still exits 0 (advice only)"
    want_ok "advisory names the userns restriction" \
        grep -q "restricts unprivileged user namespaces" "$OUT"
    want_ok "advisory points at the shipped loader with sudo bash" \
        grep -q "sudo bash .*apparmor/install-apparmor-profile.sh" "$OUT"
    # The harness bindir is a custom MINIMAL_BIN, outside the tunable's stock
    # attachment set, so the advised command must attach it explicitly.
    want_ok "advisory carries --path for a custom MINIMAL_BIN" \
        grep -q -- "--path \"$H_A/bin/minimald\"" "$OUT"
    # The card is the parting block even when the AppArmor advisory is the last note.
    want_card_last "the card follows the AppArmor advisory (R10.4)"

    USERNS_SYSCTL="$root/sysctl-off"
    run aa_unrestricted "$H_A"
    USERNS_SYSCTL=
    want_err "no advisory when the restriction is off (sysctl 0)" \
        grep -q "restricts unprivileged user namespaces" "$OUT"

    # A loaded system profile alone is NOT remediation for a custom MINIMAL_BIN:
    # the stock tunable does not attach it, so sessions still die and the advisory
    # must keep firing (with --path) until the tunables name this binary.
    mkdir -p "$root/aa-present"; printf 'profile\n' >"$root/aa-present/minimald"
    USERNS_SYSCTL="$root/sysctl-on"; APPARMOR_DIR="$root/aa-present"
    run aa_present_unattached "$H_A"
    want_ok "advisory still fires when the profile is loaded but MINIMAL_BIN unattached" \
        grep -q -- "--path \"$H_A/bin/minimald\"" "$OUT"

    # ...and is suppressed once the tunables do name it (what the loader's --path
    # records under tunables/minimald.d).
    mkdir -p "$root/aa-present/tunables/minimald.d"
    printf '@{minimald_bin} += %s/bin/minimald\n' "$H_A" \
        >"$root/aa-present/tunables/minimald.d/paths"
    run aa_attached "$H_A"
    want_err "no advisory when the tunables attach this MINIMAL_BIN" \
        grep -q "restricts unprivileged user namespaces" "$OUT"

    # For the stock prefix (~/.local/bin) the profile's own tunable already
    # attaches the binary, so the profile file existing IS remediation.
    BIN_OVERRIDE="$H_A/.local/bin"
    run aa_already_default_bin "$H_A"
    BIN_OVERRIDE=
    want_err "no advisory for the default prefix when the system profile is installed" \
        grep -q "restricts unprivileged user namespaces" "$OUT"
    USERNS_SYSCTL=; APPARMOR_DIR=

    # Darwin hosts never receive the apparmor components (linux-only manifest rows).
    HAA_D="$root/haa_d"; mkdir -p "$HAA_D"
    PLAT_S=Darwin; PLAT_M=arm64
    run aa_darwin "$HAA_D"
    PLAT_S=Linux; PLAT_M=x86_64
    check 0 "$rc" "darwin install exits 0"
    want_err "apparmor components skipped on darwin" \
        test -e "$HAA_D/xdg-data/minimal/apparmor/minimald"

}

case_apparmor_uninstall() {
    # --- Uninstall: offer to remove the system AppArmor profile ----------------
    # A non-interactive uninstall (stdin is /dev/null, not a tty) advises the root
    # removal command and never elevates: the seeded system profile survives, while
    # the shipped loader is removed by the record walk like any other component.
    # Without the step's record the profile is not `min finalize-install`'s, so
    # the advisory does not point at `--undo`.
    HAA_U="$root/haa_u"; mkdir -p "$HAA_U"
    run aa_u_seed "$HAA_U"
    check 0 "$rc" "uninstall-apparmor seed install exits 0"
    fake_aa="$root/fake-apparmor.d"; mkdir -p "$fake_aa/tunables"
    printf 'profile\n' >"$fake_aa/minimald"
    printf 'tunable\n' >"$fake_aa/tunables/minimald"
    APPARMOR_DIR="$fake_aa"
    run aa_u_run "$HAA_U" --uninstall
    APPARMOR_DIR=
    check 0 "$rc" "uninstall with a loaded system profile exits 0"
    want_ok "uninstall advises the system profile is still installed" \
        grep -q "still installed on this host.*system AppArmor profile" "$OUT"
    want_ok "advisory gives the root removal command" grep -q "apparmor_parser -R" "$OUT"
    want_err "an unrecorded profile is not offered to min finalize-install --undo" \
        grep -q "min finalize-install --undo" "$OUT"
    want_ok "non-interactive uninstall never elevates (profile survives)" \
        test -f "$fake_aa/minimald"
    want_err "uninstall removed the shipped apparmor loader" \
        test -e "$HAA_U/xdg-data/minimal/apparmor/install-apparmor-profile.sh"
}

case_finalize_install_uninstall() {
    # --- Uninstall: advise removing what min finalize-install installed ----------
    # A non-interactive uninstall on a host where `min finalize-install` ran advises
    # `min finalize-install --undo` and the root commands that stay valid once `min` is
    # gone, and never elevates: the seeded host files survive. Every artifact the
    # step owns is detected on its own, and everything found shares one advisory.
    # A host that never ran the step sees nothing.
    HNS="$root/hns"; mkdir -p "$HNS"
    run ns_seed "$HNS"
    check 0 "$rc" "uninstall-net-setup seed install exits 0"
    fake_ns="$root/fake-net-setup-root"
    case "$PLAT_S" in
        Darwin) ns_file="$fake_ns/etc/resolver/min.internal" ;;
        *)      ns_file="$fake_ns/etc/systemd/system/minzoned.service" ;;
    esac
    mkdir -p "$(dirname "$ns_file")"
    printf 'unit\n' >"$ns_file"
    FINALIZE_INSTALL_ROOT="$fake_ns"
    run ns_run "$HNS" --uninstall
    FINALIZE_INSTALL_ROOT=
    check 0 "$rc" "uninstall with the host DNS setup present exits 0"
    want_ok "uninstall advises the host DNS setup is still installed" \
        grep -q "still installed on this host.*host DNS setup" "$OUT"
    want_ok "advisory names min finalize-install --undo" grep -q "min finalize-install --undo" "$OUT"
    want_ok "advisory gives the root removal commands" grep -q "sudo " "$OUT"
    want_ok "non-interactive uninstall never elevates (host file survives)" \
        test -f "$ns_file"

    HNS2="$root/hns2"; mkdir -p "$HNS2"
    run ns2_seed "$HNS2"
    run ns2_run "$HNS2" --uninstall
    check 0 "$rc" "uninstall on a host without the setup exits 0"
    want_err "a host that never ran min finalize-install sees no advisory" \
        grep -q "min finalize-install" "$OUT"

    # The Linux-only items, each detected by what the step leaves for `--undo`.
    [ "$PLAT_S" = Linux ] || return 0

    # The user-namespace profile with the step's record: offered to --undo, with
    # the record in the manual remedy.
    HNS3="$root/hns3"; mkdir -p "$HNS3"
    run ns3_seed "$HNS3"
    fake_aa3="$root/fake-apparmor.d-3"; mkdir -p "$fake_aa3/tunables"
    printf 'profile\n' >"$fake_aa3/minimald"
    fake_ns3="$root/fake-net-setup-root-3"
    mkdir -p "$fake_ns3/var/lib/minimal"
    : >"$fake_ns3/var/lib/minimal/finalize-install-apparmor-profile"
    APPARMOR_DIR="$fake_aa3"; FINALIZE_INSTALL_ROOT="$fake_ns3"
    run ns3_run "$HNS3" --uninstall
    APPARMOR_DIR=; FINALIZE_INSTALL_ROOT=
    check 0 "$rc" "uninstall with a recorded profile exits 0"
    want_ok "a recorded profile is advised as min finalize-install's" \
        grep -q "still installed on this host.*user-namespace profile" "$OUT"
    want_ok "a recorded profile points at min finalize-install --undo" \
        grep -q "min finalize-install --undo" "$OUT"
    want_ok "the remedy removes the profile and its record" \
        grep -q "apparmor_parser -R.*finalize-install-apparmor-profile" "$OUT"
    want_ok "the recorded profile survives a non-interactive uninstall" \
        test -f "$fake_aa3/minimald"

    # The classifier tree, by its marker.
    HNS4="$root/hns4"; mkdir -p "$HNS4"
    run ns4_seed "$HNS4"
    fake_ns4="$root/fake-net-setup-root-4"
    mkdir -p "$fake_ns4/sys/fs/cgroup/minimald.slice/classifier-table"
    FINALIZE_INSTALL_ROOT="$fake_ns4"
    run ns4_run "$HNS4" --uninstall
    FINALIZE_INSTALL_ROOT=
    check 0 "$rc" "uninstall with the classifier tree exits 0"
    want_ok "the classifier tree is advised" \
        grep -q "still installed on this host.*classifier tree" "$OUT"
    want_ok "the remedy removes the classifier table" \
        grep -q "nft delete table inet minimal_class" "$OUT"
    # The tree's removal is rooted under the same root its detection reads, so
    # the advisory a developer runs (or a later test executes) targets the
    # seeded tree, never the host's real one.
    want_ok "the remedy removes the tree under the root it was detected in" \
        grep -qF "sudo find \"$fake_ns4/sys/fs/cgroup/minimald.slice\"" "$OUT"

    # The kvm group membership, by its record.
    HNS5="$root/hns5"; mkdir -p "$HNS5"
    run ns5_seed "$HNS5"
    fake_ns5="$root/fake-net-setup-root-5"
    mkdir -p "$fake_ns5/var/lib/minimal"
    printf 'alice\n' >"$fake_ns5/var/lib/minimal/finalize-install-kvm-group"
    FINALIZE_INSTALL_ROOT="$fake_ns5"
    run ns5_run "$HNS5" --uninstall
    FINALIZE_INSTALL_ROOT=
    check 0 "$rc" "uninstall with the kvm record exits 0"
    want_ok "the kvm membership is advised" \
        grep -q "still installed on this host.*kvm group membership" "$OUT"
    want_ok "the remedy takes the membership back by the record" \
        grep -q "gpasswd -d" "$OUT"

    # Everything at once, an unrecorded profile included: one advisory, one list.
    HNS6="$root/hns6"; mkdir -p "$HNS6"
    run ns6_seed "$HNS6"
    fake_aa6="$root/fake-apparmor.d-6"; mkdir -p "$fake_aa6/tunables"
    printf 'profile\n' >"$fake_aa6/minimald"
    fake_ns6="$root/fake-net-setup-root-6"
    mkdir -p "$fake_ns6/etc/systemd/system" "$fake_ns6/var/lib/minimal" \
        "$fake_ns6/sys/fs/cgroup/minimald.slice/classifier-table"
    printf 'unit\n' >"$fake_ns6/etc/systemd/system/minzoned.service"
    printf 'alice\n' >"$fake_ns6/var/lib/minimal/finalize-install-kvm-group"
    APPARMOR_DIR="$fake_aa6"; FINALIZE_INSTALL_ROOT="$fake_ns6"
    run ns6_run "$HNS6" --uninstall
    APPARMOR_DIR=; FINALIZE_INSTALL_ROOT=
    check 0 "$rc" "uninstall with every artifact exits 0"
    check 1 "$(grep -c "still installed on this host" "$OUT")" "one advisory covers everything found"
    for item in "host DNS setup" "system AppArmor profile" "classifier tree" "kvm group membership"; do
        want_ok "the one advisory lists: $item" grep -q "still installed on this host.*$item" "$OUT"
    done
    for cmd in "systemctl disable --now minzoned" "apparmor_parser -R" "nft delete table" "gpasswd -d"; do
        want_ok "the remedy covers: $cmd" grep -q "$cmd" "$OUT"
    done
}

case_checksum_mismatch() {
    # --- Unit 5: checksum mismatch (R5.3) --------------------------------------
    # Point the manifest's minimal hash at a wrong value; artifact stays as-is.
    awk '$1=="minimal" && $2=="linux" {$5="deadbeef"} {print}' "$root/good-components" \
        >"$mock/versions/v1/components"
    H2="$root/h2"; mkdir -p "$H2"
    reset_dl
    run mismatch "$H2"
    check 1 "$rc" "checksum mismatch exits non-zero (R5.3)"
    want_ok "mismatch names the failure" grep -q "checksum mismatch" "$OUT"
    want_err "no closing card on a failed install (R10.4)" \
        grep -qE "Minimal .+ is ready" "$OUT"
    want_err "no file installed on mismatch" test -e "$H2/bin/min"
    if ls "$H2/bin/"min.tmp.* >/dev/null 2>&1
    then bad "temp file left behind"; else ok "no .tmp file left (R5.3)"; fi
    cp "$root/good-components" "$mock/versions/v1/components"   # restore
}

case_target_validation() {
    # --- Unit 2: target / version / format validation --------------------------
    H3="$root/h3"; mkdir -p "$H3"
    reset_dl
    run traversal "$H3" "../evil"
    check 1 "$rc" "path-like target exits non-zero (R2.1)"
    check 0 "$(downloads)" "invalid target fetches nothing (R2.1)"

    run emptytarget "$H3" ""
    check 1 "$rc" "empty target exits non-zero (R2.1)"

    # Dot-segment targets pass the charset but would let curl normalize the URL past
    # the bucket prefix; reject them outright, before any fetch.
    for dot in . ..; do
        reset_dl
        run "dottarget" "$H3" "$dot"
        check 1 "$rc" "dot-segment target '$dot' exits non-zero (R2.1)"
        check 0 "$(downloads)" "dot-segment target '$dot' fetches nothing"
    done

    # A compromised pointer resolving to a dot-segment version must also be rejected
    # (before the manifest fetch), not just the char whitelist.
    printf '..\n' >"$mock/dotversion"
    run dotversion "$H3" dotversion
    check 1 "$rc" "dot-segment version from pointer exits non-zero (R2.2)"

    write_manifest 999
    run badformat "$H3"
    check 1 "$rc" "unsupported manifest format exits non-zero (R2.4)"
    want_ok "format error names supported version (R2.4)" grep -q "supports 1" "$OUT"
    write_manifest 1

    # --version names the version directly: no pointer is fetched, so it installs
    # with the pointer file gone (R2.5).
    mv "$mock/stable" "$root/stable.saved"
    HV="$root/hv"; mkdir -p "$HV"
    run version "$HV" --version v1
    check 0 "$rc" "--version installs without a pointer (R2.5)"
    check "$h_minimald" "$(hash_file "$HV/bin/minimald")" "--version installs that version's bytes (R2.5)"
    want_ok "--version names the version, not a target (R2.5)" grep -q "version.*v1" "$OUT"
    HV2="$root/hv2"; mkdir -p "$HV2"
    run versioneq "$HV2" --force-stop --version=v1
    check 0 "$rc" "--version=VER with another flag installs (R2.5)"
    mv "$root/stable.saved" "$mock/stable"

    reset_dl
    run versiondot "$HV" --version ..
    check 1 "$rc" "dot-segment --version exits non-zero (R2.5)"
    check 0 "$(downloads)" "dot-segment --version fetches nothing (R2.5)"
    run versionbad "$HV" --version 'a/b'
    check 1 "$rc" "--version outside the charset exits non-zero (R2.5)"
    run versionnone "$HV" --version
    check 1 "$rc" "--version without a value exits non-zero (R2.5)"
    run versionflag "$HV" --version --force-stop
    check 1 "$rc" "--version followed by a flag exits non-zero (R2.5)"
    want_ok "a flag is not taken as the version (R2.5)" grep -q "needs a value" "$OUT"
    run versioneqnone "$HV" --version=
    check 1 "$rc" "--version= without a value exits non-zero (R2.5)"
    want_ok "an empty --version= needs a value (R2.5)" grep -q "needs a value" "$OUT"
    run versioneqflag "$HV" --version=--force-stop
    check 1 "$rc" "--version=-FLAG exits non-zero (R2.5)"
    want_ok "a flag is not taken as the --version= value (R2.5)" grep -q "needs a value" "$OUT"
    run versionboth "$HV" unstable --version v1
    check 1 "$rc" "a target plus --version exits non-zero (R2.5)"
    want_ok "the conflict is named (R2.5)" grep -q "not both" "$OUT"
    run versionmissing "$HV" --version v9
    check 1 "$rc" "--version with no staged manifest exits non-zero (R2.5)"
}

case_prefix_resolution() {
    # --- Unit 4: prefix resolution + traversal rejection (R4.1/R4.2) -----------
    # A dest with a `..` component must be rejected, writing nothing.
    awk '$1=="minimal" && $2=="linux" {$7="bin/../../etc/x"} {print}' "$root/good-components" \
        >"$mock/versions/v1/components"
    H4="$root/h4"; mkdir -p "$H4"
    run unsafedest "$H4"
    check 1 "$rc" "unsafe .. dest exits non-zero (R4.2)"
    want_err "traversal wrote nothing (R4.2)" test -e "$H4/etc/x"
    # Absolute subpath likewise.
    awk '$1=="minimal" && $2=="linux" {$7="bin//etc/x"} {print}' "$root/good-components" \
        >"$mock/versions/v1/components"
    run absdest "$H4"
    check 1 "$rc" "absolute dest subpath exits non-zero (R4.2)"
    cp "$root/good-components" "$mock/versions/v1/components"

    # XDG_DATA_HOME steers the `data` prefix (R4.1): a one-off manifest with a
    # single data-prefixed row that applies to this host, asserting where it lands.
    {
        printf '# format: 1\n'
        printf '# c o a v s k d s\n'
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs linux amd64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-amd64.img
    } >"$mock/versions/v1/components"
    H5="$root/h5"; mkdir -p "$H5"
    run datadest "$H5"
    check 0 "$rc" "data-prefixed component installs (R4.1)"
    want_ok "data resolves under XDG_DATA_HOME/minimal (R4.1)" \
        test -f "$H5/xdg-data/minimal/rootfs.img"
    cp "$root/good-components" "$mock/versions/v1/components"

    # The `lib` prefix (R4.1) is a bin SIBLING: it resolves to ~/.local/lib with NO
    # `/minimal` suffix (unlike data/state/cache), so a bin/<x> binary reaches a
    # shipped lib/<y> via a `@loader_path/../lib` rpath. XDG_LIB_HOME is unset in the
    # run env, so it must fall back to $HOME/.local/lib. A lib file is also not `bin`,
    # so it must NOT be marked executable.
    {
        printf '# format: 1\n'
        printf '# c o a v s k d s\n'
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            libkrun linux amd64 v1 "$h_rootfs" file lib/libkrun.1.dylib versions/v1/rootfs-amd64.img
    } >"$mock/versions/v1/components"
    H6="$root/h6"; mkdir -p "$H6"
    run libdest "$H6"
    check 0 "$rc" "lib-prefixed component installs (R4.1)"
    want_ok "lib falls back to HOME/.local/lib, no /minimal suffix (R4.1)" \
        test -f "$H6/.local/lib/libkrun.1.dylib"
    want_err "lib component is not marked executable (only bin gets +x)" \
        test -x "$H6/.local/lib/libkrun.1.dylib"
    cp "$root/good-components" "$mock/versions/v1/components"

    # A manifest without the min CLI (data-only) skips completions, non-fatally.
    want_ok "completions skipped when min absent (R9.3)" \
        grep -qE "completions +skipped" "$root/out.datadest"
}

case_install_record() {
    # --- Unit 6: install record (R6.1) + PATH advisory (R6.2) ------------------
    # Reads the record a completed install wrote, so this case seeds its own home
    # rather than inheriting another case's.
    H_IR="$root/hir"; mkdir -p "$H_IR"
    run record_seed "$H_IR"
    check 0 "$rc" "record seed install exits 0"
    record="$H_IR/xdg-state/minimal/installed"
    want_ok "install record lists components (R6.1)" grep -q "minimald" "$record"
    want_ok "install record lists resolved dest (R6.1)" grep -q "$H_IR/bin/minimald" "$record"
    want_ok "install record lists hash (R6.1)" grep -q "$h_minimald" "$record"
    want_ok "symlink row records link:<target> in the hash columns (R6.1)" \
        grep -q "link:min" "$record"

    # bin not on PATH -> advisory printed.
    run advise_off "$H_IR"
    want_ok "PATH advisory printed when bin absent (R6.2)" grep -q "is not on your PATH" "$OUT"
    # bin on PATH -> advisory suppressed. Re-run with bin on PATH via a wrapper env.
    OUT="$root/out.advise_on"
    set +e
    env -i PATH="$stubbin:$H_IR/bin:/usr/bin:/bin" HOME="$H_IR" MINIMAL_BIN="$H_IR/bin" \
        XDG_STATE_HOME="$H_IR/xdg-state" XDG_DATA_HOME="$H_IR/xdg-data" XDG_CACHE_HOME="$H_IR/xdg-cache" \
        MINIMAL_OVERRIDE_INSTALLER_BUCKET="$BUCKET_HOST" \
        STUB_UNAME_S="$PLAT_S" STUB_UNAME_M="$PLAT_M" \
        "$SH" "$installer" >"$OUT" 2>&1
    set -e
    want_err "PATH advisory suppressed when bin present (R6.2)" grep -q "is not on your PATH" "$OUT"
}

case_daemon_stop() {
    # --- Unit 5: pre-upgrade daemon stop (R5.5) --------------------------------
    # The installed `min` (the mock records its `stop` calls to $HOME/stop.calls) is
    # run once, only on a run that actually replaces a file, and only when it was
    # already on disk beforehand.

    # Seed <home> with a completed install, then stage the next run as an upgrade
    # (one stale component) whose on-disk `min` reports live sessions.
    stage_live_upgrade() {
        run "$2_seed" "$1"
        check 0 "$rc" "$2: seed install exits 0"
        printf 'stale\n' >"$1/bin/minimald"
        write_min_stub "$1/bin/min"
        : >"$1/sessions.live"
        rm -f "$1/stop.calls"
    }

    H8="$root/h8"; mkdir -p "$H8"
    run daemonfresh "$H8"
    check 0 "$rc" "fresh install exits 0"
    want_err "fresh install stops no daemon: none installed yet (R5.5)" test -e "$H8/stop.calls"

    # Everything up to date -> nothing replaced -> a healthy daemon is left alone.
    run daemonnoop "$H8"
    check 0 "$rc" "up-to-date rerun exits 0"
    want_err "up-to-date rerun stops no daemon (R5.5)" test -e "$H8/stop.calls"

    # An upgrade (two components stale) stops the daemon exactly once, before the
    # swap, via the min that is on disk now — an older build than the manifest's,
    # still runnable, still able to reach the daemon it started. With no sessions
    # running the graceful stop succeeds, so nothing is forced and nothing is asked.
    printf 'stale\n' >"$H8/bin/minimald"
    write_min_stub "$H8/bin/min" "previous release"
    run daemonupgrade "$H8"
    check 0 "$rc" "upgrade exits 0"
    want_ok "upgrade runs min stop (R5.5)" test -f "$H8/stop.calls"
    check "stop" "$(cat "$H8/stop.calls")" "stop is called once, gracefully (R5.5)"
    want_err "a graceful stop is never escalated to --force (R5.5)" \
        grep -qx "stop --force" "$H8/stop.calls"
    want_err "no sessions means no question (R5.5)" grep -q "Continue?" "$OUT"

    # Replacing only a data component must NOT stop the daemon: data files (the
    # apparmor profile/tunable/loader) are not executable images, and the running
    # daemon does not serve from them — only bin/lib swaps wedge it (R5.5).
    rm -f "$H8/stop.calls"
    printf 'tampered\n' >"$H8/xdg-data/minimal/apparmor/minimald"
    run daemondataonly "$H8"
    check 0 "$rc" "data-only rerun exits 0"
    want_err "data-only replacement leaves the daemon alone (R5.5)" test -e "$H8/stop.calls"
    check "$h_aaprof" "$(hash_file "$H8/xdg-data/minimal/apparmor/minimald")" \
        "tampered data component was re-placed"

    # A `min` that fails and shouts is non-fatal and silent: an old binary may not
    # know `stop --force`, and no daemon running is itself a non-zero `min stop`.
    H9="$root/h9"; mkdir -p "$H9"
    run daemonprep "$H9"
    check 0 "$rc" "prep install exits 0"
    cat >"$H9/bin/min" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$HOME/stop.calls"
echo "old min: unrecognized subcommand 'stop'" >&2
echo "noise on stdout" >&1
exit 2
EOF
    chmod +x "$H9/bin/min"
    printf 'stale\n' >"$H9/bin/minimald"
    run daemonfails "$H9"
    check 0 "$rc" "a failing min stop does not fail the install (R5.5)"
    want_err "min stop stderr is hidden (R5.5)" grep -q "unrecognized subcommand" "$OUT"
    want_err "min stop stdout is hidden (R5.5)" grep -q "noise on stdout" "$OUT"
    check "$h_minimald" "$(hash_file "$H9/bin/minimald")" "the upgrade still completed (R5.5)"
    # Only the active-sessions refusal may prompt: every other non-zero stop (no
    # daemon, a failed connect, a min too old) stays silent and best-effort, and
    # still falls through to the force stop — the arm that covers a wedged daemon.
    want_err "a non-sessions stop failure asks nothing (R5.5)" grep -q "Continue?" "$OUT"
    want_err "a non-sessions stop failure lists nothing (R5.5)" grep -q "active sessions" "$OUT"
    want_ok "a non-sessions stop failure still force-stops (R5.5)" \
        grep -qx "stop --force" "$H9/stop.calls"

    # Live sessions turn the stop into a decision: the installer lists what is
    # running and asks. The answer is read from the controlling terminal, never
    # from stdin — under `curl … | sh` stdin is the script itself — so the harness
    # points MINIMAL_OVERRIDE_TTY at a file standing in for /dev/tty.
    #
    # These homes carry their own HL prefix rather than extending the plain H<n>
    # run, following the HAA_/HD/HU families above. Every scenario here deliberately
    # leaves a home a later run must not inherit — a `sessions.live` marker and a
    # `min` that refuses to stop while it exists — so a home reused by number
    # further down would not be the fresh install it reads as, and would abort on
    # the prompt instead.
    HL1="$root/hl1"; mkdir -p "$HL1"
    stage_live_upgrade "$HL1" liveyes
    printf 'y\n' >"$root/tty-yes"
    TTY_FILE="$root/tty-yes"
    run liveyes "$HL1"
    TTY_FILE=
    check 0 "$rc" "confirmed upgrade exits 0 (R5.5)"
    want_ok "the running sessions are listed (R5.5)" grep -q "session-alpha" "$OUT"
    want_ok "the user is asked before sessions die (R5.5)" grep -q "Continue?" "$OUT"
    want_ok "the graceful stop is tried first (R5.5)" grep -qx "stop" "$HL1/stop.calls"
    want_ok "confirmation escalates to --force (R5.5)" grep -qx "stop --force" "$HL1/stop.calls"
    check "$h_minimald" "$(hash_file "$HL1/bin/minimald")" "a confirmed upgrade completes (R5.5)"

    # Declining aborts before the first swap: non-zero, nothing installed, no
    # temp file left behind, and the daemon never force-stopped.
    HL2="$root/hl2"; mkdir -p "$HL2"
    stage_live_upgrade "$HL2" liveno
    printf 'n\n' >"$root/tty-no"
    TTY_FILE="$root/tty-no"
    run liveno "$HL2"
    TTY_FILE=
    check 1 "$rc" "declining aborts the install (R5.5)"
    want_ok "the abort reports no executable was replaced (R5.5)" \
        grep -q "no executables were replaced" "$OUT"
    want_err "declining never force-stops (R5.5)" grep -qx "stop --force" "$HL2/stop.calls"
    check "stale" "$(cat "$HL2/bin/minimald")" "the stale component is left in place (R5.5)"
    want_err "no temp file survives the abort (R5.5)" ls "$HL2/bin/"*.tmp.* 2>/dev/null

    # No terminal to ask on (CI, a non-interactive shell): abort promptly naming the
    # escape hatch rather than hang on a read or destroy sessions unasked.
    HL3="$root/hl3"; mkdir -p "$HL3"
    stage_live_upgrade "$HL3" livenotty
    run livenotty "$HL3"
    check 1 "$rc" "an unconfirmable upgrade aborts (R5.5)"
    want_ok "the abort names the escape hatch (R5.5)" grep -q -- "--force-stop" "$OUT"
    want_err "nothing is asked without a terminal (R5.5)" grep -q "Continue?" "$OUT"
    want_err "an unconfirmable upgrade never force-stops (R5.5)" \
        grep -qx "stop --force" "$HL3/stop.calls"
    check "stale" "$(cat "$HL3/bin/minimald")" "nothing is installed without confirmation (R5.5)"

    # The escape hatch as a flag: force-stop straight away, no question, no hang.
    HL4="$root/hl4"; mkdir -p "$HL4"
    stage_live_upgrade "$HL4" liveforce
    run liveforce "$HL4" --force-stop
    check 0 "$rc" "--force-stop upgrade exits 0 (R5.5)"
    want_err "--force-stop asks nothing (R5.5)" grep -q "Continue?" "$OUT"
    want_err "--force-stop skips the graceful stop (R5.5)" grep -qx "stop" "$HL4/stop.calls"
    want_ok "--force-stop force-stops (R5.5)" grep -qx "stop --force" "$HL4/stop.calls"
    check "$h_minimald" "$(hash_file "$HL4/bin/minimald")" "a forced upgrade completes (R5.5)"

    # The same hatch through the environment, for a pipeline with no argv at all.
    HL5="$root/hl5"; mkdir -p "$HL5"
    stage_live_upgrade "$HL5" liveforceenv
    FORCE_STOP=1
    run liveforceenv "$HL5"
    FORCE_STOP=
    check 0 "$rc" "MINIMAL_INSTALL_FORCE_STOP upgrade exits 0 (R5.5)"
    want_err "the env hatch asks nothing (R5.5)" grep -q "Continue?" "$OUT"
    want_ok "the env hatch force-stops (R5.5)" grep -qx "stop --force" "$HL5/stop.calls"

    # The flag is filtered out of the arguments wherever it sits, so the target
    # positional still resolves (R2.1). Deliberately a NON-default target: with
    # `stable` a filter that dropped every positional would land on the default and
    # still look right.
    printf 'v1\n' >"$mock/unstable"
    HL6="$root/hl6"; mkdir -p "$HL6"
    stage_live_upgrade "$HL6" liveforcepos
    run liveforcepos "$HL6" unstable --force-stop
    check 0 "$rc" "target plus --force-stop exits 0 (R5.5/R2.1)"
    want_ok "the target survives the option filter (R2.1)" grep -q "target 'unstable'" "$OUT"
    want_ok "the trailing flag still force-stops (R5.5)" grep -qx "stop --force" "$HL6/stop.calls"
}

case_shell_integration() {
    # --- Unit 9: shell-init files, rc hook, completions (R9.1-R9.3) -------------
    # A bash-login-shell install generates the three init files, hooks .bashrc
    # (creating it, since none exists in the fresh home), and produces completions
    # by running the installed bin/min itself.
    H7="$root/h7"; mkdir -p "$H7"
    TEST_SHELL=/bin/bash
    run shellinit "$H7"
    check 0 "$rc" "shell-init install exits 0"
    init7="$H7/xdg-data/minimal/shell-init"
    for f in bash.sh zsh.sh fish.fish; do
        want_ok "init file $f generated (R9.1)" test -f "$init7/$f"
    done
    want_ok "init embeds the resolved bin dir (R9.1)" grep -q "$H7/bin" "$init7/bash.sh"
    want_ok "record lists the generated init files (R9.1/R6.1)" \
        grep -q "shell-init-bash" "$H7/xdg-state/minimal/installed"

    # Sourcing the init under plain sh prepends bin to PATH exactly once.
    p1="$(env -i PATH=/usr/bin:/bin HOME="$H7" sh -c ". '$init7/bash.sh'; printf %s \"\$PATH\"")"
    check "$H7/bin:/usr/bin:/bin" "$p1" "sourcing the init prepends bin to PATH (R9.1)"
    p2="$(env -i PATH="$H7/bin:/usr/bin:/bin" HOME="$H7" sh -c ". '$init7/bash.sh'; printf %s \"\$PATH\"")"
    check "$H7/bin:/usr/bin:/bin" "$p2" "init never duplicates an existing PATH entry (R9.1)"

    # rc hook: created .bashrc carries exactly one marker-fenced block sourcing the
    # bash init; a rerun adds nothing (R9.2 idempotence).
    want_ok ".bashrc created with the marker block (R9.2)" grep -q '>>> minimal >>>' "$H7/.bashrc"
    want_ok "rc block sources the bash init (R9.2)" grep -q "shell-init/bash.sh" "$H7/.bashrc"
    run shellinit2 "$H7"
    check 0 "$rc" "shell-init rerun exits 0"
    check 1 "$(grep -c '>>> minimal >>>' "$H7/.bashrc")" "rerun adds no second rc block (R9.2)"

    # Completions, installed by executing the installed mock min (R9.3).
    want_ok "bash completions written for min (R9.3)" \
        grep -q "mock min completions for bash" "$H7/xdg-data/bash-completion/completions/min"
    want_ok "zsh completions written as _min (R9.3)" \
        grep -q "mock min completions for zsh" "$H7/xdg-data/zsh/completions/_min"
    want_ok "fish completions written (R9.3)" \
        grep -q "mock min completions for fish" "$H7/xdg-config/fish/completions/min.fish"
    want_ok "record lists the generated completions (R9.3/R6.1)" \
        grep -q "completions-zsh" "$H7/xdg-state/minimal/installed"
    # The record's path column is the path the binary printed, per shell — the
    # whole contract of the delegation (R9.3).
    want_ok "record row carries the installed zsh path (R9.3)" \
        record_has completions-zsh "$H7/xdg-data/zsh/completions/_min" \
            "$H7/xdg-state/minimal/installed"

    # The record is fed by what the binary PRINTS on stdout, not by a path table
    # the installer keeps: a min that installs somewhere the installer never
    # derives is still recorded (and so still uninstallable). That is the contract
    # between the two halves of R9.3.
    cat >"$mock/versions/v1/minimal-odd" <<'EOF'
#!/bin/sh
# mock min that installs completions where it likes, and says so on stdout
[ "${1:-}" = completions ] || exit 0
mkdir -p "$HOME/odd"
printf '# odd completions for %s\n' "$3" >"$HOME/odd/$3-odd"
printf '%s\n' "$HOME/odd/$3-odd"
EOF
    chmod +x "$mock/versions/v1/minimal-odd"
    h_odd="$(hash_file "$mock/versions/v1/minimal-odd")"
    awk -v h="$h_odd" \
        '$1=="minimal" && $2=="linux" {$5=h; $8="versions/v1/minimal-odd"} {print}' \
        "$root/good-components" >"$mock/versions/v1/components"
    H16="$root/h16"; mkdir -p "$H16"
    run oddpaths "$H16"
    check 0 "$rc" "install exits 0 when min installs completions elsewhere (R9.3)"
    want_ok "the path the binary printed is what gets recorded (R9.3)" \
        record_has completions-zsh "$H16/odd/zsh-odd" "$H16/xdg-state/minimal/installed"
    want_err "the installer records no path of its own devising (R9.3)" \
        grep -q "bash-completion/completions/min" "$H16/xdg-state/minimal/installed"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore

    # Both existing bash rc files are hooked, and user content is preserved.
    HS_B="$root/hs_b"; mkdir -p "$HS_B"
    printf '# my bashrc\n' >"$HS_B/.bashrc"
    printf '# my bash_profile\n' >"$HS_B/.bash_profile"
    run bashboth "$HS_B"
    want_ok "existing .bashrc hooked (R9.2)" grep -q '>>> minimal >>>' "$HS_B/.bashrc"
    want_ok "existing .bash_profile hooked too (R9.2)" grep -q '>>> minimal >>>' "$HS_B/.bash_profile"
    want_ok "user rc content preserved (R9.2)" grep -q '# my bashrc' "$HS_B/.bashrc"

    # zsh and fish get their own rc files (created when missing); an unknown shell
    # falls back to .profile with the POSIX init.
    HS_Z="$root/hs_z"; mkdir -p "$HS_Z"
    TEST_SHELL=/usr/bin/zsh
    run zshinit "$HS_Z"
    want_ok ".zshrc created and hooked (R9.2)" grep -q "shell-init/zsh.sh" "$HS_Z/.zshrc"
    want_ok "zsh init wires fpath completions (R9.1)" \
        grep -q "fpath=" "$HS_Z/xdg-data/minimal/shell-init/zsh.sh"
    want_ok "zsh init self-heals a stale compinit dump (R9.1)" \
        grep -q '_comps\[min\]' "$HS_Z/xdg-data/minimal/shell-init/zsh.sh"
    H10="$root/h10"; mkdir -p "$H10"
    TEST_SHELL=/usr/bin/fish
    run fishinit "$H10"
    want_ok "config.fish created and hooked (R9.2)" \
        grep -q "shell-init/fish.fish" "$H10/xdg-config/fish/config.fish"
    H11="$root/h11"; mkdir -p "$H11"
    TEST_SHELL=/bin/ksh
    run kshinit "$H11"
    want_ok "unknown shell falls back to .profile (R9.2)" grep -q "shell-init/bash.sh" "$H11/.profile"
    TEST_SHELL=

    # Upgrade from the pre-rewrite installer: its rc block used the same markers
    # but sources ~/.minimal/shim/shell-init, so an unreplaced block leaves PATH
    # and completions silently dead. The markers are ours to own (R9.2): a stale
    # block is swapped for the current one, exactly once, preserving the user's
    # own rc content on both sides of it.
    H14="$root/h14"; mkdir -p "$H14"
    {
        printf '# my zshrc\n'
        printf '\n# >>> minimal >>>\n'
        # The old installer wrote a literal $HOME, hence the single quotes.
        # shellcheck disable=SC2016
        printf '[ -f "$HOME/.minimal/shim/shell-init/zsh.sh" ] && . "$HOME/.minimal/shim/shell-init/zsh.sh"\n'
        printf '# <<< minimal <<<\n'
        printf '\n# added after the old install\n'
    } >"$H14/.zshrc"
    # A compinit dump from the old install: its (version, file count) header can
    # keep matching after the completions-dir swap, so compinit would trust it and
    # never see the new _min. The install must drop it when it (re)writes the zsh
    # completions.
    printf '#files: 1 version: 5.9\n' >"$H14/.zcompdump"
    TEST_SHELL=/usr/bin/zsh
    run oldblock "$H14"
    check 0 "$rc" "upgrade over old rc block exits 0"
    want_err "stale compinit dump dropped on upgrade (R9.3)" test -e "$H14/.zcompdump"
    want_ok "dump drop announced (R9.3)" grep -q "cleared compinit dump cache" "$OUT"
    want_ok "stale block replacement announced (R9.2)" grep -qE "shell-init +replaced" "$OUT"
    check 1 "$(grep -c '>>> minimal >>>' "$H14/.zshrc")" "exactly one marker block after upgrade (R9.2)"
    want_ok "block now sources the current zsh init (R9.2)" grep -q "shell-init/zsh.sh" "$H14/.zshrc"
    want_err "no reference to the old shim path remains (R9.2)" grep -q '\.minimal/shim' "$H14/.zshrc"
    want_ok "user content before the old block preserved (R9.2)" grep -q '# my zshrc' "$H14/.zshrc"
    want_ok "user content after the old block preserved (R9.2)" \
        grep -q '# added after the old install' "$H14/.zshrc"
    run oldblock2 "$H14"
    check 0 "$rc" "rerun after replacement exits 0"
    want_err "rerun rewrites nothing (R9.2)" grep -qE "shell-init +(added|replaced)" "$OUT"
    check 1 "$(grep -c '>>> minimal >>>' "$H14/.zshrc")" "rerun keeps a single marker block (R9.2)"
    want_err "no dump means no drop announcement on rerun (R9.3)" \
        grep -q "cleared compinit dump cache" "$OUT"
    TEST_SHELL=

    # A start marker whose end marker was lost to a hand edit must never cost the
    # user the tail of their rc file: the strip refuses (the naive filter would
    # drop everything from the marker to EOF), the install warns with the manual
    # line, appends nothing, and still exits 0. Uninstall likewise keeps the file.
    H15="$root/h15"; mkdir -p "$H15"
    {
        printf '# my zshrc\n'
        printf '# >>> minimal >>>\n'
        printf '# end marker lost in a hand edit\n'
        printf 'alias important=stuff\n'
    } >"$H15/.zshrc"
    TEST_SHELL=/usr/bin/zsh
    run unterminated "$H15"
    check 0 "$rc" "unterminated marker block is non-fatal on install (R9.2)"
    want_ok "warning names the broken block (R9.2)" \
        grep -q "unterminated minimal block" "$OUT"
    want_ok "manual line still offered (R9.2)" grep -q "shell-init/zsh.sh" "$OUT"
    want_err "nothing appended after the stray marker (R9.2)" \
        grep -q "shell-init/zsh.sh" "$H15/.zshrc"
    want_ok "rc tail survives (R9.2)" grep -q "alias important=stuff" "$H15/.zshrc"
    want_ok "binaries still installed (R9.2)" test -x "$H15/bin/min"
    run untermuninst "$H15" --uninstall
    check 0 "$rc" "uninstall over unterminated block exits 0 (R9.4)"
    want_ok "uninstall warns about the broken block (R9.4)" \
        grep -q "unterminated minimal block" "$OUT"
    want_ok "uninstall keeps the rc tail (R9.4)" grep -q "alias important=stuff" "$H15/.zshrc"
    # The block survived, so the record must survive with it. The record is the only
    # inventory a later run has and `--uninstall` reads a missing one as "nothing to
    # undo", so dropping it here would strand the stray block permanently.
    want_ok "record retained while a shell block remains (R9.4)" \
        test -f "$H15/xdg-state/minimal/installed"
    want_ok "record retention is announced (R9.4)" grep -q "kept install record" "$OUT"
    # ...and the retention is worth something: repair the marker by hand and a second
    # uninstall finishes the job, block and record both.
    {
        printf '# my zshrc\n'
        printf '# >>> minimal >>>\n'
        printf '# end marker restored by hand\n'
        printf '# <<< minimal <<<\n'
        printf 'alias important=stuff\n'
    } >"$H15/.zshrc"
    TEST_SHELL=/usr/bin/zsh
    run untermretry "$H15" --uninstall
    check 0 "$rc" "uninstall retry over a repaired block exits 0 (R9.4)"
    want_err "repaired block is stripped on the retry (R9.4)" \
        grep -q '>>> minimal >>>' "$H15/.zshrc"
    want_ok "retry keeps the rc tail (R9.4)" grep -q "alias important=stuff" "$H15/.zshrc"
    want_err "record removed once the footprint is fully gone (R9.4)" \
        test -f "$H15/xdg-state/minimal/installed"
    TEST_SHELL=


    # A read-only rc file degrades to a warning: the install itself already
    # succeeded and must still exit 0, with the PATH advisory still printed.
    # (Root ignores file modes, so the scenario can't be staged there.)
    if [ "$(id -u)" -ne 0 ]; then
        H12="$root/h12"; mkdir -p "$H12"
        printf '# locked down\n' >"$H12/.bashrc"
        chmod 444 "$H12/.bashrc"
        TEST_SHELL=/bin/bash
        run rcreadonly "$H12"
        check 0 "$rc" "unwritable rc is non-fatal (R9.2)"
        want_ok "warning names the unwritable rc (R9.2)" \
            grep -q "failed to hook minimal shell support" "$OUT"
        want_ok "warning shows the line to add by hand (R9.2)" \
            grep -q "shell-init/bash.sh" "$OUT"
        want_err "read-only rc left untouched (R9.2)" grep -q '>>> minimal >>>' "$H12/.bashrc"
        want_ok "binaries still installed despite rc failure (R9.2)" test -x "$H12/bin/min"
        want_ok "PATH advisory still printed after rc failure (R6.2)" \
            grep -q "is not on your PATH" "$OUT"
        want_err "no raw shell error leaks on rc failure (R9.2)" \
            grep -qi "permission denied" "$OUT"
        TEST_SHELL=

        # An unwritable completion dir (e.g. a root-owned ~/.config/fish/completions
        # left by another tool) degrades to a warning naming the dir: the install
        # still exits 0, the other shells' completions still land, and the shell's
        # own redirection error is not leaked to the user.
        H13="$root/h13"; mkdir -p "$H13/xdg-config/fish/completions"
        chmod 555 "$H13/xdg-config/fish/completions"
        run compreadonly "$H13"
        chmod 755 "$H13/xdg-config/fish/completions"   # restore for later cleanup
        check 0 "$rc" "unwritable completion dir is non-fatal (R9.3)"
        # The binary warns on stderr; the installer relays it in its own voice.
        want_ok "warning names the unwritable completion dir (R9.3)" \
            grep -q "completions: warning: failed to install fish completions" "$OUT"
        want_err "no raw shell error leaks on completion failure (R9.3)" \
            grep -qi "permission denied" "$OUT"
        want_ok "other shells' completions still installed (R9.3)" \
            test -f "$H13/xdg-data/bash-completion/completions/min"
        want_err "nothing written into the unwritable dir (R9.3)" \
            ls "$H13/xdg-config/fish/completions/"* 2>/dev/null
    fi
}

case_darwin_dequarantine() {
    # --- Unit 5 (darwin): dequarantine Mach-O bin/lib components ---------------
    # Force a darwin/arm64 platform (via the uname stub) so this runs on every lane.
    # The applicable rows are then `minimal` (bin) and `rootfs` (data). A bin file
    # must be quarantine-stripped; a data file must not be. Release artifacts are
    # Developer ID signed at build time, so the installer does NO local signing —
    # it places the downloaded bytes verbatim.
    PLAT_S=Darwin
    PLAT_M=arm64
    : >"$root/xattr.calls"
    HD="$root/hd"; mkdir -p "$HD"
    reset_dl
    run darwin1 "$HD"
    check 0 "$rc" "darwin install exits 0"
    want_ok "darwin bin component installed" test -f "$HD/bin/min"
    want_ok "quarantine stripped from bin (xattr)" grep -q "/bin/min\.tmp" "$root/xattr.calls"
    want_err "data component not dequarantined" grep -q "rootfs" "$root/xattr.calls"

    # A darwin `lib` dylib gets the SAME dequarantine treatment as a bin file so the
    # shipped libkrun.1.dylib runs without a Gatekeeper prompt. Isolated home +
    # one-off manifest with a single darwin lib row, so it doesn't perturb the rerun
    # counts below.
    {
        printf '# format: 1\n'
        printf '# c o a v s k d s\n'
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            libkrun darwin arm64 v1 "$h_drootfs" file lib/libkrun.1.dylib versions/v1/rootfs-darwin-arm64.img
    } >"$mock/versions/v1/components"
    : >"$root/xattr.calls"
    HDL="$root/hdl"; mkdir -p "$HDL"
    reset_dl
    run darwinlib "$HDL"
    check 0 "$rc" "darwin lib install exits 0"
    want_ok "darwin lib dylib installed" test -f "$HDL/.local/lib/libkrun.1.dylib"
    want_ok "quarantine stripped from lib dylib (xattr)" \
        grep -q "/lib/libkrun.1.dylib" "$root/xattr.calls"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore
    : >"$root/xattr.calls"

    # The installer places the artifact bytes verbatim, so the on-disk hash equals
    # the manifest hash. A rerun recognizes the component as already installed and
    # downloads nothing (Goal 2 — cheap reruns).
    reset_dl
    run darwin2 "$HD"
    check 0 "$rc" "darwin rerun exits 0"
    check 0 "$(downloads)" "darwin bin: rerun downloads nothing"

    # A NEW release (its manifest sha256 changes) is re-downloaded rather than judged
    # up to date, since the on-disk bytes no longer match the new manifest hash.
    printf 'darwin-arm64-minimal-body-v2\n' >"$mock/versions/v1/minimal-darwin-arm64-v2"
    h_dmin2="$(hash_file "$mock/versions/v1/minimal-darwin-arm64-v2")"
    awk -v h="$h_dmin2" \
        '$1=="minimal" && $2=="darwin" {$5=h; $8="versions/v1/minimal-darwin-arm64-v2"} {print}' \
        "$root/good-components" >"$mock/versions/v1/components"
    reset_dl
    run darwin3 "$HD"
    check 0 "$rc" "darwin new-version rerun exits 0"
    check 1 "$(downloads)" "new manifest hash re-downloads the darwin bin"
    # The v2 artifact is an opaque body, not a runnable script: completion
    # generation must degrade to a warning, not fail the install (R9.3).
    want_ok "unrunnable min degrades to a completions warning (R9.3)" \
        grep -q "could not generate" "$OUT"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore
    PLAT_S=Linux
    PLAT_M=x86_64
}

case_uninstall() {
    # --- Units 7-8: uninstall (walk the install record and undo it) ------------
    # Uninstall is offline and driven solely by the record the install wrote (R6.1).
    # Each scenario seeds a fresh home with a normal linux/amd64 install (placing
    # bin/minimald + bin/minimal and the record), then exercises one uninstall path.

    # R7.3/R8.1 — basic uninstall removes every recorded file, the record, and prunes
    # the now-empty owned dirs.
    HU="$root/hu"; mkdir -p "$HU"
    run u_install "$HU"
    check 0 "$rc" "uninstall: seed install exits 0"
    urec="$HU/xdg-state/minimal/installed"
    want_ok "uninstall: seed wrote the record" test -f "$urec"
    run u_basic "$HU" --uninstall
    check 0 "$rc" "uninstall exits 0 (R8.4)"
    want_err "uninstall removed minimald (R7.3)" test -e "$HU/bin/minimald"
    want_err "uninstall removed min (R7.3)" test -e "$HU/bin/min"
    want_err "uninstall removed the git-remote-min symlink (R7.3)" test -L "$HU/bin/git-remote-min"
    want_err "uninstall removed the record (R8.1)" test -e "$urec"
    want_ok "uninstall prints a summary" grep -q "uninstall:" "$OUT"
    want_err "empty bin dir pruned (R8.1)" test -d "$HU/bin"
    want_err "empty state dir pruned (R8.1)" test -d "$HU/xdg-state/minimal"
    # R7.2 — a second uninstall (record now gone) is a clean no-op.
    run u_again "$HU" --uninstall
    check 0 "$rc" "second uninstall is a clean no-op (R7.2)"
    want_ok "no-op names the missing record (R7.2)" grep -q "nothing to uninstall" "$OUT"

    # R7.3/R7.4 — a file modified since install is KEPT (its bytes no longer match the
    # recorded hash), and the record is retained so --force can still reach it.
    HU2="$root/hu2"; mkdir -p "$HU2"
    run u2_install "$HU2"
    urec2="$HU2/xdg-state/minimal/installed"
    printf 'my own build\n' >"$HU2/bin/minimald"      # user replaced a binary
    run u2_keep "$HU2" --uninstall
    check 0 "$rc" "uninstall with a modified file exits 0 (R8.4)"
    want_ok "modified file kept (R7.3)" test -f "$HU2/bin/minimald"
    want_ok "keep is reported (R7.3)" grep -qE "kept +modified since install" "$OUT"
    want_err "unmodified sibling still removed (R7.3)" test -e "$HU2/bin/min"
    want_ok "record retained while entries remain (R8.1)" test -f "$urec2"
    # --force then removes the modified file and, footprint clear, drops the record.
    run u2_force "$HU2" --uninstall --force
    check 0 "$rc" "uninstall --force exits 0"
    want_err "modified file removed under --force (R7.3)" test -e "$HU2/bin/minimald"
    want_err "record removed once footprint is gone (R8.1)" test -e "$urec2"

    # R7.2 — uninstall on a home that never installed anything exits 0, does nothing.
    HU3="$root/hu3"; mkdir -p "$HU3"
    run u3_noop "$HU3" --uninstall
    check 0 "$rc" "uninstall with no record exits 0 (R7.2)"
    want_ok "no-op names the missing record" grep -q "nothing to uninstall" "$OUT"

    # R8.3 — --dry-run removes nothing and leaves the record; a real run still cleans.
    HU4="$root/hu4"; mkdir -p "$HU4"
    run u4_install "$HU4"
    urec4="$HU4/xdg-state/minimal/installed"
    run u4_dry "$HU4" --uninstall --dry-run
    check 0 "$rc" "uninstall --dry-run exits 0 (R8.3)"
    want_ok "dry-run keeps minimald (R8.3)" test -f "$HU4/bin/minimald"
    want_ok "dry-run keeps the record (R8.3)" test -f "$urec4"
    want_ok "dry-run announces itself (R8.3)" grep -q "dry run" "$OUT"
    run u4_real "$HU4" --uninstall
    want_err "real uninstall after dry-run removes minimald" test -e "$HU4/bin/minimald"

    # R8.2 — plain uninstall leaves an unrelated build artifact in the cache tree;
    # --purge removes the whole minimal-owned cache tree.
    HU5="$root/hu5"; mkdir -p "$HU5"
    run u5_install "$HU5"
    stray="$HU5/xdg-cache/minimal/built/deadbeef"
    mkdir -p "$HU5/xdg-cache/minimal/built"; printf 'artifact\n' >"$stray"
    run u5_plain "$HU5" --uninstall
    want_ok "plain uninstall leaves the build cache (R8.2)" test -f "$stray"
    run u5_reinstall "$HU5"
    run u5_purge "$HU5" --uninstall --purge
    check 0 "$rc" "uninstall --purge exits 0"
    want_err "purge removes the cache tree (R8.2)" test -e "$HU5/xdg-cache/minimal"

    # R7.3 — a non-regular file now occupying a recorded path is never removed, even
    # with --force (the installer only ever wrote regular files there).
    HU6="$root/hu6"; mkdir -p "$HU6"
    run u6_install "$HU6"
    urec6="$HU6/xdg-state/minimal/installed"
    rm -f "$HU6/bin/minimald"; mkdir -p "$HU6/bin/minimald"   # a dir now sits there
    run u6_foreign "$HU6" --uninstall --force
    check 0 "$rc" "uninstall over a non-regular path exits 0 (R7.3)"
    want_ok "directory at a recorded path is left alone (R7.3)" test -d "$HU6/bin/minimald"
    want_ok "foreign entry is reported (R7.3)" grep -q "not a regular file" "$OUT"
    want_ok "record retained due to the foreign entry (R8.1)" test -f "$urec6"

    # R7.3 — a symlink retargeted since install is the user's edit: kept by default,
    # removed under --force. A regular file now at the recorded symlink path is
    # foreign — kept even with --force.
    HU8="$root/hu8"; mkdir -p "$HU8"
    run u8_install "$HU8"
    urec8="$HU8/xdg-state/minimal/installed"
    rm -f "$HU8/bin/git-remote-min"; ln -s minimald "$HU8/bin/git-remote-min"
    run u8_keep "$HU8" --uninstall
    check 0 "$rc" "uninstall with a retargeted symlink exits 0 (R8.4)"
    want_ok "retargeted symlink kept (R7.3)" test -L "$HU8/bin/git-remote-min"
    want_ok "retarget keep is reported (R7.3)" grep -q "retargeted" "$OUT"
    want_ok "record retained while the link remains (R8.1)" test -f "$urec8"
    run u8_force "$HU8" --uninstall --force
    check 0 "$rc" "uninstall --force over a retargeted symlink exits 0"
    want_err "retargeted symlink removed under --force (R7.3)" test -L "$HU8/bin/git-remote-min"
    want_err "record removed once footprint is gone (R8.1)" test -e "$urec8"

    HU9="$root/hu9"; mkdir -p "$HU9"
    run u9_install "$HU9"
    rm -f "$HU9/bin/git-remote-min"; printf 'a real file now\n' >"$HU9/bin/git-remote-min"
    run u9_foreign "$HU9" --uninstall --force
    check 0 "$rc" "uninstall over a file at a symlink row exits 0 (R7.3)"
    want_ok "regular file at a symlink row kept even with --force (R7.3)" \
        test -f "$HU9/bin/git-remote-min"
    want_ok "foreign symlink row is reported (R7.3)" grep -q "not a symlink" "$OUT"

    # R9.4 — uninstall removes the generated init/completion files (they are plain
    # record rows), strips the marker block from the rc file, prunes the emptied
    # completion dirs, and leaves the user's own rc content untouched.
    HU7="$root/hu7"; mkdir -p "$HU7"
    printf '# keep me\n' >"$HU7/.bashrc"
    TEST_SHELL=/bin/bash
    run u7_install "$HU7"
    check 0 "$rc" "shell-integration seed install exits 0"
    # A dump written after the install (by the user's shells) still holds the min
    # registration; uninstall must drop it or the next `min <tab>` autoload fails.
    printf '#files: 1 version: 5.9\n' >"$HU7/.zcompdump"
    run u7_dry "$HU7" --uninstall --dry-run
    want_ok "dry-run announces the rc strip without editing (R9.4/R8.3)" \
        grep -q "would remove shell-init block" "$OUT"
    want_ok "dry-run leaves the rc block (R8.3)" grep -q '>>> minimal >>>' "$HU7/.bashrc"
    want_ok "dry-run announces the compinit dump drop (R9.4/R8.3)" \
        grep -q "would remove compinit dump cache" "$OUT"
    want_ok "dry-run leaves the compinit dump (R8.3)" test -f "$HU7/.zcompdump"
    run u7_un "$HU7" --uninstall
    check 0 "$rc" "uninstall with shell integration exits 0"
    want_err "compinit dump dropped (R9.4)" test -e "$HU7/.zcompdump"
    want_err "completions removed (R9.4)" test -e "$HU7/xdg-data/bash-completion/completions/min"
    want_err "init files removed (R9.4)" test -e "$HU7/xdg-data/minimal/shell-init"
    want_err "emptied completion dirs pruned (R9.4)" test -d "$HU7/xdg-data/bash-completion"
    want_err "emptied data dir pruned (R9.4)" test -d "$HU7/xdg-data/minimal"
    want_err "rc block stripped (R9.4)" grep -q '>>> minimal >>>' "$HU7/.bashrc"
    want_ok "user rc content survives the strip (R9.4)" grep -q '# keep me' "$HU7/.bashrc"
    TEST_SHELL=

    # R9.4 — a record without a completions-zsh row must NOT cost the user their
    # compinit dump: the cache is only cleared when the installer actually put min
    # into it. Seeds its own data-only install (as the prefix case does), so the
    # case stands alone.
    {
        printf '# format: 1\n'
        printf '# c o a v s k d s\n'
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs linux amd64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-amd64.img
    } >"$mock/versions/v1/components"
    HUD="$root/hud"; mkdir -p "$HUD"
    run u_datadump_install "$HUD"
    check 0 "$rc" "data-only seed install exits 0"
    printf '# untouched user cache\n' >"$HUD/.zcompdump"
    run u_datadump "$HUD" --uninstall
    check 0 "$rc" "data-only uninstall exits 0"
    want_ok "dump kept when no zsh completions were installed (R9.4)" \
        grep -q '# untouched user cache' "$HUD/.zcompdump"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore
}

case_gvproxy_rename_migration() {
    # --- gvproxy -> gvproxy-min rename migration --------------------------------

    # The switch binary moved from bin/gvproxy to bin/gvproxy-min (the bin prefix is
    # on PATH and podman/crc ship their own gvproxy). The old dest is in no
    # manifest any more, so nothing would ever revisit it — the install has to undo
    # it explicitly, on the same bytes-still-ours terms as uninstall.
    HG_R="$root/hg_r"; mkdir -p "$HG_R"
    run gvren_seed "$HG_R"
    check 0 "$rc" "rename-migration seed install exits 0"

    # Seed what a pre-rename install left behind: the binary plus its record row.
    gvren_rec="$HG_R/xdg-state/minimal/installed"
    printf 'old-gvproxy-body\n' >"$HG_R/bin/gvproxy"
    gvren_h="$(hash_file "$HG_R/bin/gvproxy")"
    printf 'gvproxy\t%s\t%s\t%s\n' "$HG_R/bin/gvproxy" "$gvren_h" "$gvren_h" >>"$gvren_rec"

    run gvren "$HG_R"
    check 0 "$rc" "rename-migration install exits 0"
    want_err "stale bin/gvproxy removed on upgrade" test -e "$HG_R/bin/gvproxy"
    want_ok "removal announced" grep -q "renamed to gvproxy-min" "$OUT"

    run gvren_rerun "$HG_R"
    check 0 "$rc" "rerun after migration exits 0"
    want_err "rerun says nothing about gvproxy" grep -q "renamed to gvproxy-min" "$OUT"

    # A manifest that STILL ships a `gvproxy` component is not a rename: the file
    # on disk is the one this very run installed, so the migration must not touch
    # it. Channels advance independently, so a post-rename installer WILL be
    # pointed at a pre-rename manifest — deleting there would leave the host with
    # no switch binary at all, on every single run.
    HG_S="$root/hg_s"; mkdir -p "$HG_S"
    run gvship_seed "$HG_S"
    check 0 "$rc" "still-ships-gvproxy seed install exits 0"
    gvship_rec="$HG_S/xdg-state/minimal/installed"
    printf 'shipped-gvproxy-body\n' >"$HG_S/bin/gvproxy"
    gvship_h="$(hash_file "$HG_S/bin/gvproxy")"
    printf 'gvproxy\t%s\t%s\t%s\n' "$HG_S/bin/gvproxy" "$gvship_h" "$gvship_h" >>"$gvship_rec"
    # Make THIS run install a gvproxy component too, as a pre-rename manifest does.
    printf 'shipped-gvproxy-body\n' >"$mock/versions/v1/gvproxy-linux-amd64"
    h_gv="$(hash_file "$mock/versions/v1/gvproxy-linux-amd64")"
    {
        cat "$mock/versions/v1/components"
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            gvproxy linux amd64 v1 "$h_gv" file bin/gvproxy versions/v1/gvproxy-linux-amd64
    } >"$mock/versions/v1/components.new"
    mv "$mock/versions/v1/components.new" "$mock/versions/v1/components"
    run gvship "$HG_S"
    check 0 "$rc" "install against a manifest that still ships gvproxy exits 0"
    want_ok "the just-installed bin/gvproxy survives" test -f "$HG_S/bin/gvproxy"
    want_err "no removal is announced" grep -q "renamed to gvproxy-min" "$OUT"
    write_manifest 1

    # A gvproxy the user replaced (podman's, say) is NOT ours to delete: the hash
    # no longer matches what we recorded writing, so it is kept and reported.
    HG_K="$root/hg_k"; mkdir -p "$HG_K"
    run gvkeep_seed "$HG_K"
    check 0 "$rc" "rename-keep seed install exits 0"
    gvkeep_rec="$HG_K/xdg-state/minimal/installed"
    printf 'ours-when-installed\n' >"$HG_K/bin/gvproxy"
    gvkeep_h="$(hash_file "$HG_K/bin/gvproxy")"
    printf 'gvproxy\t%s\t%s\t%s\n' "$HG_K/bin/gvproxy" "$gvkeep_h" "$gvkeep_h" >>"$gvkeep_rec"
    printf 'the-users-own-gvproxy\n' >"$HG_K/bin/gvproxy"

    run gvkeep "$HG_K"
    check 0 "$rc" "rename-keep install exits 0"
    want_ok "a user-replaced gvproxy is kept" test -f "$HG_K/bin/gvproxy"
    want_ok "kept content is untouched" grep -q 'the-users-own-gvproxy' "$HG_K/bin/gvproxy"
    want_ok "keeping it is announced" grep -q "modified since install" "$OUT"
}

# --- NET-041: the installer verifies the switch binary -----------------------
# An own-IP session is served by a switch binary (gvproxy-min) the daemon
# spawns from exactly the paths this installer writes to, so the install
# confirms the binary is present and executable — and names the path it
# checked — before the gvproxy rename cleanup can delete anything.
case_installer_switch_binary_executable() {
    # A fresh install of the default manifest ships bin/gvproxy-min and must
    # verify it, by path, on stdout.
    HX="$root/hx"; mkdir -p "$HX"
    run sw_fresh "$HX"
    check 0 "$rc" "fresh install exits 0 with the switch binary shipped"
    want_ok "install names the switch binary it verified" \
        grep -qE "switch-binary +verified +[^ ]*bin/gvproxy-min$" "$OUT"
    want_ok "the verified switch binary is executable" test -x "$HX/bin/gvproxy-min"

    # The bytes still match the manifest, so no download repairs the bit: only
    # the executable check catches a file that lost its +x.
    chmod -x "$HX/bin/gvproxy-min"
    run sw_noexec "$HX"
    check 1 "$rc" "install dies when the shipped switch binary is not executable"
    want_ok "the failure names the switch binary path" \
        grep -qE "switch binary .*bin/gvproxy-min .*not.*executable" "$OUT"
    want_err "no closing card on the failed install (R10.4)" \
        grep -qE "Minimal .+ is ready" "$OUT"
    chmod +x "$HX/bin/gvproxy-min"

    # A channel with no switch binary at all says so and still succeeds.
    {
        printf '# format: 1\n'
        printf '# c o a v s k d s\n'
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs linux amd64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-amd64.img
    } >"$mock/versions/v1/components"
    HY="$root/hy"; mkdir -p "$HY"
    run sw_noship "$HY"
    check 0 "$rc" "a channel that ships no switch binary still exits 0"
    want_ok "the absent switch binary is reported, not fatal" \
        grep -qE "switch-binary +skipped" "$OUT"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore

    # A pre-rename channel still ships `bin/gvproxy` under the old name: the
    # check falls back to that row, the only switch binary such a host has
    # (and the rename cleanup below it must not leave the host without one).
    printf 'pre-rename-gvproxy-body\n' >"$mock/versions/v1/gvproxy-linux-amd64"
    h_gv_old="$(hash_file "$mock/versions/v1/gvproxy-linux-amd64")"
    {
        printf '# format: 1\n'
        printf '# c o a v s k d s\n'
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimald linux amd64 v1 "$h_minimald" file bin/minimald versions/v1/minimald-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            gvproxy linux amd64 v1 "$h_gv_old" file bin/gvproxy versions/v1/gvproxy-linux-amd64
    } >"$mock/versions/v1/components"
    HZ="$root/hz"; mkdir -p "$HZ"
    run sw_prerename "$HZ"
    check 0 "$rc" "pre-rename channel install exits 0"
    want_ok "the check verifies the old gvproxy row the channel still ships" \
        grep -qE "switch-binary +verified +[^ ]*bin/gvproxy$" "$OUT"
    want_ok "the pre-rename switch binary is executable" test -x "$HZ/bin/gvproxy"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore
}

# --- NET-079: the host classifier tree --------------------------------------
# install-host-classifier.sh is the privileged step that lays out the cgroup
# tree minimald and its boxes are placed in, on a native host. CI cannot mount
# cgroup2, so the case drives the script against a stand-in mount table through
# its MINIMAL_OVERRIDE_CGROUP_MOUNTINFO seam, with stubbed `chown` and `nft`
# recording their own argv, over a tree rooted in a temp dir: what is pinned
# is the decision sequence a root run would take on the real mount — refuse an
# undelegated hierarchy, refuse another namespace's view, delegate the slice
# and every cgroup it lays out whole (each directory plus cgroup.procs,
# cgroup.threads and cgroup.subtree_control, the cohort's two subtrees
# included), leave the cgroup2 mount root above the slice root-owned, refuse
# to render the cohort's two source identities half-done, load exactly one
# packet-filter transaction that replaces the table rather than adding to
# it, remove the presence marker before the load and write it again only
# after, and print the very transaction it loads under --print-ruleset. The
# one fact the stand-in cannot stand in for
# is the kernel: it makes a cgroup's files at mkdir and dissolves them with the
# cgroup at rmdir, so the case drops the modeled ones wherever a real rmdir
# would have taken the cgroup too.
case_host_classifier_tree_installed() {
    command -v bash >/dev/null 2>&1 || {
        echo "install_test: bash not found; skipping host_classifier_tree_installed" >&2
        return 0
    }
    hc="$here/install-host-classifier.sh"
    if [ ! -f "$hc" ]; then bad "install-host-classifier.sh is missing"; return 0; fi

    cg="$root/cg"                      # the stand-in cgroup2 mountpoint
    tree="$cg/minimald.slice"          # the tree the script installs
    me="$(id -u)"

    # Stand-in mount tables. Field 4 is the mount's root within the
    # filesystem: "/" in the host's initial cgroup namespace, something else
    # inside a container that mounts cgroup2 into its own — the case the
    # script must refuse, or the tree would be created inside that namespace.
    printf '38 30 0:25 / %s rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n' "$cg" >"$root/mi-on"
    printf '38 30 0:25 / %s rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n' "$cg" >"$root/mi-off"
    printf '38 30 0:25 /inner %s rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n' "$cg" >"$root/mi-nested"
    printf '38 30 0:26 / %s rw,relatime - ext4 /dev/root rw\n' "$root" >"$root/mi-none"

    # A recording chown stub: delegation is the point of the install, and on
    # the stand-in filesystem the caller owns the files anyway, so the case
    # reads what the script chowned rather than inferring it from their owner.
    # It records and exits 0 without exec'ing the real chown: on the host this
    # script installs on that chown runs as root, which CI's unprivileged
    # lanes cannot stage, and where it lives is host-specific (/usr/bin on
    # Linux, /usr/sbin on macOS), so exec'ing it would break the macOS lane
    # while asserting nothing the case needs — the recorded argv is the whole
    # delegation decision.
    hcbin="$root/hcbin"; mkdir -p "$hcbin"
    chown_calls="$root/chown.calls"; : >"$chown_calls"
    cat >"$hcbin/chown" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$CHOWN_CALLS"
STUB
    chmod +x "$hcbin/chown"

    # A recording nft stub, in the chown stub's image: the step's second half
    # is the packet-filter table, and what CI can pin of it without the
    # capability to load one is the decision sequence — the transaction file
    # that replaces the table, loaded exactly once, and the marker only
    # after. The `-f` argument's file is captured whole: the case and the
    # daemon's own ruleset tests read the transaction the step rendered.
    # NFT_FAIL makes the load die, for the case that a failed re-load must
    # leave no marker behind it. `list ruleset` serves the listing NFT_RULESET
    # names, because the step now reads the ruleset it is about to load over
    # — the scan for a ct-mark user of its bits is a real call, and the
    # fixture is how a conflict is staged. Any other `list` says absent: no
    # stand-in kernel holds a table, so the uninstall probes once, skips its
    # delete, and reports nothing removed.
    nft_calls="$root/nft.calls"; : >"$nft_calls"
    nft_input="$root/nft.input"; : >"$nft_input"
    cat >"$hcbin/nft" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$NFT_CALLS"
if [ "$1" = "-f" ] && [ -n "${2:-}" ]; then
    cat "$2" >>"$NFT_INPUT"
    exit "${NFT_FAIL:-0}"
fi
if [ "$1" = "list" ] && [ "$2" = "ruleset" ]; then
    cat "${NFT_RULESET:-/dev/null}"
    exit 0
fi
[ "$1" = "list" ] && exit 1
exit 0
STUB
    chmod +x "$hcbin/nft"

    # run_hc <label> <mountinfo> [args...] ; sets rc, captures output in $OUT.
    run_hc() {
        label="$1"; mi="$2"; shift 2
        OUT="$root/hc.$label"
        set +e
        env -i \
            PATH="$hcbin:/usr/bin:/bin" \
            CHOWN_CALLS="$chown_calls" \
            NFT_CALLS="$nft_calls" \
            NFT_INPUT="$nft_input" \
            NFT_FAIL="${NFT_FAIL:-0}" \
            NFT_RULESET="${NFT_RULESET:-}" \
            MINIMAL_OVERRIDE_CGROUP_MOUNTINFO="$mi" \
            bash "$hc" --root "$tree" "$@" </dev/null >"$OUT" 2>&1
        rc=$?
        set -e
    }

    # drop_cgroup_files <cgroup-dir> — what the kernel does at rmdir on the
    # real mount: a cgroup's cgroup.procs, cgroup.threads and
    # cgroup.subtree_control belong to the cgroup and go with it, while the
    # stand-in is a plain directory that keeps them and would make every
    # rmdir below fail for the stand-in's own reason, not the one pinned.
    drop_cgroup_files() {
        rm -f "$1/cgroup.procs" "$1/cgroup.threads" "$1/cgroup.subtree_control"
    }

    # --- Before the install: --check reports the missing tree, makes nothing.
    run_hc pre_check "$root/mi-on" --check --user "$me"
    check 1 "$rc" "check exits 1 before the tree exists"
    want_ok "check names the tree it cannot find" grep -q "does not exist" "$OUT"
    want_ok "check advises the install, not a re-check" grep -q "install it: sudo" "$OUT"
    want_ok "the pre-install hint names the cohort's identity flag" \
        grep -q -- "--cohort-address <cohort address>" "$OUT"
    want_ok "the pre-install hint names the node plane's identity flag too" \
        grep -q -- "--node-plane-address <node-plane address>" "$OUT"
    want_err "check creates nothing" test -e "$tree"

    # --- Refusals: every one of them dies before a directory is made.
    run_hc no_nsdelegate "$root/mi-off" --user "$me"
    check 1 "$rc" "install dies on a cgroup2 mount without nsdelegate"
    want_ok "the refusal names nsdelegate" grep -q "nsdelegate" "$OUT"
    want_err "an undelegated hierarchy gets no tree" test -e "$tree"

    run_hc unmounted "$root/mi-none" --user "$me"
    check 1 "$rc" "install dies when no cgroup2 mount covers the tree"
    want_ok "the refusal names the hierarchy it needs" grep -q "cgroup2 mount" "$OUT"

    run_hc nested_ns "$root/mi-nested" --user "$me"
    check 1 "$rc" "install dies inside another cgroup namespace's view"
    want_ok "the refusal names the namespace" grep -q "another cgroup namespace" "$OUT"

    run_hc nested_check "$root/mi-nested" --check --user "$me"
    check 1 "$rc" "check reports the namespace view too"
    want_ok "check names the mount's root within it" grep -q "root /inner" "$OUT"

    run_hc no_owner "$root/mi-on"
    check 1 "$rc" "install dies without an account to delegate to"
    want_ok "the refusal asks for --user" grep -q -- "--user NAME" "$OUT"

    run_hc root_owner "$root/mi-on" --user root
    check 1 "$rc" "install refuses to delegate to root"
    want_ok "the refusal says what delegating to root means" \
        grep -q "same as not delegating" "$OUT"

    run_hc bogus_owner "$root/mi-on" --user no-such-account-net079
    check 1 "$rc" "install dies for an unknown account"
    want_ok "the refusal names the account" grep -q "no such account" "$OUT"
    want_err "a bad account still creates nothing" test -e "$tree"

    # --- The two source identities are required, together: a table that
    # refuses a deny-all box's connections while its cohort keeps the host's
    # own source identity is half of the classification, so the step refuses
    # to render half of it — with either missing, and with both missing.
    run_hc no_identity "$root/mi-on" --user "$me"
    check 1 "$rc" "install dies without the two source identities"
    want_ok "the refusal names the flag it needs" \
        grep -q -- "--cohort-address ADDR" "$OUT"
    want_ok "the refusal names the other flag too" \
        grep -q -- "--node-plane-address ADDR" "$OUT"
    want_err "no identities, no tree" test -e "$tree"

    run_hc half_identity "$root/mi-on" --user "$me" --cohort-address 100.72.0.9
    check 1 "$rc" "install dies with one of the two identities missing"
    want_ok "the refusal says they go together" grep -q "both source identities" "$OUT"
    want_err "half an identity still creates nothing" test -e "$tree"

    # --- The install: the slice, its daemon leaf, the cohort's two subtrees,
    # and the whole v2 contract delegated to the account minimald runs as.
    run_hc install "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 0 "$rc" "install exits 0 on a delegated cgroup2 mount"
    want_ok "the daemon leaf exists" test -d "$tree/daemon"
    want_ok "the box cohort exists"   test -d "$tree/boxes"
    want_ok "the deny subtree exists"  test -d "$tree/boxes/deny"
    want_ok "the allow subtree exists" test -d "$tree/boxes/allow"
    want_ok "the table's marker exists once the transaction succeeded" \
        test -d "$tree/classifier-table"
    want_ok "install names the tree it laid out"   grep -q "installed the classifier tree" "$OUT"
    want_ok "install names the delegated account" grep -q "delegated to" "$OUT"
    want_ok "install names the contract it delegated" grep -q "v2 contract" "$OUT"
    want_ok "install says what a daemon in the slice does per launch, not on its next start" \
        grep -q "once minimald is in the slice, each box it launches" "$OUT"
    want_ok "install names the loaded table" grep -q "loaded the classifier table" "$OUT"
    want_ok "install names the marker minimald probes" \
        grep -q "presence marker at $tree/classifier-table" "$OUT"
    want_ok "the slice's cgroup.procs is there for the daemon to write" \
        test -e "$tree/cgroup.procs"
    want_ok "the daemon leaf's cgroup.procs is there for --pid to write" \
        test -e "$tree/daemon/cgroup.procs"
    # Delegation handed over each cgroup whole — its directory plus
    # cgroup.procs, cgroup.threads and cgroup.subtree_control, because a
    # migration into a leaf needs write access to the common ancestor's
    # cgroup.procs, and that ancestor is the slice itself — and never
    # reached above the slice: a box runs as the daemon's uid, so a mount
    # root owned by that account is every cgroup on the host. The two
    # subtrees are delegated like the cohort they live under.
    _o="$(id -u):$(id -g)"
    _want=""
    for _cg in "" "/daemon" "/boxes" "/boxes/deny" "/boxes/allow"; do
        for _f in cgroup.procs cgroup.threads cgroup.subtree_control; do
            _want="$_want$_o $tree$_cg/$_f "
        done
        _want="$_want$_o $tree$_cg "
    done
    # One recorded call per line, compared as one line: the file is the stub's
    # ledger, not a shell variable, so fold it rather than word-split it.
    _got="$(awk '{printf "%s%s", sep, $0; sep = " "}' "$chown_calls")"
    check "${_want% }" "$_got" \
        "delegation reached the slice and every leaf whole, never above the slice"
    # The one packet-filter transaction, loaded exactly once, and nothing
    # per-box in it — every rule is keyed on a cgroup path. The daemon's own
    # ruleset tests read the same input in depth; this pins what the step
    # decided, at the layer the installer owns: the transaction replaces the
    # table rather than adding to it, the cohort's two identities, the
    # answerer as the deny subtree's one destination, and the retarget that
    # makes the answerer the destination a deny-all box's lookups reach.
    want_ok "the step loaded one transaction, exactly once" \
        [ "$(grep -c '^-f ' "$nft_calls")" -eq 1 ]
    want_ok "the step probes for no previous table: the transaction deletes it in-batch" \
        [ "$(grep -c '^list table' "$nft_calls")" -eq 0 ]
    want_ok "the transaction replaces the table: it declares what it deletes" \
        grep -q '^add table inet minimal_class$' "$nft_input"
    want_ok "the delete travels with the definition, before it" \
        awk '/^delete table inet minimal_class$/ {d = NR}
             /^table inet minimal_class \{/ {t = NR}
             END {exit !(d && t && d < t)}' "$nft_input"
    want_ok "the transaction keys its deny rule on the deny subtree" \
        grep -q 'cgroupv2 level 3 "minimald.slice/boxes/deny" jump deny_out' "$nft_input"
    # deny_out's first rule is pinned as the exact line it must be: the
    # reply leg of a connection someone else opened to the box — the
    # hostname proxy's to its loopback listener — is admitted, and nothing
    # the box itself originates is, so the refusal falls on it.
    check "$(awk '/chain deny_out \{/ {ch = 1; next}
                  ch && /^\}/ {exit}
                  ch && NF {sub(/^[ \t]+/, ""); print; exit}' "$nft_input")" \
          "ct state established,related ct direction reply accept" \
          "deny_out admits the reply direction only as its first rule"
    want_err "the deny chain admits no direction-less flow: what the box \
originates is refused" \
        grep -q 'ct state established,related accept' "$nft_input"
    want_ok "the deny rule admits the answerer by address and port only" \
        grep -q 'ip daddr 127.0.0.1 udp dport 7656 accept' "$nft_input"
    want_ok "the deny subtree's DNS-port lookups are retargeted onto the answerer" \
        grep -q 'level 3 "minimald.slice/boxes/deny" ip daddr 127.0.0.1 udp dport 53 dnat ip to 127.0.0.1:7656' "$nft_input"
    want_ok "the retarget runs at dstnat, before the filter chain decides" \
        grep -q 'type nat hook output priority dstnat' "$nft_input"
    want_ok "the deny rule refuses actively, never a silent drop" \
        grep -q 'reject with icmpx admin-prohibited' "$nft_input"
    # NET-078, translated: classification and translation are two chains,
    # because the kernel admits a socket-cgroup match only before
    # postrouting — a rule keyed on one there has never been loadable. The
    # classify chain runs at output's mangle priority, classes only a
    # connection that is new, and writes only the mask's two bits (the `and
    # ~mask or bit` shape, so bits another component classes with survive);
    # the slice's rule is guarded by the mask so it never re-decides a flow
    # the boxes rule already classed. The postrouting chain reads the mark,
    # never a socket, and gives the two planes their distinct sources.
    want_ok "the classify chain runs at output's mangle priority, ahead of the filter" \
        grep -q 'type filter hook output priority mangle' "$nft_input"
    want_ok "the cohort is classed by its subtree on a new connection, its bit written" \
        grep -q 'ct state new socket cgroupv2 level 2 "minimald.slice/boxes" ct mark set ct mark and 0xcfffffff or 0x10000000' "$nft_input"
    want_ok "the slice's rule is guarded by the mask, so the boxes rule's mark is final" \
        grep -q 'ct state new ct mark and 0x30000000 == 0 socket cgroupv2 level 1 "minimald.slice" ct mark set ct mark and 0xcfffffff or 0x20000000' "$nft_input"
    want_err "no postrouting rule matches a socket: the kernel refuses one there" \
        awk '/chain postrouting \{/ {p = 1; next}
             p && /^\}/ {exit}
             p && /socket/ {found = 1}
             END {exit found ? 0 : 1}' "$nft_input"
    want_ok "the cohort leaves as its own address, translated by its ct-mark bit, loopback excluded" \
        grep -q 'ct mark and 0x30000000 == 0x10000000 oifname != "lo" snat ip to 100.72.0.9' "$nft_input"
    want_ok "the node plane leaves as its own address, translated by its own bit" \
        grep -q 'ct mark and 0x30000000 == 0x20000000 oifname != "lo" snat ip to 100.72.0.1' "$nft_input"
    # The scan is a real decision, not a decoration: the step read the
    # ruleset it was about to load over, and recorded the two bits it chose
    # beside the marker the daemon probes.
    want_ok "the step read the ruleset it loads over, exactly once" \
        [ "$(grep -c '^list ruleset' "$nft_calls")" -eq 1 ]
    want_ok "the install records the ct-mark mask beside the marker" \
        test -d "$tree/ct-mark-mask-0x30000000"

    # --- --print-ruleset prints the same transaction the install loaded:
    # the daemon's own ruleset tests read this mode, so the two spellings
    # cannot drift.
    run_hc print_ruleset "$root/mi-on" --print-ruleset \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 0 "$rc" "--print-ruleset exits 0"
    check "$(cat "$nft_input")" "$(cat "$OUT")" \
        "print-ruleset prints exactly the transaction the install loaded"

    run_hc installed_check "$root/mi-on" --check --user "$me"
    check 0 "$rc" "check exits 0 once the tree is installed"
    want_ok "check reports the delegation it verified" grep -q "delegated:" "$OUT"
    want_ok "check names the contract it verified" grep -q "cgroup.threads" "$OUT"
    want_ok "check says what stays root-owned" grep -q "stays root-owned" "$OUT"
    want_ok "check reports the table's marker" grep -q "classifier-table" "$OUT"
    want_ok "check reports the recorded ct-mark mask" grep -q "ct-mark:  0x30000000" "$OUT"

    # --user takes an account name too, resolved to the same uid and group;
    # only when the caller's uid has a passwd entry to name it by (a cross
    # container runs as the host's uid, which has none).
    if me_name="$(id -un 2>/dev/null)"; then
        run_hc named_check "$root/mi-on" --check --user "$me_name"
        check 0 "$rc" "check by account name verifies the same delegation"
    fi

    # A numeric uid that is neither an account nor the caller has no group
    # to delegate to: refused, never handed the caller's group.
    stranger=4000000000
    if ! id -g "$stranger" >/dev/null 2>&1 && [ "$stranger" != "$(id -u)" ]; then
        run_hc stranger_check "$root/mi-on" --check --user "$stranger"
        check 1 "$rc" "check refuses a numeric uid with no account behind it"
        want_ok "the refusal names the uid" grep -q "no account with uid $stranger" "$OUT"
    fi

    # --- A re-install whose transaction dies leaves no marker: the step
    # removes it before the load and writes it only after, so the daemon
    # reads a host that decides nothing per box rather than a marker that
    # vouches for a table this step did not render. The tree's half is
    # already done, and stays.
    NFT_FAIL=1
    run_hc reload_failed "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 1 "$rc" "a re-install whose nft transaction dies exits 1"
    want_err "a failed re-load leaves no marker" test -e "$tree/classifier-table"
    want_err "a failed re-load leaves no ct-mark mask record either" \
        test -e "$tree/ct-mark-mask-0x30000000"
    want_ok "the failure says neither the marker nor its record was written" \
        grep -q "neither the marker nor its ct-mark mask record was written" "$OUT"
    want_ok "the tree itself survives a failed re-load" test -d "$tree/boxes/deny"
    NFT_FAIL=0
    run_hc reloaded "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 0 "$rc" "the next good re-install exits 0"
    want_ok "the next good re-install restores the marker" \
        test -d "$tree/classifier-table"
    want_ok "the next good re-install restores the mask record beside it" \
        test -d "$tree/ct-mark-mask-0x30000000"

    # --- The ct-mark bits are a shared namespace: a component already
    # classing with one of them would be silently overwritten by the
    # classify chain (and would overwrite it back), so the step reads the
    # ruleset it is about to load over and refuses, naming the rule and the
    # override. The fixture's rule is the stand-in for that component; the
    # escape is --ct-mark-mask naming bits nobody else classes with, and it
    # must be recorded, not just rendered.
    nft_ruleset_fixture="$root/nft-ruleset-conflict"
    printf 'table inet other_component {\n    chain classify {\n        ct mark set ct mark or 0x10000000\n    }\n}\n' \
        >"$nft_ruleset_fixture"
    NFT_RULESET="$nft_ruleset_fixture"
    run_hc conflict "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 1 "$rc" "the install refuses to load over a ct-mark user of its bits"
    want_ok "the refusal names the conflicting rule itself" \
        grep -q 'ct mark set ct mark or 0x10000000' "$OUT"
    want_ok "the refusal names the override it would take instead" \
        grep -q -- "--ct-mark-mask <two contiguous bits nothing else classes with>" "$OUT"
    want_ok "the refusal dies before touching anything: the previous marker \
still vouches for the table it loaded" \
        test -d "$tree/classifier-table"
    run_hc conflict_escaped "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1 \
        --ct-mark-mask 0x0000c000
    check 0 "$rc" "an install with non-overlapping bits escapes the conflict"
    want_ok "the escape renders its own bits, both identities on them" \
        grep -q 'ct mark and 0x0000c000 == 0x00004000 oifname != "lo" snat ip to 100.72.0.9' "$nft_input"
    want_ok "the escape records the bits it chose" \
        test -d "$tree/ct-mark-mask-0x0000c000"
    want_err "the escape left no record of the refused mask" \
        test -e "$tree/ct-mark-mask-0x30000000"
    run_hc conflict_back "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 1 "$rc" "the next default-mask install refuses again"
    NFT_RULESET=

    # --- --ct-mark-mask is validated before anything is made: exactly two
    # contiguous set bits inside the 32 a connection mark holds, nothing
    # else, each refused with the reason. A rule classing on one bit is no
    # classification of two identities, three is a spelling mistake, two
    # that are not adjacent is a mis-typed pair, and a bit the kernel cannot
    # hold is not a mask this step can render. A value that is not
    # hexadecimal at all is refused for that reason, its own.
    for bad_mask in 0x10000000 0x70000000 0x50000000 0x100000000 0x0 0x3000000f; do
        run_hc "bad_mask_$bad_mask" "$root/mi-on" --user "$me" \
            --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1 \
            --ct-mark-mask "$bad_mask"
        check 1 "$rc" "--ct-mark-mask $bad_mask is refused"
        want_ok "the refusal of $bad_mask says what a mask is" \
            grep -q -- "--ct-mark-mask must name" "$OUT"
        want_err "the refused mask $bad_mask made nothing" \
            test -e "$tree/ct-mark-mask-$bad_mask"
    done
    for bad_mask in not-hex 30000000 0xzz; do
        run_hc "bad_mask_$bad_mask" "$root/mi-on" --user "$me" \
            --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1 \
            --ct-mark-mask "$bad_mask"
        check 1 "$rc" "--ct-mark-mask $bad_mask is refused for its spelling"
        want_ok "the refusal of $bad_mask names the spelling it needs" \
            grep -q -- "--ct-mark-mask needs a" "$OUT"
        want_err "the refused mask $bad_mask made nothing" \
            test -e "$tree/ct-mark-mask-$bad_mask"
    done

    # --- Uninstall: the tree comes away whole — the two subtrees and the
    # table's marker with it — but a leaf the script did not place (a live
    # session's) stops it rather than tearing the box down. The kernel
    # dissolves a cgroup's own files with it, so the case drops the modeled
    # ones first and the rmdir rehearsed is the real one.
    drop_cgroup_files "$tree"
    drop_cgroup_files "$tree/daemon"
    drop_cgroup_files "$tree/boxes"
    drop_cgroup_files "$tree/boxes/deny"
    drop_cgroup_files "$tree/boxes/allow"
    run_hc uninstall "$root/mi-on" --uninstall
    check 0 "$rc" "uninstall removes the installed tree"
    want_err "uninstall leaves no tree behind" test -e "$tree"

    run_hc reinstalled "$root/mi-on" --user "$me" \
        --cohort-address 100.72.0.9 --node-plane-address 100.72.0.1
    check 0 "$rc" "install after an uninstall exits 0"

    # --- --pid: the daemon's first hop into the slice is the one migration
    # the delegated account cannot make itself — the common ancestor of the
    # cgroup a daemon starts in and the slice is the root-owned hierarchy
    # root — so the installer offers to make it for the running daemon.
    run_hc place "$root/mi-on" --pid "$$"
    check 0 "$rc" "--pid places the running daemon in its leaf"
    want_ok "the daemon leaf holds exactly that pid" \
        grep -qx "$$" "$tree/daemon/cgroup.procs"
    want_ok "the placement names the leaf it wrote" grep -q "placed .* in .*daemon" "$OUT"
    want_ok "the placement says it takes effect on the next launch, not the next start" \
        grep -q "per launch" "$OUT"
    want_ok "the placement says a plain restart loses it" \
        grep -q "Delegate=yes unit" "$OUT"

    run_hc place_dead "$root/mi-on" --pid 999999999
    check 1 "$rc" "--pid dies for a process that does not exist"
    want_ok "the refusal names the pid it could not find" \
        grep -q "no process 999999999" "$OUT"

    run_hc place_nonnumeric "$root/mi-on" --pid not-a-pid
    check 1 "$rc" "--pid dies for a pid that is not one"
    want_ok "the refusal asks for a numeric process id" \
        grep -q "numeric process id" "$OUT"

    drop_cgroup_files "$tree"
    drop_cgroup_files "$tree/daemon"
    drop_cgroup_files "$tree/boxes"
    drop_cgroup_files "$tree/boxes/deny"
    drop_cgroup_files "$tree/boxes/allow"
    mkdir "$tree/boxes/deny/a-session"
    run_hc uninstall_live "$root/mi-on" --uninstall
    check 1 "$rc" "uninstall dies while a box leaf survives"
    want_ok "the refusal says what is holding the tree" grep -q "stop minimald" "$OUT"
    want_ok "the live leaf survives the refused uninstall" test -d "$tree/boxes/deny/a-session"
    rm -rf "$tree"   # the sweep this case alone owns; the refused uninstall could not

    # --- --pid with no tree to place into names the step that is missing.
    run_hc place_no_tree "$root/mi-on" --pid "$$"
    check 1 "$rc" "--pid dies when the tree is not installed"
    want_ok "the refusal names the install it still needs" \
        grep -q "is not installed" "$OUT"

    # --- --help prints the script's own header as its usage.
    run_hc help "$root/mi-on" --help
    check 0 "$rc" "--help exits 0"
    want_ok "usage shows the sudo form" grep -q "sudo scripts/install-host-classifier.sh" "$OUT"
    want_ok "usage shows the unprivileged --check" grep -q -- "--check" "$OUT"
    want_ok "usage shows the unprivileged --print-ruleset" grep -q -- "--print-ruleset" "$OUT"
    want_ok "usage shows the --pid step" grep -q -- "--pid PID" "$OUT"
    want_ok "usage shows the ct-mark mask override" grep -q -- "--ct-mark-mask" "$OUT"

    # --- Without the rehearsal seam the script demands root, like the other
    # privileged loaders; nothing is created either way.
    OUT="$root/hc.rootcheck"
    set +e
    env -i PATH="/usr/bin:/bin" bash "$hc" --root "$tree" --user "$me" </dev/null >"$OUT" 2>&1
    rc=$?
    set -e
    want_err "an unprivileged real-host run creates nothing" test -e "$tree"
    if [ "$(id -u)" -eq 0 ]; then
        ok "root check skipped: this harness already runs as root"
    else
        check 1 "$rc" "an unprivileged real-host run dies"
        want_ok "the refusal asks for sudo" grep -q "must run as root" "$OUT"
    fi
}

# --- NET-048 / NET-050: Linux amd64 and arm64 releases ship the VM stack -----
# The proof is the release components table itself: every Linux architecture
# carries minvmd, the guest kernel, initramfs, rootfs image, and the switch.
# Each architecture installs under the uname stub into its own home, then we
# assert the files land on disk and are recorded.
case_linux_vm_stack() {
    _arch="$1"
    case "$_arch" in
        amd64) _uname_m=x86_64 ;;
        arm64) _uname_m=arm64 ;;
        *) bad "case_linux_vm_stack: unknown arch '$_arch'"; return ;;
    esac

    H_VM="$root/h_vm_$_arch"; mkdir -p "$H_VM"

    # Manifest proof: the release component table must list every VM-stack
    # part for linux/$_arch. If a row is missing the failure names the
    # component and architecture.
    for _comp in minvmd initramfs rootfs vmlinuz gvproxy-min; do
        want_ok "manifest ships $_comp for linux/$_arch" \
            manifest_has "$_comp" linux "$_arch"
    done

    PLAT_M="$_uname_m"
    reset_dl
    run "vm_${_arch}_install" "$H_VM"
    PLAT_M=x86_64
    check 0 "$rc" "$_arch install with VM stack exits 0"

    # The installer must have placed every VM-stack component for this arch.
    want_ok "$_arch minvmd installed and executable" test -x "$H_VM/bin/minvmd"
    want_ok "$_arch initramfs installed to data" test -f "$H_VM/xdg-data/minimal/initramfs.cpio"
    want_ok "$_arch rootfs installed to data" test -f "$H_VM/xdg-data/minimal/rootfs.img"
    want_ok "$_arch vmlinuz installed to data" test -f "$H_VM/xdg-data/minimal/vmlinuz"
    want_ok "$_arch switch binary installed and executable" test -x "$H_VM/bin/gvproxy-min"

    # Each one appears in the install record so --uninstall can remove it.
    _rec="$H_VM/xdg-state/minimal/installed"
    for _comp in minvmd initramfs rootfs vmlinuz gvproxy-min; do
        want_ok "$_arch install record lists $_comp" \
            record_has_comp "$_comp" "$_rec"
    done

    # Observability: the installer output names every component it found.
    for _comp in minvmd initramfs rootfs vmlinuz; do
        want_ok "$_arch installer printed $_comp status" \
            grep -qE "^  $_comp +(installed|current)" "$OUT"
    done
    want_ok "$_arch installer verified the switch binary" \
        grep -qE "^  switch-binary +(verified|current)" "$OUT"
}

case_linux_amd64_manifest_ships_vm_stack() { case_linux_vm_stack amd64; }
case_linux_arm64_manifest_ships_vm_stack() { case_linux_vm_stack arm64; }

# --- NET-122: the answerer ships beside min on every platform, as the copy
# source the session advisory's privileged step copies from. The installer
# places it with the same rules as the other binaries and writes no unit or
# plist naming the user-prefix path — the advisory's one privileged command is
# the only thing that ever installs the answerer service.
case_answerer_source_installed() {
    # linux/amd64: beside min, executable, byte-exact, recorded.
    H_A1="$root/h_ans_amd64"; mkdir -p "$H_A1"
    run ans_amd64_install "$H_A1"
    check 0 "$rc" "amd64 install with the answerer row exits 0"
    want_ok "amd64: the answerer installs beside min" test -f "$H_A1/bin/minzoned"
    want_ok "amd64: beside the installed min itself" test -f "$H_A1/bin/min"
    want_ok "amd64: the answerer is executable like every bin row" test -x "$H_A1/bin/minzoned"
    check "$h_answerer" "$(hash_file "$H_A1/bin/minzoned")" \
        "amd64: installed answerer matches the manifest hash"
    want_ok "amd64: the installer printed the answerer status" \
        grep -qE "^  minzoned +(installed|current)" "$OUT"
    _rec="$H_A1/xdg-state/minimal/installed"
    want_ok "amd64: the answerer is recorded at its user-prefix path" \
        record_has minzoned "$H_A1/bin/minzoned" "$_rec"
    # The installed copy is only the copy source: no unit or plist was
    # written, and no record row names a service-manager path or the
    # root-owned program path.
    # shellcheck disable=SC2016  # $1 is expanded by the inner sh, not here
    want_err "no unit or plist file was written" \
        sh -c 'find "$1" \( -name "*.plist" -o -name "*.service" -o -name "*.socket" \) -print | grep -q .' sh "$H_A1"
    # shellcheck disable=SC2016  # $2 is awk's second field, not a shell parameter
    want_ok "no record row names a unit, plist, or root-owned answerer path" \
        awk '$2 ~ /(systemd|launchd|PrivilegedHelperTools|lib\/minimal\/minzoned|dev\.gominimal\.zone)/ {bad=1} END{exit bad ? 1 : 0}' "$_rec"

    # An upgrade replaces it like the other binaries: a new release's answerer
    # bytes alone re-download and land.
    printf 'linux-amd64-answerer-body-v2\n' >"$mock/versions/v1/minzoned-linux-amd64-v2"
    h_answerer2="$(hash_file "$mock/versions/v1/minzoned-linux-amd64-v2")"
    awk -v h="$h_answerer2" \
        '$1=="minzoned" && $2=="linux" && $3=="amd64" {$5=h; $8="versions/v1/minzoned-linux-amd64-v2"} {print}' \
        "$root/good-components" >"$mock/versions/v1/components"
    reset_dl
    run ans_amd64_upgrade "$H_A1"
    check 0 "$rc" "answerer upgrade install exits 0"
    check 1 "$(downloads)" "a new manifest hash re-downloads the answerer alone"
    check "$h_answerer2" "$(hash_file "$H_A1/bin/minzoned")" \
        "the upgraded answerer replaced the installed copy"
    cp "$root/good-components" "$mock/versions/v1/components"   # restore

    # linux/arm64: its own row and bytes.
    PLAT_M=arm64
    H_A2="$root/h_ans_arm64"; mkdir -p "$H_A2"
    run ans_arm64_install "$H_A2"
    check 0 "$rc" "arm64 install with the answerer row exits 0"
    check "$h_answerer_arm" "$(hash_file "$H_A2/bin/minzoned")" \
        "arm64: the answerer installs beside min"
    PLAT_M=x86_64

    # darwin/arm64: beside min, dequarantined like every other bin row,
    # recorded at the user prefix.
    PLAT_S=Darwin; PLAT_M=arm64
    : >"$root/xattr.calls"
    H_A3="$root/h_ans_darwin"; mkdir -p "$H_A3"
    run ans_darwin_install "$H_A3"
    check 0 "$rc" "darwin install with the answerer row exits 0"
    want_ok "darwin: the answerer installs beside min" test -f "$H_A3/bin/minzoned"
    want_ok "darwin: quarantine stripped from the answerer bin (xattr)" \
        grep -q "/bin/minzoned\.tmp" "$root/xattr.calls"
    want_ok "darwin: the answerer is recorded at its user-prefix path" \
        record_has minzoned "$H_A3/bin/minzoned" "$H_A3/xdg-state/minimal/installed"
    PLAT_S=Linux; PLAT_M=x86_64
}

# --- Case dispatch -----------------------------------------------------------
# Every scenario group above is one named case. No argument runs them all, in
# the order the linear script used to have; one argument runs exactly that
# case (`just test-installer <case>`) for a tight loop on the case being
# edited. Each case seeds its own homes and restores whatever manifest state
# it mutates, so any one of them is runnable alone.
case_for() {
    case "$1" in
        install)                            case_install ;;
        apparmor)                           case_apparmor ;;
        apparmor_uninstall)                 case_apparmor_uninstall ;;
        finalize_install_uninstall)         case_finalize_install_uninstall ;;
        checksum_mismatch)                  case_checksum_mismatch ;;
        target_validation)                  case_target_validation ;;
        prefix_resolution)                  case_prefix_resolution ;;
        install_record)                     case_install_record ;;
        daemon_stop)                        case_daemon_stop ;;
        shell_integration)                  case_shell_integration ;;
        darwin_dequarantine)                case_darwin_dequarantine ;;
        uninstall)                          case_uninstall ;;
        gvproxy_rename_migration)           case_gvproxy_rename_migration ;;
        installer_switch_binary_executable) case_installer_switch_binary_executable ;;
        host_classifier_tree_installed)  case_host_classifier_tree_installed ;;
        answerer_source_installed)      case_answerer_source_installed ;;
        linux_amd64_manifest_ships_vm_stack) case_linux_amd64_manifest_ships_vm_stack ;;
        linux_arm64_manifest_ships_vm_stack) case_linux_arm64_manifest_ships_vm_stack ;;
        *)
            echo "install_test: unknown case '$1' (known cases listed in the dispatch)" >&2
            exit 2
            ;;
    esac
}
case "${1:-}" in
    "")
        for _c in install apparmor apparmor_uninstall finalize_install_uninstall checksum_mismatch \
            target_validation prefix_resolution install_record daemon_stop \
            shell_integration darwin_dequarantine uninstall \
            gvproxy_rename_migration installer_switch_binary_executable \
            host_classifier_tree_installed answerer_source_installed \
            linux_amd64_manifest_ships_vm_stack linux_arm64_manifest_ships_vm_stack; do
            case_for "$_c"
        done
        ;;
    *)  case_for "$1" ;;
esac

# ===========================================================================
echo "# ---"
printf '# %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
