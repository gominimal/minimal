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
#   scripts/install_test.sh            # runs under `sh`
#   sh scripts/install_test.sh         # ditto
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
printf 'linux-amd64-minimald-body\n'  >"$mock/versions/v1/minimald-linux-amd64"
write_min_stub "$mock/versions/v1/minimal-linux-amd64"  linux-amd64
write_min_stub "$mock/versions/v1/minimal-darwin-arm64" darwin-arm64
printf 'darwin-arm64-rootfs-body\n'   >"$mock/versions/v1/rootfs-arm64.img"

# AppArmor components: noarch text (the loader is a runnable stub here), shipped
# to Linux hosts under the data prefix (see stage-release.sh).
printf 'mock-apparmor-profile-body\n'  >"$mock/versions/v1/minimald.apparmor"
printf 'mock-apparmor-tunable-body\n'  >"$mock/versions/v1/minimald.apparmor-tunable"
printf '#!/bin/sh\n# mock apparmor loader\n' >"$mock/versions/v1/install-apparmor-profile.sh"

h_minimald="$(hash_file "$mock/versions/v1/minimald-linux-amd64")"
h_minimal="$(hash_file "$mock/versions/v1/minimal-linux-amd64")"
h_dmin="$(hash_file "$mock/versions/v1/minimal-darwin-arm64")"
h_rootfs="$(hash_file "$mock/versions/v1/rootfs-arm64.img")"
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
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimald linux amd64 v1 "$h_minimald" file bin/minimald versions/v1/minimald-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimal linux amd64 v1 "$h_minimal" file bin/min versions/v1/minimal-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimal darwin arm64 v1 "$h_dmin" file bin/min versions/v1/minimal-darwin-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs darwin arm64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-arm64.img
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-profile linux amd64 v1 "$h_aaprof" file data/apparmor/minimald versions/v1/minimald.apparmor
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-tunable linux amd64 v1 "$h_aatun" file data/apparmor/tunables/minimald versions/v1/minimald.apparmor-tunable
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            apparmor-installer linux amd64 v1 "$h_aaload" file data/apparmor/install-apparmor-profile.sh versions/v1/install-apparmor-profile.sh
        # Symlink rows (R5.6): sha256 is the `-` placeholder, src is the link
        # target relative to dest's directory.
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            git-remote-min linux amd64 v1 - symlink bin/git-remote-min min
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            git-remote-min darwin arm64 v1 - symlink bin/git-remote-min min
    } >"$mock/versions/v1/components"
}
write_manifest 1

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
        MINIMAL_OVERRIDE_TTY="${TTY_FILE:-$root/no-such-tty}" \
        MINIMAL_INSTALL_FORCE_STOP="${FORCE_STOP:-}" \
        "$SH" "$installer" "$@" </dev/null >"$OUT" 2>&1
    rc=$?
    set -e
}

# ===========================================================================
echo "# install.sh tests (SH=$SH)"

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
    grep -q "min session activate --attach ." "$OUT"
want_card_last "the card closes a fresh install (R10.4)"
# Nothing on a redirected stream may carry terminal escapes (R10.1): this
# output is a file, so a stray SGR here would land in every CI log.
want_err "no terminal escapes when stderr is not a terminal (R10.1)" \
    grep -q "$esc" "$OUT"

reset_dl
run second "$H1"
check 0 "$rc" "rerun exits 0"
check 0 "$(downloads)" "rerun performs zero downloads (R5.1/R2 reruns cheap)"
want_card_last "the card closes an up-to-date rerun (R10.4)"

# --- AppArmor components + Ubuntu 24.04+ advisory --------------------------
# The three noarch apparmor components install under the data prefix on Linux.
aa_root="$H1/xdg-data/minimal/apparmor"
want_ok "apparmor profile installed under data prefix"  test -f "$aa_root/minimald"
want_ok "apparmor tunable installed under data prefix"  test -f "$aa_root/tunables/minimald"
want_ok "apparmor loader installed under data prefix"   test -f "$aa_root/install-apparmor-profile.sh"

# The advisory fires only when the userns restriction is active (sysctl reads 1),
# points at the shipped loader, and never elevates — install still exits 0.
printf '1\n' >"$root/sysctl-on"
printf '0\n' >"$root/sysctl-off"

USERNS_SYSCTL="$root/sysctl-on"
run aa_restricted "$H1"
USERNS_SYSCTL=
check 0 "$rc" "install on a restricted host still exits 0 (advice only)"
want_ok "advisory names the userns restriction" \
    grep -q "restricts unprivileged user namespaces" "$OUT"
want_ok "advisory points at the shipped loader with sudo bash" \
    grep -q "sudo bash .*apparmor/install-apparmor-profile.sh" "$OUT"
# The harness bindir is a custom MINIMAL_BIN, outside the tunable's stock
# attachment set, so the advised command must attach it explicitly.
want_ok "advisory carries --path for a custom MINIMAL_BIN" \
    grep -q -- "--path \"$H1/bin/minimald\"" "$OUT"
# The card is the parting block even when the AppArmor advisory is the last note.
want_card_last "the card follows the AppArmor advisory (R10.4)"

USERNS_SYSCTL="$root/sysctl-off"
run aa_unrestricted "$H1"
USERNS_SYSCTL=
want_err "no advisory when the restriction is off (sysctl 0)" \
    grep -q "restricts unprivileged user namespaces" "$OUT"

# A loaded system profile alone is NOT remediation for a custom MINIMAL_BIN:
# the stock tunable does not attach it, so sessions still die and the advisory
# must keep firing (with --path) until the tunables name this binary.
mkdir -p "$root/aa-present"; printf 'profile\n' >"$root/aa-present/minimald"
USERNS_SYSCTL="$root/sysctl-on"; APPARMOR_DIR="$root/aa-present"
run aa_present_unattached "$H1"
want_ok "advisory still fires when the profile is loaded but MINIMAL_BIN unattached" \
    grep -q -- "--path \"$H1/bin/minimald\"" "$OUT"

# ...and is suppressed once the tunables do name it (what the loader's --path
# records under tunables/minimald.d).
mkdir -p "$root/aa-present/tunables/minimald.d"
printf '@{minimald_bin} += %s/bin/minimald\n' "$H1" \
    >"$root/aa-present/tunables/minimald.d/paths"
run aa_attached "$H1"
want_err "no advisory when the tunables attach this MINIMAL_BIN" \
    grep -q "restricts unprivileged user namespaces" "$OUT"

# For the stock prefix (~/.local/bin) the profile's own tunable already
# attaches the binary, so the profile file existing IS remediation.
BIN_OVERRIDE="$H1/.local/bin"
run aa_already_default_bin "$H1"
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

# --- Uninstall: offer to remove the system AppArmor profile ----------------
# A non-interactive uninstall (stdin is /dev/null, not a tty) advises the root
# removal command and never elevates: the seeded system profile survives, while
# the shipped loader is removed by the record walk like any other component.
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
want_ok "uninstall advises the system profile is still loaded" \
    grep -q "system AppArmor profile is still loaded" "$OUT"
want_ok "advisory gives the root removal command" grep -q "apparmor_parser -R" "$OUT"
want_ok "non-interactive uninstall never elevates (profile survives)" \
    test -f "$fake_aa/minimald"
want_err "uninstall removed the shipped apparmor loader" \
    test -e "$HAA_U/xdg-data/minimal/apparmor/install-apparmor-profile.sh"

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

# --- Unit 5: checksum mismatch (R5.3) --------------------------------------
# Point the manifest's minimal hash at a wrong value; artifact stays as-is.
cp "$mock/versions/v1/components" "$root/good-components"
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
        rootfs linux amd64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-arm64.img
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
        libkrun linux amd64 v1 "$h_rootfs" file lib/libkrun.1.dylib versions/v1/rootfs-arm64.img
} >"$mock/versions/v1/components"
H6="$root/h6"; mkdir -p "$H6"
run libdest "$H6"
check 0 "$rc" "lib-prefixed component installs (R4.1)"
want_ok "lib falls back to HOME/.local/lib, no /minimal suffix (R4.1)" \
    test -f "$H6/.local/lib/libkrun.1.dylib"
want_err "lib component is not marked executable (only bin gets +x)" \
    test -x "$H6/.local/lib/libkrun.1.dylib"
cp "$root/good-components" "$mock/versions/v1/components"

# --- Unit 6: install record (R6.1) + PATH advisory (R6.2) ------------------
record="$H1/xdg-state/minimal/installed"
want_ok "install record lists components (R6.1)" grep -q "minimald" "$record"
want_ok "install record lists resolved dest (R6.1)" grep -q "$H1/bin/minimald" "$record"
want_ok "install record lists hash (R6.1)" grep -q "$h_minimald" "$record"
want_ok "symlink row records link:<target> in the hash columns (R6.1)" \
    grep -q "link:min" "$record"

# bin not on PATH -> advisory printed.
run advise_off "$H1"
want_ok "PATH advisory printed when bin absent (R6.2)" grep -q "is not on your PATH" "$OUT"
# bin on PATH -> advisory suppressed. Re-run with bin on PATH via a wrapper env.
OUT="$root/out.advise_on"
set +e
env -i PATH="$stubbin:$H1/bin:/usr/bin:/bin" HOME="$H1" MINIMAL_BIN="$H1/bin" \
    XDG_STATE_HOME="$H1/xdg-state" XDG_DATA_HOME="$H1/xdg-data" XDG_CACHE_HOME="$H1/xdg-cache" \
    MINIMAL_OVERRIDE_INSTALLER_BUCKET="$BUCKET_HOST" \
    STUB_UNAME_S="$PLAT_S" STUB_UNAME_M="$PLAT_M" \
    "$SH" "$installer" >"$OUT" 2>&1
set -e
want_err "PATH advisory suppressed when bin present (R6.2)" grep -q "is not on your PATH" "$OUT"

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
H8="$root/h8"; mkdir -p "$H8"
printf '# my bashrc\n' >"$H8/.bashrc"
printf '# my bash_profile\n' >"$H8/.bash_profile"
run bashboth "$H8"
want_ok "existing .bashrc hooked (R9.2)" grep -q '>>> minimal >>>' "$H8/.bashrc"
want_ok "existing .bash_profile hooked too (R9.2)" grep -q '>>> minimal >>>' "$H8/.bash_profile"
want_ok "user rc content preserved (R9.2)" grep -q '# my bashrc' "$H8/.bashrc"

# zsh and fish get their own rc files (created when missing); an unknown shell
# falls back to .profile with the POSIX init.
H9="$root/h9"; mkdir -p "$H9"
TEST_SHELL=/usr/bin/zsh
run zshinit "$H9"
want_ok ".zshrc created and hooked (R9.2)" grep -q "shell-init/zsh.sh" "$H9/.zshrc"
want_ok "zsh init wires fpath completions (R9.1)" \
    grep -q "fpath=" "$H9/xdg-data/minimal/shell-init/zsh.sh"
want_ok "zsh init self-heals a stale compinit dump (R9.1)" \
    grep -q '_comps\[min\]' "$H9/xdg-data/minimal/shell-init/zsh.sh"
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
TEST_SHELL=

# A manifest without the min CLI (data-only) skips completions, non-fatally.
want_ok "completions skipped when min absent (R9.3)" \
    grep -qE "completions +skipped" "$root/out.datadest"

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
        libkrun darwin arm64 v1 "$h_rootfs" file lib/libkrun.1.dylib versions/v1/rootfs-arm64.img
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

# R9.4 — a record without a completions-zsh row (the data-only install above)
# must NOT cost the user their compinit dump: the cache is only cleared when
# the installer actually put min into it.
printf '# untouched user cache\n' >"$H5/.zcompdump"
run u_datadump "$H5" --uninstall
check 0 "$rc" "data-only uninstall exits 0"
want_ok "dump kept when no zsh completions were installed (R9.4)" \
    grep -q '# untouched user cache' "$H5/.zcompdump"

# --- gvproxy -> gvproxy-min rename migration --------------------------------

# The switch binary moved from bin/gvproxy to bin/gvproxy-min (the bin prefix is
# on PATH and podman/crc ship their own gvproxy). The old dest is in no
# manifest any more, so nothing would ever revisit it — the install has to undo
# it explicitly, on the same bytes-still-ours terms as uninstall.
H15="$root/h15"; mkdir -p "$H15"
run gvren_seed "$H15"
check 0 "$rc" "rename-migration seed install exits 0"

# Seed what a pre-rename install left behind: the binary plus its record row.
gvren_rec="$H15/xdg-state/minimal/installed"
printf 'old-gvproxy-body\n' >"$H15/bin/gvproxy"
gvren_h="$(hash_file "$H15/bin/gvproxy")"
printf 'gvproxy\t%s\t%s\t%s\n' "$H15/bin/gvproxy" "$gvren_h" "$gvren_h" >>"$gvren_rec"

run gvren "$H15"
check 0 "$rc" "rename-migration install exits 0"
want_err "stale bin/gvproxy removed on upgrade" test -e "$H15/bin/gvproxy"
want_ok "removal announced" grep -q "renamed to gvproxy-min" "$OUT"

run gvren_rerun "$H15"
check 0 "$rc" "rerun after migration exits 0"
want_err "rerun says nothing about gvproxy" grep -q "renamed to gvproxy-min" "$OUT"

# A manifest that STILL ships a `gvproxy` component is not a rename: the file
# on disk is the one this very run installed, so the migration must not touch
# it. Channels advance independently, so a post-rename installer WILL be
# pointed at a pre-rename manifest — deleting there would leave the host with
# no switch binary at all, on every single run.
H17="$root/h17"; mkdir -p "$H17"
run gvship_seed "$H17"
check 0 "$rc" "still-ships-gvproxy seed install exits 0"
gvship_rec="$H17/xdg-state/minimal/installed"
printf 'shipped-gvproxy-body\n' >"$H17/bin/gvproxy"
gvship_h="$(hash_file "$H17/bin/gvproxy")"
printf 'gvproxy\t%s\t%s\t%s\n' "$H17/bin/gvproxy" "$gvship_h" "$gvship_h" >>"$gvship_rec"
# Make THIS run install a gvproxy component too, as a pre-rename manifest does.
printf 'shipped-gvproxy-body\n' >"$mock/versions/v1/gvproxy-linux-amd64"
h_gv="$(hash_file "$mock/versions/v1/gvproxy-linux-amd64")"
{
    cat "$mock/versions/v1/components"
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
        gvproxy linux amd64 v1 "$h_gv" file bin/gvproxy versions/v1/gvproxy-linux-amd64
} >"$mock/versions/v1/components.new"
mv "$mock/versions/v1/components.new" "$mock/versions/v1/components"
run gvship "$H17"
check 0 "$rc" "install against a manifest that still ships gvproxy exits 0"
want_ok "the just-installed bin/gvproxy survives" test -f "$H17/bin/gvproxy"
want_err "no removal is announced" grep -q "renamed to gvproxy-min" "$OUT"
write_manifest 1

# A gvproxy the user replaced (podman's, say) is NOT ours to delete: the hash
# no longer matches what we recorded writing, so it is kept and reported.
H16="$root/h16"; mkdir -p "$H16"
run gvkeep_seed "$H16"
check 0 "$rc" "rename-keep seed install exits 0"
gvkeep_rec="$H16/xdg-state/minimal/installed"
printf 'ours-when-installed\n' >"$H16/bin/gvproxy"
gvkeep_h="$(hash_file "$H16/bin/gvproxy")"
printf 'gvproxy\t%s\t%s\t%s\n' "$H16/bin/gvproxy" "$gvkeep_h" "$gvkeep_h" >>"$gvkeep_rec"
printf 'the-users-own-gvproxy\n' >"$H16/bin/gvproxy"

run gvkeep "$H16"
check 0 "$rc" "rename-keep install exits 0"
want_ok "a user-replaced gvproxy is kept" test -f "$H16/bin/gvproxy"
want_ok "kept content is untouched" grep -q 'the-users-own-gvproxy' "$H16/bin/gvproxy"
want_ok "keeping it is announced" grep -q "modified since install" "$OUT"

# ===========================================================================
echo "# ---"
printf '# %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
