#!/bin/sh
#
# install_test.sh — POSIX-sh test harness for scripts/install.sh.
#
# Exercises Units 1–6 of docs/specs/07-spec-installer against a local mock
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

# Two platform-diverse artifacts with padded columns and comment/blank lines, to
# prove awk field-splitting survives padding (R3.1/R3.3).
printf 'linux-amd64-minimald-body\n'  >"$mock/versions/v1/minimald-linux-amd64"
printf 'linux-amd64-minimal-body\n'   >"$mock/versions/v1/minimal-linux-amd64"
printf 'darwin-arm64-minimal-body\n'  >"$mock/versions/v1/minimal-darwin-arm64"
printf 'darwin-arm64-rootfs-body\n'   >"$mock/versions/v1/rootfs-arm64.img"

h_minimald="$(hash_file "$mock/versions/v1/minimald-linux-amd64")"
h_minimal="$(hash_file "$mock/versions/v1/minimal-linux-amd64")"
h_dmin="$(hash_file "$mock/versions/v1/minimal-darwin-arm64")"
h_rootfs="$(hash_file "$mock/versions/v1/rootfs-arm64.img")"

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
            minimal linux amd64 v1 "$h_minimal" file bin/minimal versions/v1/minimal-linux-amd64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            minimal darwin arm64 v1 "$h_dmin" file bin/minimal versions/v1/minimal-darwin-arm64
        printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
            rootfs darwin arm64 v1 "$h_rootfs" file data/rootfs.img versions/v1/rootfs-arm64.img
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

# Stub `codesign`: the real tool needs a valid Mach-O (our mock artifacts are
# plain files) and is macOS-only. It records the signed path and APPENDS to the
# file, emulating how signing rewrites the binary so its hash diverges from the
# manifest — which is exactly what the skip oracle must tolerate.
cat >"$stubbin/codesign" <<STUB
#!/bin/sh
f=
for a in "\$@"; do f="\$a"; done   # target is the last argument
printf '%s\n' "\$f" >>"$root/codesign.calls"
printf 'adhoc-signature\n' >>"\$f"
STUB
chmod +x "$stubbin/codesign"

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

# run <label> <homeprefix> [args...] ; sets rc, captures combined output in $OUT.
OUT=
run() {
    label="$1"; hp="$2"; shift 2
    OUT="$root/out.$label"
    set +e
    env -i \
        PATH="$stubbin:/usr/bin:/bin" \
        HOME="$hp" \
        MINIMAL_BIN="$hp/bin" \
        XDG_DATA_HOME="$hp/xdg-data" \
        XDG_STATE_HOME="$hp/xdg-state" \
        XDG_CACHE_HOME="$hp/xdg-cache" \
        MINIMAL_OVERRIDE_INSTALLER_BUCKET="$BUCKET_HOST" \
        STUB_UNAME_S="$PLAT_S" \
        STUB_UNAME_M="$PLAT_M" \
        "$SH" "$installer" "$@" >"$OUT" 2>&1
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

reset_dl
run second "$H1"
check 0 "$rc" "rerun exits 0"
check 0 "$(downloads)" "rerun performs zero downloads (R5.1/R2 reruns cheap)"

# Corrupt one on-disk binary -> only that component re-fetches.
printf 'tampered\n' >"$H1/bin/minimald"
reset_dl
run third "$H1"
check 0 "$rc" "rerun after tamper exits 0"
check 1 "$(downloads)" "only the changed component re-downloads"
check "$h_minimald" "$(hash_file "$H1/bin/minimald")" "tampered binary restored"

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
want_err "no file installed on mismatch" test -e "$H2/bin/minimal"
if ls "$H2/bin/"minimal.tmp.* >/dev/null 2>&1
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

# --- Unit 5 (darwin): dequarantine + ad-hoc codesign for bin files ---------
# Force a darwin/arm64 platform (via the uname stub) so this runs on every lane.
# The applicable rows are then `minimal` (bin) and `rootfs` (data). A bin file
# must be quarantine-stripped and ad-hoc codesigned; a data file must not be.
PLAT_S=Darwin
PLAT_M=arm64
: >"$root/codesign.calls"
: >"$root/xattr.calls"
HD="$root/hd"; mkdir -p "$HD"
reset_dl
run darwin1 "$HD"
check 0 "$rc" "darwin install exits 0"
want_ok "darwin bin component installed" test -f "$HD/bin/minimal"
want_ok "quarantine stripped from bin (xattr)" grep -q "com.apple.quarantine" "$root/xattr.calls"
want_ok "bin file ad-hoc codesigned" grep -q "/bin/minimal" "$root/codesign.calls"
want_err "data component not codesigned" grep -q "rootfs" "$root/codesign.calls"

# A darwin `lib` dylib gets the SAME Mach-O treatment as a bin file — quarantine
# strip + ad-hoc codesign (the plain else-branch sign, no minvmd entitlement) —
# so the shipped libkrun.1.dylib is loadable. Isolated home + one-off manifest
# with a single darwin lib row, so it doesn't perturb the rerun counts below.
{
    printf '# format: 1\n'
    printf '# c o a v s k d s\n'
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
        libkrun darwin arm64 v1 "$h_rootfs" file lib/libkrun.1.dylib versions/v1/rootfs-arm64.img
} >"$mock/versions/v1/components"
: >"$root/codesign.calls"; : >"$root/xattr.calls"
HDL="$root/hdl"; mkdir -p "$HDL"
reset_dl
run darwinlib "$HDL"
check 0 "$rc" "darwin lib install exits 0"
want_ok "darwin lib dylib installed" test -f "$HDL/.local/lib/libkrun.1.dylib"
want_ok "quarantine stripped from lib dylib (xattr)" \
    grep -q "com.apple.quarantine" "$root/xattr.calls"
want_ok "lib dylib ad-hoc codesigned" \
    grep -q "/lib/libkrun.1.dylib" "$root/codesign.calls"
cp "$root/good-components" "$mock/versions/v1/components"   # restore
: >"$root/codesign.calls"; : >"$root/xattr.calls"

# Signing diverged the on-disk bytes from the manifest hash. A rerun must still
# recognize the component as installed (via the recorded hash) and not download
# or re-sign it — otherwise macOS reruns would never be cheap (Goal 2).
reset_dl
: >"$root/codesign.calls"
run darwin2 "$HD"
check 0 "$rc" "darwin rerun exits 0"
check 0 "$(downloads)" "signed darwin bin: rerun downloads nothing"
want_err "signed darwin bin: not re-codesigned on rerun" grep -q "/bin/minimal" "$root/codesign.calls"

# A NEW release of a signed darwin bin (its manifest sha256 changes) must
# re-download and re-sign — NOT be judged up to date because the old signed
# bytes still equal the previously-recorded installed hash. The skip-by-record
# path is keyed on the manifest hash for exactly this staleness case.
printf 'darwin-arm64-minimal-body-v2\n' >"$mock/versions/v1/minimal-darwin-arm64-v2"
h_dmin2="$(hash_file "$mock/versions/v1/minimal-darwin-arm64-v2")"
awk -v h="$h_dmin2" \
    '$1=="minimal" && $2=="darwin" {$5=h; $8="versions/v1/minimal-darwin-arm64-v2"} {print}' \
    "$root/good-components" >"$mock/versions/v1/components"
reset_dl
: >"$root/codesign.calls"
run darwin3 "$HD"
check 0 "$rc" "darwin new-version rerun exits 0"
check 1 "$(downloads)" "new manifest hash re-downloads the signed darwin bin (staleness fix)"
want_ok "new darwin bin is re-codesigned" grep -q "/bin/minimal" "$root/codesign.calls"
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
want_err "uninstall removed minimal (R7.3)" test -e "$HU/bin/minimal"
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
want_ok "keep is reported (R7.3)" grep -q "kept (modified" "$OUT"
want_err "unmodified sibling still removed (R7.3)" test -e "$HU2/bin/minimal"
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

# ===========================================================================
echo "# ---"
printf '# %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
