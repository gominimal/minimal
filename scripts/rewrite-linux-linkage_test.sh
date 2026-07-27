#!/usr/bin/env bash
#
# rewrite-linux-linkage_test.sh — test harness for
# scripts/rewrite-linux-linkage.sh.
#
# `patchelf` is stubbed by prepending a temp dir to PATH with a fake that models
# the real tool's state: --print-{needed,rpath,soname} replay canned per-file
# values, and --set-rpath updates the value a later --print-rpath returns. No
# ELF binaries and no patchelf install are needed, so the RUNPATH logic and
# every hard-fail path are exercised on any host — including macOS, where the
# real script can never run. Run directly or via `just test-linkage`.
#
# `$ORIGIN` is an ELF loader token: the expected values below are deliberately
# single-quoted so they compare against the literal the script must record.
# shellcheck disable=SC2016
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/rewrite-linux-linkage.sh"
[ -f "$script" ] || { echo "cannot find rewrite-linux-linkage.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-linktest)"
trap 'rm -rf "$root"' EXIT

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (want [$1] got [$2])"; fi; }

# --- patchelf stub ---------------------------------------------------------

mkdir -p "$root/bin"
cat >"$root/bin/patchelf" <<'EOF'
#!/usr/bin/env bash
# Canned state lives in $STUB_STATE/<basename>.<field>; --set-rpath writes it
# back so the script's own read-after-write sees the update, as with the real
# tool.
set -u
state="${STUB_STATE:?}"
field_file() { printf '%s/%s.%s\n' "$state" "$(basename "$2")" "$1"; }
case "$1" in
    --print-needed) cat "$(field_file needed "$2")" 2>/dev/null || exit 1 ;;
    --print-rpath)  cat "$(field_file rpath  "$2")" 2>/dev/null ;;
    --print-soname) cat "$(field_file soname "$2")" 2>/dev/null ;;
    --set-rpath)    printf '%s\n' "$2" >"$(field_file rpath "$3")" ;;
    *) echo "stub patchelf: unhandled $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$root/bin/patchelf"

# Build a scenario: a minvmd binary plus the libkrun pair, with canned patchelf
# state. Any field can be overridden per-scenario before the run.
scenario() {
    s="$root/$1"; rm -rf "$s"; mkdir -p "$s/state" "$s/lib"
    : >"$s/minvmd"
    : >"$s/lib/libkrun.so.1"
    : >"$s/lib/libkrunfw.so.5"
    printf 'libkrun.so.1\nlibc.so.6\n' >"$s/state/minvmd.needed"
    printf '$ORIGIN:/usr/local/lib:/usr/lib\n' >"$s/state/minvmd.rpath"
    printf 'libkrun.so.1\n' >"$s/state/libkrun.so.1.soname"
    printf '\n' >"$s/state/libkrun.so.1.rpath"
    printf 'libkrunfw.so.5\n' >"$s/state/libkrunfw.so.5.soname"
}

run() {
    s="$root/$1"
    OUT="$root/out.$1"
    PATH="$root/bin:$PATH" STUB_STATE="$s/state" \
        bash "$script" "$s/minvmd" "$s/lib" >"$OUT" 2>&1
    rc=$?
}

rpath_of() { cat "$root/$1/state/$2.rpath"; }

echo "# rewrite-linux-linkage.sh tests"

# --- happy path ------------------------------------------------------------

scenario happy
run happy
check 0 "$rc" "happy path exits 0"
check '$ORIGIN:$ORIGIN/../lib:/usr/local/lib:/usr/lib' "$(rpath_of happy minvmd)" \
    "minvmd gains \$ORIGIN/../lib, system dirs preserved in order"
check '$ORIGIN' "$(rpath_of happy libkrun.so.1)" \
    "libkrun gains \$ORIGIN so its dlopen finds libkrunfw"

# Re-running over already-rewritten state must be a no-op, not a second insert:
# the release job and a manual re-run both hit this.
run happy
check 0 "$rc" "re-run exits 0"
check '$ORIGIN:$ORIGIN/../lib:/usr/local/lib:/usr/lib' "$(rpath_of happy minvmd)" \
    "re-run leaves minvmd RUNPATH unchanged (idempotent)"
check '$ORIGIN' "$(rpath_of happy libkrun.so.1)" "re-run leaves libkrun RUNPATH unchanged"

# --- the stub-backend trap -------------------------------------------------

# A minvmd built with LIBKRUN_PREFIX unset silently links the stub impl and has
# no libkrun DT_NEEDED. Shipping it would install a VM backend that cannot boot
# anything, so this must fail loudly at release time.
scenario stubbed
printf 'libc.so.6\n' >"$root/stubbed/state/minvmd.needed"
run stubbed
check 1 "$rc" "a stub-linked minvmd fails"
if grep -q "stub" "$OUT"; then ok "stub failure names the cause"; else bad "stub failure names the cause"; fi

# --- soname drift ----------------------------------------------------------

# A libkrun major bump changes the soname; the lib/ dests in stage-release.sh
# would then point at a filename nothing loads. Fail here instead.
scenario sonamebump
printf 'libkrun.so.2\nlibc.so.6\n' >"$root/sonamebump/state/minvmd.needed"
run sonamebump
check 1 "$rc" "a libkrun soname bump fails"
if grep -q "stage-release" "$OUT"; then ok "soname failure points at stage-release.sh"; else bad "soname failure points at stage-release.sh"; fi

scenario fwbump
printf 'libkrunfw.so.6\n' >"$root/fwbump/state/libkrunfw.so.5.soname"
run fwbump
check 1 "$rc" "a libkrunfw soname mismatch fails"

# --- ephemeral prefix leak -------------------------------------------------

# build.rs drops the materialized prefix on a Linux release build; if one ever
# survives, it points at a directory that exists only on the runner.
scenario leak
printf '$ORIGIN:/home/runner/.krun:/usr/lib\n' >"$root/leak/state/minvmd.rpath"
run leak
check 1 "$rc" "a leaked build prefix in RUNPATH fails"
if grep -q "ephemeral" "$OUT"; then ok "leak failure names the ephemeral prefix"; else bad "leak failure names the ephemeral prefix"; fi

# --- missing libraries -----------------------------------------------------

scenario nolib
rm -f "$root/nolib/lib/libkrun.so.1"
run nolib
check 1 "$rc" "a missing libkrun under the lib dir fails"

scenario nofw
rm -f "$root/nofw/lib/libkrunfw.so.5"
run nofw
check 1 "$rc" "a missing libkrunfw under the lib dir fails"

# --- soname dispatch keys on the file, not the path ------------------------

# A lib dir whose own path contains "krunfw" must not make libkrun be checked
# against libkrunfw's soname. The old `case "$lib" in *krunfw*` matched the
# whole resolved path and aborted the release citing a bump that never happened.
scenario krunfwpath
mv "$root/krunfwpath/lib" "$root/krunfwpath/libkrunfw-1.5"
sed_dir="$root/krunfwpath/libkrunfw-1.5"
PATH="$root/bin:$PATH" STUB_STATE="$root/krunfwpath/state" \
    bash "$script" "$root/krunfwpath/minvmd" "$sed_dir" >"$root/out.krunfwpath" 2>&1
check 0 "$?" "a lib dir path containing 'krunfw' still checks libkrun's own soname"

# --- leaked build prefix in the SHIPPED libkrun ----------------------------

# The upstream .so carries its own build host's RUNPATH and we prepend to it,
# so the same leak check minvmd gets must apply here or an absolute build path
# ships to users.
scenario libleak
printf '/home/builder/.krun/lib\n' >"$root/libleak/state/libkrun.so.1.rpath"
run libleak
check 1 "$rc" "a leaked build prefix in libkrun's own RUNPATH fails"
if grep -q "ephemeral" "$OUT"; then ok "libkrun leak failure names the ephemeral prefix"; else bad "libkrun leak failure names the ephemeral prefix"; fi

# --- libkrun with a pre-existing RUNPATH -----------------------------------

# The upstream .so may already carry one; $ORIGIN is prepended, not substituted,
# so whatever it resolved before still resolves.
scenario prerpath
printf '/opt/vendor/lib\n' >"$root/prerpath/state/libkrun.so.1.rpath"
run prerpath
check 0 "$rc" "a libkrun with an existing RUNPATH exits 0"
check '$ORIGIN:/opt/vendor/lib' "$(rpath_of prerpath libkrun.so.1)" \
    "\$ORIGIN is prepended, existing entries kept"

# --- minvmd with no RUNPATH at all -----------------------------------------

scenario norpath
: >"$root/norpath/state/minvmd.rpath"
run norpath
check 0 "$rc" "a minvmd with an empty RUNPATH exits 0"
check '$ORIGIN:$ORIGIN/../lib' "$(rpath_of norpath minvmd)" \
    "both binary-relative entries are set from empty"

echo "# ---"
printf '# %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
