#!/usr/bin/env bash
#
# package-version_test.sh — test harness for scripts/package-version.sh.
#
# Asserts the per-format normalization table, that a released semver is the
# identity in every format (the guarantee that keeps the stable nfpm packages
# byte-identical), and the refusals. When the real package managers are on
# PATH it additionally PROVES the ordering claims empirically — dpkg for the
# deb `~` rule and apk for the apk shape — and skips those checks where the
# tool is absent, so a dev host without them still exercises the strings. Run
# directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/package-version.sh"
[ -f "$script" ] || { echo "cannot find package-version.sh next to test" >&2; exit 1; }

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# normalize <format> <version> — the script's stdout, or empty on failure.
normalize() { "$script" --format "$1" "$2" 2>/dev/null; }

# want <format> <input> <expected>
want() {
    local fmt="$1" in="$2" exp="$3" out
    out="$(normalize "$fmt" "$in")"
    if [ "$out" = "$exp" ]; then ok "$fmt: $in -> $exp"; else bad "$fmt: $in -> want '$exp', got '$out'"; fi
}

# --- the normalization table --------------------------------------------------

DEV=0.6.0-dev.10.g8e7e72c2
want deb  "$DEV" 0.6.0~dev.10.g8e7e72c2
want rpm  "$DEV" 0.6.0~dev.10.g8e7e72c2
want apk  "$DEV" 0.6.0_dev.10.g8e7e72c2
want aur  "$DEV" 0.6.0.dev.10.g8e7e72c2
want brew "$DEV" "$DEV"

# The prerelease-tag shape (a build past v0.6.0-rc1) normalizes the same way.
RC=0.6.0-rc1.dev.4.gabc12345
want deb  "$RC" 0.6.0~rc1.dev.4.gabc12345
want aur  "$RC" 0.6.0.rc1.dev.4.gabc12345

# A released semver is the identity in every format.
for fmt in deb rpm apk aur brew; do
    want "$fmt" 0.6.0 0.6.0
done

# Build metadata (the +dirty marker) survives every format.
want deb  0.6.0-dev.10.g8e7e72c2+dirty 0.6.0~dev.10.g8e7e72c2+dirty
want brew 0.6.0+dirty 0.6.0+dirty

# --- empirical ordering, where the real tools exist ---------------------------

# deb: `~` must sort below the bare release, and a higher dev count above a
# lower one. dpkg is the only authority for this; skip where absent.
if command -v dpkg >/dev/null 2>&1; then
    a="$(normalize deb 0.6.0-dev.10.g8e7e72c2)"
    b="$(normalize deb 0.6.0-dev.9.gdeadbeef)"
    if dpkg --compare-versions "$a" gt "$b"; then ok "dpkg: $a sorts above $b"; else bad "dpkg: $a should sort above $b"; fi
    if dpkg --compare-versions "$a" lt 0.6.0; then ok "dpkg: $a sorts below the stable 0.6.0"; else bad "dpkg: $a should sort below 0.6.0"; fi
else
    echo "note - dpkg not on PATH; skipping the deb ordering proof"
fi

# apk: prove the channel shape is accepted AND monotonic. This is the fiddliest
# normalization in the table — apk has no `~` and uses `-r<N>` as its own
# revision separator — so the shape is asserted against the real parser rather
# than trusted. Skip where apk is absent.
if command -v apk >/dev/null 2>&1; then
    a="$(normalize apk 0.6.0-dev.10.g8e7e72c2)"
    b="$(normalize apk 0.6.0-dev.9.gdeadbeef)"
    if apk version -t "$a" >/dev/null 2>&1 && apk version -t "$b" >/dev/null 2>&1; then
        ok "apk accepts the channel version shape ($a)"
        if [ "$(apk version -t "$a" "$b")" = ">" ]; then ok "apk: $a sorts above $b"; else bad "apk: $a should sort above $b"; fi
    else
        bad "apk rejects the channel version shape ($a or $b) — use the 0.6.0_git<N> fallback (see the script header)"
    fi
else
    echo "note - apk not on PATH; skipping the apk ordering proof"
fi

# --- refusals -----------------------------------------------------------------

expect() {
    local want_rc="$1" want_msg="$2" desc="$3"; shift 3
    [ "${1:-}" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -eq "$want_rc" ] && [[ "$out" == *"$want_msg"* ]]; then
        ok "$desc"
    else
        bad "$desc (want rc=$want_rc and '$want_msg'; got rc=$rc, out: $out)"
    fi
}

expect 1 "unknown --format" "an unknown format is refused" -- "$script" --format msi 0.6.0
expect 1 "--format is required" "a missing format is refused" -- "$script" 0.6.0
expect 1 "VERSION is required" "a missing version is refused" -- "$script" --format deb
expect 1 "must not carry the v prefix" "a v-prefixed version is refused" -- "$script" --format deb v0.6.0
expect 1 "not a canonical" "a bare sha is refused" -- "$script" --format deb 8e7e72c2
expect 1 "not a canonical" "a two-part version is refused" -- "$script" --format deb 0.6

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
