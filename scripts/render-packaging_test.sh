#!/usr/bin/env bash
#
# render-packaging_test.sh — test harness for scripts/render-packaging.sh.
#
# Exercises the renderer against fixture templates: the happy path (tokens
# stamped, values preserved literally — including `&`, which bash >= 5.2's
# patsub_replacement would otherwise expand back to the match), and every way
# it must refuse to write a half-stamped file (unset or empty variable,
# malformed leftover tokens). Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/render-packaging.sh"
[ -f "$script" ] || { echo "cannot find render-packaging.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-rendertest)"
trap 'rm -rf "$root"' EXIT

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# expect <want_rc> <want_substring> <description> -- <command...>
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

template="$root/t.tmpl"
output="$root/out"

# --- happy path -------------------------------------------------------------

cat >"$template" <<'EOF'
pkgver=@@PKGVER@@
_bucket="@@BUCKET_URL@@"
maintainer="@@MAINTAINER@@"
EOF

out="$(
    PKGVER=0.5.4 \
    BUCKET_URL='https://example.test/minimal-one' \
    MAINTAINER='Minimal Packagers <pkg@minimal.dev> & friends' \
        "$script" "$template" "$output" && cat "$output"
)"
if [[ "$out" == *'pkgver=0.5.4'* ]] \
    && [[ "$out" == *'_bucket="https://example.test/minimal-one"'* ]] \
    && [[ "$out" == *'Minimal Packagers <pkg@minimal.dev> & friends'* ]] \
    && ! grep -q '@@' <<<"$out"; then
    ok "tokens stamp literally, including & in the value"
else
    bad "tokens stamp literally, including & in the value (out: $out)"
fi

# An empty variable must fail the run — printenv exits 0 for set-but-empty, so
# only the length check catches it. Left unstamped, a checksum or version
# token would ship as the empty string.
expect 1 "unset or empty" "empty variable fails the run" -- \
    env -u PKGVER PKGVER= BUCKET_URL=x MAINTAINER=m "$script" "$template" "$output"

expect 1 "environment variable MAINTAINER is unset or empty" "unset variable fails the run" -- \
    env -u MAINTAINER PKGVER=0.5.4 BUCKET_URL=x "$script" "$template" "$output"

# --- refuses to write a half-stamped file ------------------------------------

cat >"$template" <<'EOF'
ok=@@PKGVER@@
bad=@@lower-case@@
EOF

rm -f "$output"
expect 1 "unrendered token(s) remain" "malformed token is refused" -- \
    env PKGVER=0.5.4 "$script" "$template" "$output"
if [ -e "$output" ]; then
    bad "failed render must not write the output file"
else
    ok "failed render writes no output file"
fi

# A malformed token only (no unrendered @@..@@ left) is the leftover scan's job.
cat >"$template" <<'EOF'
weird=@@ONE@TWO@@
EOF
expect 1 "unrendered token(s) remain" "token with embedded @ is refused" -- \
    env PKGVER=0.5.4 "$script" "$template" "$output"

# --- argument handling --------------------------------------------------------

expect 1 "usage" "missing output argument fails" -- env PKGVER=0.5.4 "$script" "$template"
expect 1 "no such template file" "missing template fails" -- \
    env PKGVER=0.5.4 "$script" "$root/absent.tmpl" "$output"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
