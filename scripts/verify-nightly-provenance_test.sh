#!/usr/bin/env bash
#
# verify-nightly-provenance_test.sh — test harness for
# scripts/verify-nightly-provenance.sh.
#
# `gh` is stubbed by prepending a temp dir to PATH containing a fake that
# records its arguments (so the API path can be asserted) and replays canned
# run lines / exit codes from files — no network, no auth. Run directly or via
# `just test-promote-gate`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/verify-nightly-provenance.sh"
[ -f "$script" ] || { echo "cannot find verify-nightly-provenance.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-provtest)"
trap 'rm -rf "$root"' EXIT

mkdir -p "$root/bin"
cat >"$root/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"${GH_STUB_ARGS:?}"
code="${GH_STUB_EXIT:-0}"
[ "$code" -eq 0 ] || exit "$code"
cat "${GH_STUB_RUNS:?}"
EOF
chmod +x "$root/bin/gh"
export PATH="$root/bin:$PATH"
export GH_STUB_ARGS="$root/gh-args"
export GH_STUB_RUNS="$root/runs"
unset GH_STUB_EXIT

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# expect <want_rc> <want_substring> <description> -- <command...>
# Runs the command, asserting its exit code and that combined output contains
# the substring. The command is spelled out in full (not just script args) so
# tests can wrap with `env -u`.
expect() {
    local want_rc="$1" want_msg="$2" desc="$3"; shift 3
    [ "$1" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -eq "$want_rc" ] && [[ "$out" == *"$want_msg"* ]]; then
        ok "$desc"
    else
        bad "$desc (want rc=$want_rc got rc=$rc; out: $out)"
    fi
}

# One successful nightly run per line: "<full head_sha> <run url>".
sha_a="dd20ee67e6349ca8573df43e16abd407a617a0df"
sha_b="0badf00d5eed5eed5eed5eed5eed5eed5eed5eed"
cat >"$GH_STUB_RUNS" <<EOF
$sha_a https://example.test/runs/1
$sha_b https://example.test/runs/2
EOF
: >"$GH_STUB_ARGS"

# ── Argument and input validation (no gh call expected) ──────────────────────
expect 0 "Usage" "--help prints usage" \
    -- "$script" --help
expect 1 "missing --sha" "missing --sha dies" \
    -- "$script" --repo acme/widgets
expect 1 "missing --repo" "missing --repo (and GITHUB_REPOSITORY) dies" \
    -- env -u GITHUB_REPOSITORY "$script" --sha dd20ee67
expect 1 "missing value for --sha" "valueless --sha dies cleanly under set -u" \
    -- "$script" --sha
expect 1 "missing value for --workflow" "valueless --workflow dies cleanly" \
    -- "$script" --sha dd20ee67 --repo acme/widgets --workflow
expect 1 "unknown argument" "unknown flag dies" \
    -- "$script" --sha dd20ee67 --repo acme/widgets --bogus
expect 1 "non-hex" "non-hex sha dies" \
    -- "$script" --sha 'dd20ee6!' --repo acme/widgets
expect 1 "too short" "7-char sha is rejected (staged format is 8+)" \
    -- "$script" --sha dd20ee6 --repo acme/widgets
expect 1 "longer than a full" "41-char sha is rejected" \
    -- "$script" --sha "${sha_a}0" --repo acme/widgets
if [ ! -s "$GH_STUB_ARGS" ]; then
    ok "validation failures never reach gh"
else
    bad "validation failures never reach gh (gh was called)"
fi

# ── Matching against successful runs ─────────────────────────────────────────
expect 0 "https://example.test/runs/1" "8-char staged sha matches its run" \
    -- "$script" --sha dd20ee67 --repo acme/widgets
expect 0 "https://example.test/runs/1" "full 40-char sha matches its run" \
    -- "$script" --sha "$sha_a" --repo acme/widgets
expect 0 "https://example.test/runs/2" "match on a later line is found" \
    -- "$script" --sha 0badf00d --repo acme/widgets
expect 0 "https://example.test/runs/1" "uppercase input is normalized" \
    -- "$script" --sha DD20EE67 --repo acme/widgets
expect 1 "was not built by a successful" "unknown sha fails and mentions the override" \
    -- "$script" --sha deadbeef --repo acme/widgets
expect 1 "provenance override" "failure message points at the emergency override" \
    -- "$script" --sha deadbeef --repo acme/widgets
expect 1 "was not built" "full sha differing only in its last char fails" \
    -- "$script" --sha "${sha_a%?}e" --repo acme/widgets

# The API path must target the requested repo and workflow file.
: >"$GH_STUB_ARGS"
"$script" --sha dd20ee67 --repo acme/widgets --workflow custom.yml >/dev/null 2>&1
if grep -q "repos/acme/widgets/actions/workflows/custom.yml/runs?status=success" "$GH_STUB_ARGS"; then
    ok "queries the requested repo and workflow"
else
    bad "queries the requested repo and workflow (args: $(cat "$GH_STUB_ARGS"))"
fi

# ── gh failure propagation ───────────────────────────────────────────────────
expect 22 "" "gh API failure propagates the failing exit code" \
    -- env GH_STUB_EXIT=22 "$script" --sha dd20ee67 --repo acme/widgets

# Empty run history (no successful nightly ever) is a plain no-match failure.
: >"$GH_STUB_RUNS"
expect 1 "was not built" "empty run history fails closed" \
    -- "$script" --sha dd20ee67 --repo acme/widgets

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
