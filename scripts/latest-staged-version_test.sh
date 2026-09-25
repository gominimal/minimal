#!/usr/bin/env bash
#
# latest-staged-version_test.sh — test harness for
# scripts/latest-staged-version.sh.
#
# `gcloud` is stubbed by prepending a temp dir to PATH: the fake replays a
# canned `gcloud storage ls -l` listing from a file — no network, no auth.
# The listing exercises the two ways the resolution can go wrong: a semver
# packaging row staged newest (must NOT hijack the default), and rows whose
# creation-time column sorts differently from their name order. Run directly
# or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/latest-staged-version.sh"
[ -f "$script" ] || { echo "cannot find latest-staged-version.sh next to test" >&2; exit 1; }
# shellcheck disable=SC1091  # dynamic path: testlib.sh sits beside this harness
. "$here/testlib.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-latesttest)"
trap 'rm -rf "$root"' EXIT

mkdir -p "$root/bin"
cat >"$root/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
# Replays the canned listing; a --exit file makes the listing fail (empty
# bucket error path).
if [ -n "${GCLOUD_STUB_EXIT:-}" ] && [ "$GCLOUD_STUB_EXIT" != "0" ]; then
    echo "gcloud: simulated failure" >&2
    exit "$GCLOUD_STUB_EXIT"
fi
cat "${GCLOUD_STUB_LISTING:?}"
exit 0
EOF
chmod +x "$root/bin/gcloud"
export PATH="$root/bin:$PATH"
export GCLOUD_STUB_LISTING="$root/listing"

# listing <line>... — write the canned `gcloud storage ls -l` output.
# Format: `SIZE  CREATION_TIME  NAME` (name last), as gcloud prints it.
listing() {
    : >"$GCLOUD_STUB_LISTING"
    local line
    for line in "$@"; do
        printf '%s\n' "$line" >>"$GCLOUD_STUB_LISTING"
    done
}

run() {
    "$script" --bucket gs://stub
}

# --- the semver row must not hijack the default -----------------------------

# Tag-push staging order: the semver packaging row lands AFTER its sha row, so
# it sorts newest. The default target is still the commit.
listing \
    "1234  2026-01-01T00:00:00Z  gs://minimal-one/versions/abc12345/components" \
    "1234  2026-01-02T00:00:00Z  gs://minimal-one/versions/0.5.4/components"
expect 0 "" "semver row newest does not hijack the default" -- run
out="$(run 2>/dev/null)"
if [ "$out" = "abc12345" ]; then ok "newest commit sha is chosen"; else bad "newest commit sha is chosen (got '$out')"; fi

# Newest by creation time wins even when it is not last in the listing.
listing \
    "1234  2026-03-01T00:00:00Z  gs://minimal-one/versions/11111111/components" \
    "1234  2026-02-01T00:00:00Z  gs://minimal-one/versions/22222222/components"
out="$(run 2>/dev/null)"
if [ "$out" = "11111111" ]; then ok "creation time, not listing order, decides"; else bad "creation time, not listing order, decides (got '$out')"; fi

# A row with an exotic staged name (neither sha-like nor semver) is ignored.
listing \
    "1234  2026-04-01T00:00:00Z  gs://minimal-one/versions/NOT-A-SHA/components" \
    "1234  2026-01-01T00:00:00Z  gs://minimal-one/versions/abc12345/components"
out="$(run 2>/dev/null)"
if [ "$out" = "abc12345" ]; then ok "non-sha non-semver rows are ignored"; else bad "non-sha non-semver rows are ignored (got '$out')"; fi

# --- empty bucket fails loudly ----------------------------------------------

listing
expect 1 "no staged commit versions" "empty bucket fails loudly" -- run

GCLOUD_STUB_EXIT=1 listing "irrelevant"
expect 1 "no staged commit versions" "listing failure fails loudly" -- run
unset GCLOUD_STUB_EXIT

finish
