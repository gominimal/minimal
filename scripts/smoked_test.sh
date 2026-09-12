#!/usr/bin/env bash
#
# smoked_test.sh — test harness for scripts/record-smoked.sh and
# scripts/verify-smoked.sh, the smoke-provenance marker and the promotion
# gate that reads it.
#
# `gcloud` is stubbed by prepending a temp dir to PATH containing a fake
# whose `storage cat`/`storage cp` read and write a directory standing in
# for the bucket — no network, no auth. So the two scripts are tested
# end-to-end against each other: record writes the marker, verify reads it,
# and every failure mode (unstaged, never smoked, re-staged, unreadable
# marker) is a plain file operation. Run directly or via `just test-shell`
# / `just test-promote-gate`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
record="$here/record-smoked.sh"
verify="$here/verify-smoked.sh"
[ -f "$record" ] || { echo "cannot find record-smoked.sh next to test" >&2; exit 1; }
[ -f "$verify" ] || { echo "cannot find verify-smoked.sh next to test" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not installed — skipping smoked_test.sh"; exit 0; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-smokedtest)"
trap 'rm -rf "$root"' EXIT

mkdir -p "$root/bin" "$root/bucket"
cat >"$root/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
# gs://<bucket>/<path> -> $GCLOUD_STUB_BUCKET/<path>
local_path() { printf '%s/%s' "${GCLOUD_STUB_BUCKET:?}" "${1#gs://*/}"; }
case "${1:-} ${2:-}" in
    "storage cat")
        f="$(local_path "$3")"
        [ -f "$f" ] || { echo "CommandException: no such object $3" >&2; exit 1; }
        cat "$f" ;;
    "storage rm")
        f="$(local_path "$3")"
        [ -f "$f" ] || { echo "CommandException: no such object $3" >&2; exit 1; }
        rm -f "$f" ;;
    "storage cp")
        shift 2
        args=(); for a in "$@"; do case "$a" in --*) ;; *) args+=("$a") ;; esac; done
        dst="$(local_path "${args[$((${#args[@]} - 1))]}")"   # no negative subscripts: macOS bash 3.2
        mkdir -p "$(dirname "$dst")"
        cp "${args[0]}" "$dst" ;;
    *) echo "gcloud stub: unexpected $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$root/bin/gcloud"
if ! command -v sha256sum >/dev/null 2>&1; then
    printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' >"$root/bin/sha256sum"
    chmod +x "$root/bin/sha256sum"
fi
export PATH="$root/bin:$PATH"
export GCLOUD_STUB_BUCKET="$root/bucket"
unset VERSION RUN_URL RUN_ID BUCKET

pass=0 fail=0
# ok / bad <description> — count and print one passing / failing case.
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

# stage_row <version> <sha256> — write a one-row components manifest into the fake bucket.
stage_row() {
    mkdir -p "$root/bucket/versions/$1"
    printf '# format: 1\nminimal linux amd64 %s %s file bin/min versions/%s/minimal-linux-amd64\n' "$1" "$2" "$1" \
        >"$root/bucket/versions/$1/components"
}

# --- nothing staged ---------------------------------------------------------

expect 1 "versions/0.6.0 is not staged" "record refuses an unstaged version" -- \
    "$record" --version 0.6.0 --run-url https://example/run/1 --bucket gs://test-bucket
expect 1 "versions/0.6.0 is not staged" "verify refuses an unstaged version" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket

# --- staged, never smoked ---------------------------------------------------

stage_row 0.6.0 "$(printf 'a%.0s' {1..64})"
expect 1 "has no smoked marker" "verify refuses a staged version nobody smoked" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket
expect 1 "override_provenance" "the refusal names the emergency override" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket

# --- record then verify -------------------------------------------------------

expect 0 "record-smoked: dry run, nothing written" "record --dry-run prints the marker and writes nothing" -- \
    "$record" --version 0.6.0 --run-url https://example/run/1 --run-id 1 --bucket gs://test-bucket --dry-run
if [ -e "$root/bucket/versions/0.6.0/smoked" ]; then bad "dry run wrote a marker"; else ok "dry run left no marker"; fi

expect 0 "record-smoked: versions/0.6.0 smoked by https://example/run/1" "record writes the marker" -- \
    "$record" --version 0.6.0 --run-url https://example/run/1 --run-id 1 --sha 8e7e72c2 --bucket gs://test-bucket
marker="$root/bucket/versions/0.6.0/smoked"
if [ -f "$marker" ] && [ "$(jq -r .version "$marker")" = "0.6.0" ] \
    && [ "$(jq -r .run_id "$marker")" = "1" ] \
    && [ "$(jq -r .sha "$marker")" = "8e7e72c2" ] \
    && [ "$(jq -r .components_sha256 "$marker")" = "$(sha256sum "$root/bucket/versions/0.6.0/components" | cut -d' ' -f1)" ]; then
    ok "the marker is JSON carrying the version, commit sha, run id, and the live components digest"
else
    bad "unexpected marker: $(cat "$marker" 2>&1)"
fi
expect 0 "verify-smoked: versions/0.6.0 smoked by https://example/run/1 (components sha256 " \
    "verify passes a recorded row and names the run" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket

# --- the row changes after the smoke ------------------------------------------

stage_row 0.6.0 "$(printf 'b%.0s' {1..64})"
expect 1 "versions/0.6.0 was re-staged after it was smoked" "verify fails when the live manifest no longer matches" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket
expect 1 "by https://example/run/1" "the mismatch names the run that smoked the old bytes" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket
expect 0 "smoked by https://example/run/2" "re-recording after a re-stage blesses the new bytes" -- \
    "$record" --version 0.6.0 --run-url https://example/run/2 --bucket gs://test-bucket
expect 0 "smoked by https://example/run/2" "verify passes again with the new marker" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket

# --- an unreadable marker is not trusted ----------------------------------------

printf 'not json\n' >"$marker"
expect 1 "unreadable or carries no components_sha256" "verify refuses a corrupt marker" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket
printf '{"run_url":"x"}\n' >"$marker"
expect 1 "carries no components_sha256" "verify refuses a marker without a digest" -- \
    "$verify" --version 0.6.0 --bucket gs://test-bucket

# --- arguments -----------------------------------------------------------------

expect 1 "missing --version" "record needs --version" -- "$record" --run-url u
expect 1 "missing --run-url" "record needs --run-url" -- "$record" --version 0.6.0
expect 1 "is not a lowercase hex commit sha" "record rejects a non-hex --sha" -- \
    "$record" --version 0.6.0 --run-url u --sha 0.6.0
expect 1 "missing --version" "verify needs --version" -- "$verify"
expect 1 "characters outside" "a version with a slash is rejected" -- "$verify" --version ../x
expect 1 "unknown argument" "unknown flags are rejected" -- "$verify" --version 0.6.0 --bogus
expect 1 "missing value for --version" "a trailing valueless flag is a usable error" -- "$verify" --version

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
