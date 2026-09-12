#!/usr/bin/env bash
#
# stage-release_test.sh — test harness for scripts/stage-release.sh's
# write-once contract.
#
# `gcloud` is stubbed by prepending a temp dir to PATH containing a fake that
# records every invocation and answers `storage objects describe` (the
# already-staged probe) from GCLOUD_STUB_EXISTS — no network, no auth, no
# bucket. The artifacts are two fake files under --allow-missing; the
# component table and manifest format are not under test here. Run directly
# or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/stage-release.sh"
[ -f "$script" ] || { echo "cannot find stage-release.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-stagetest)"
trap 'rm -rf "$root"' EXIT

mkdir -p "$root/bin"
cat >"$root/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GCLOUD_STUB_ARGS:?}"
if [ "${1:-} ${2:-} ${3:-}" = "storage objects describe" ]; then
    [ "${GCLOUD_STUB_EXISTS:-0}" = 1 ] && exit 0
    exit 1
fi
if [ "${1:-} ${2:-}" = "storage rm" ]; then
    # GCLOUD_STUB_RM_ERROR overrides the not-found failure with another one.
    [ "${GCLOUD_STUB_SMOKED:-0}" = 1 ] && exit 0
    printf '%s\n' "${GCLOUD_STUB_RM_ERROR:-ERROR: (gcloud.storage.rm) The following URLs matched no objects or files: $3}" >&2
    exit 1
fi
exit 0
EOF
chmod +x "$root/bin/gcloud"
# The script hashes with sha256sum (coreutils); a macOS dev box may only have
# shasum. Shim it so the harness runs everywhere the script's own tests do.
if ! command -v sha256sum >/dev/null 2>&1; then
    printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' >"$root/bin/sha256sum"
    chmod +x "$root/bin/sha256sum"
fi
export PATH="$root/bin:$PATH"
export GCLOUD_STUB_ARGS="$root/gcloud-args"
unset GCLOUD_STUB_EXISTS GCLOUD_STUB_SMOKED GCLOUD_STUB_RM_ERROR RESTAGE VERSION BUCKET ARTIFACTS_DIR PKG_DIR PKG_ONLY

mkdir -p "$root/artifacts" "$root/pkg"
printf 'fake min\n' >"$root/artifacts/minimal-linux-amd64"
printf 'fake mip\n' >"$root/artifacts/mip-linux-amd64"
printf 'fake deb\n' >"$root/pkg/minimal_0.6.0_amd64.deb"

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

# calls <grep pattern> — how many recorded gcloud invocations match.
calls() {
    grep -c -- "$1" "$GCLOUD_STUB_ARGS" 2>/dev/null || true
}

# expect_calls <want_count> <grep pattern> <description>
expect_calls() {
    local got
    got="$(calls "$2")"
    if [ "$got" -eq "$1" ]; then
        ok "$3"
    else
        bad "$3 (want $1 call(s) matching '$2', got $got: $(tr '\n' '|' <"$GCLOUD_STUB_ARGS" 2>/dev/null))"
    fi
}

# stage <args...> — a fresh recording, the fixture artifacts, a test bucket.
stage() {
    : >"$GCLOUD_STUB_ARGS"
    "$script" --artifacts-dir "$root/artifacts" --bucket gs://test-bucket --allow-missing "$@"
}

# with VAR=value... -- <command...> — run a shell function with those
# variables exported, in a subshell so nothing leaks between cases (`env`
# cannot run a function).
with() {
    (
        while [ "${1:-}" != "--" ]; do export "${1?}"; shift; done
        shift
        "$@"
    )
}

# --- a fresh version stages with the precondition on every upload -----------

expect 0 "staged 0.6.0 at gs://test-bucket/versions/0.6.0" "a fresh version stages" -- \
    with GCLOUD_STUB_EXISTS=0 -- stage --version 0.6.0
expect_calls 1 "^storage objects describe gs://test-bucket/versions/0.6.0/components$" \
    "the components manifest is probed once before uploading"
expect_calls 2 "^storage cp " "two uploads: the artifacts and the manifest"
expect_calls 2 "^storage cp --cache-control=public, max-age=31536000, immutable --if-generation-match=0 " \
    "both uploads carry the immutable cache header and the must-not-exist precondition"
expect_calls 1 "mip-linux-amd64 .*minimal-linux-amd64 .* gs://test-bucket/versions/0.6.0/$" \
    "the artifact upload targets the version row"
expect_calls 1 "/components gs://test-bucket/versions/0.6.0/components$" \
    "the manifest upload targets versions/<V>/components"

# --- an already-staged version fails before any upload ----------------------

expect 1 "versions/0.6.0 is already staged (gs://test-bucket/versions/0.6.0/components exists)" \
    "an existing manifest fails the run, naming the version" -- \
    with GCLOUD_STUB_EXISTS=1 -- stage --version 0.6.0
expect 1 "pass --restage to overwrite it deliberately" "the failure names the opt-in" -- \
    with GCLOUD_STUB_EXISTS=1 -- stage --version 0.6.0
expect_calls 0 "^storage cp " "nothing is uploaded when the version already exists"

# --- --restage is the explicit, logged opt-in --------------------------------

expect 0 "stage-release: --restage: overwriting whatever already exists under versions/0.6.0 (write-once guard OFF)" \
    "--restage proceeds over an existing version and logs it" -- \
    with GCLOUD_STUB_EXISTS=1 -- stage --version 0.6.0 --restage
expect_calls 0 "^storage objects describe " "--restage skips the probe"
expect_calls 2 "^storage cp " "--restage uploads both objects"
expect_calls 0 "if-generation-match" "--restage drops the precondition so the objects are replaced"
expect_calls 2 "^storage cp --cache-control=public, max-age=31536000, immutable " \
    "--restage keeps the immutable cache header"
expect 0 "write-once guard OFF" "RESTAGE=1 in the environment is the same opt-in" -- \
    with GCLOUD_STUB_EXISTS=1 RESTAGE=1 -- stage --version 0.6.0

# A restage invalidates the smoke marker before its first upload.
expect 0 "removed versions/0.6.0/smoked — the row must be smoked again" \
    "--restage over a smoked row removes the marker and says so" -- \
    with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=1 -- stage --version 0.6.0 --restage
expect_calls 1 "^storage rm gs://test-bucket/versions/0.6.0/smoked$" "the marker is deleted exactly once"
if [ "$(sed -n '1p' "$GCLOUD_STUB_ARGS")" = "storage rm gs://test-bucket/versions/0.6.0/smoked" ]; then
    ok "the marker is deleted before any upload"
else
    bad "the marker deletion did not come first: $(tr '\n' '|' <"$GCLOUD_STUB_ARGS")"
fi
expect 0 "staged 0.6.0" "--restage over a never-smoked row is fine (no marker to remove)" -- \
    with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=0 -- stage --version 0.6.0 --restage
expect_calls 1 "^storage rm " "the removal is still attempted, and its absence is not an error"
expect 0 "smoked was not present (nothing to invalidate)" "a confirmed not-found is reported as such" -- \
    with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=0 -- stage --version 0.6.0 --restage
expect 0 "staged 0.6.0" "gcloud's NotFoundException spelling is also tolerated" -- \
    with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=0 GCLOUD_STUB_RM_ERROR="ERROR: (gcloud.storage.rm) NotFoundException: 404 gs://test-bucket/versions/0.6.0/smoked does not exist." -- \
    stage --version 0.6.0 --restage

# Any other deletion failure stops the restage before the first upload: the
# stale marker would otherwise survive under the new bytes.
for rm_err in \
    "ERROR: (gcloud.storage.rm) HTTPError 403: user@example.com does not have storage.objects.delete access to the Google Cloud Storage object." \
    "ERROR: (gcloud.storage.rm) There was a problem refreshing your current auth tokens: Reauthentication is needed." \
    "ERROR: (gcloud.storage.rm) HTTPError 503: Service Unavailable"; do
    expect 1 "could not remove gs://test-bucket/versions/0.6.0/smoked, so its stale smoke provenance would survive the overwrite — nothing was uploaded. gcloud said: $rm_err" \
        "--restage dies on: ${rm_err:26:40}..." -- \
        with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=0 GCLOUD_STUB_RM_ERROR="$rm_err" -- stage --version 0.6.0 --restage
    expect_calls 0 "^storage cp " "nothing is uploaded after a failed marker deletion (${rm_err:26:20}...)"
done
expect 1 "could not remove" "--pkg-only --restage dies the same way" -- \
    with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=0 GCLOUD_STUB_RM_ERROR="ERROR: (gcloud.storage.rm) HTTPError 403: forbidden" -- \
    stage --version 0.6.0 --restage --pkg-only --pkg-dir "$root/pkg"
expect_calls 0 "^storage cp " "--pkg-only uploads nothing after a failed marker deletion"
with GCLOUD_STUB_EXISTS=0 GCLOUD_STUB_SMOKED=1 -- stage --version 0.6.0 >/dev/null 2>&1
expect_calls 0 "^storage rm " "a fresh (non-restage) stage never touches a marker"
expect 0 "removed versions/0.6.0/smoked" "--pkg-only --restage also invalidates the marker before its upload" -- \
    with GCLOUD_STUB_EXISTS=1 GCLOUD_STUB_SMOKED=1 -- stage --version 0.6.0 --restage --pkg-only --pkg-dir "$root/pkg"
if [ "$(sed -n '1p' "$GCLOUD_STUB_ARGS")" = "storage rm gs://test-bucket/versions/0.6.0/smoked" ]; then
    ok "--pkg-only --restage deletes the marker before the packages upload"
else
    bad "--pkg-only --restage did not delete the marker first: $(tr '\n' '|' <"$GCLOUD_STUB_ARGS")"
fi

# --- the packages upload is guarded the same way ------------------------------

expect 0 "staged 0.6.0" "--pkg-dir on a fresh version stages the row and the packages" -- \
    with GCLOUD_STUB_EXISTS=0 -- stage --version 0.6.0 --pkg-dir "$root/pkg"
expect_calls 3 "^storage cp --cache-control=public, max-age=31536000, immutable --if-generation-match=0 " \
    "all three uploads carry the precondition"
expect_calls 1 "minimal_0.6.0_amd64.deb gs://test-bucket/versions/0.6.0/pkg/$" \
    "the packages land under versions/<V>/pkg/"
if [ "$(grep '^storage cp ' "$GCLOUD_STUB_ARGS" | tail -n 1 | grep -c '/components$')" -eq 1 ]; then
    ok "with --pkg-dir the manifest is still the last object written, after the packages"
else
    bad "the manifest was not the last upload with --pkg-dir: $(tr '\n' '|' <"$GCLOUD_STUB_ARGS")"
fi

# --pkg-only adds packages to a row that is already staged BY DESIGN: the
# manifest probe must not fire, but each package object is still write-once.
expect 0 "staged packages for 0.6.0" "--pkg-only stages into an existing row" -- \
    with GCLOUD_STUB_EXISTS=1 -- stage --version 0.6.0 --pkg-only --pkg-dir "$root/pkg"
expect_calls 0 "^storage objects describe " "--pkg-only does not probe the manifest"
expect_calls 1 "^storage cp --cache-control=public, max-age=31536000, immutable --if-generation-match=0 .*/pkg/$" \
    "--pkg-only's single upload carries the precondition"

# --- --extra files join the row under the same guard ---------------------------

printf 'fake installer\n' >"$root/install.sh"
printf '## 0.6.0\n' >"$root/notes.md"
expect 0 "staged 0.6.0" "--extra uploads join a fresh row" -- \
    with GCLOUD_STUB_EXISTS=0 -- stage --version 0.6.0 --extra "$root/install.sh" --extra "$root/notes.md"
expect_calls 1 "^storage cp --cache-control=public, max-age=31536000, immutable --if-generation-match=0 $root/install.sh $root/notes.md gs://test-bucket/versions/0.6.0/$" \
    "the extra files upload together into versions/<V>/ with the precondition"
expect_calls 3 "^storage cp " "artifacts, extras, manifest: three uploads"
if [ "$(grep '^storage cp ' "$GCLOUD_STUB_ARGS" | tail -n 1 | grep -c '/components$')" -eq 1 ]; then
    ok "the manifest is the last object written, after the extras"
else
    bad "the manifest was not the last upload: $(tr '\n' '|' <"$GCLOUD_STUB_ARGS")"
fi
expect 1 "--extra needs an existing file" "--extra with a missing file fails before anything runs" -- \
    with GCLOUD_STUB_EXISTS=0 -- stage --version 0.6.0 --extra "$root/absent"

# --- --dry-run never talks to gcloud ------------------------------------------

expect 0 "dry run, nothing uploaded" "--dry-run over an existing version still passes" -- \
    with GCLOUD_STUB_EXISTS=1 -- stage --version 0.6.0 --dry-run
expect_calls 0 "" "--dry-run makes no gcloud call at all"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
