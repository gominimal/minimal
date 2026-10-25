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
unset GCLOUD_STUB_EXISTS GCLOUD_STUB_SMOKED GCLOUD_STUB_RM_ERROR RESTAGE VERSION BUCKET ARTIFACTS_DIR

mkdir -p "$root/artifacts"
printf 'fake min\n' >"$root/artifacts/minimal-linux-amd64"
printf 'fake mip\n' >"$root/artifacts/mip-linux-amd64"
printf 'fake answerer\n' >"$root/artifacts/minzoned-linux-amd64"

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
with GCLOUD_STUB_EXISTS=0 GCLOUD_STUB_SMOKED=1 -- stage --version 0.6.0 >/dev/null 2>&1
expect_calls 0 "^storage rm " "a fresh (non-restage) stage never touches a marker"

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

# --- minzoned stages beside min; optional until release.yml ships it -----

# The answerer row: bin/minzoned beside bin/min on every Linux platform the
# manifest ships min for (macOS ships it inside bin/Minimal.app, checked
# further down), hashed and uploaded with the rest — it is the copy
# source NET-122's session advisory finds, so a release without it is a
# release whose advisory cannot offer the host service.
answerer_out="$(with GCLOUD_STUB_EXISTS=0 -- stage --version 0.6.0 2>&1)"
answerer_rows="$(printf '%s\n' "$answerer_out" | awk '
    $1 == "minzoned" && $2 == "linux" && $3 == "amd64" && $6 == "file" \
    && $7 == "bin/minzoned" && $8 == "versions/0.6.0/minzoned-linux-amd64"')"
if [ -n "$answerer_rows" ]; then
    ok "the manifest carries minzoned as bin/minzoned beside min, hashed from the artifact"
else
    bad "no minzoned row in the manifest (out: $answerer_out)"
fi
expect_calls 1 "minzoned-linux-amd64 .*gs://test-bucket/versions/0.6.0/$" \
    "the answerer artifact uploads with the others in the one artifact cp"
if [ -n "$(printf '%s\n' "$answerer_out" | awk '$1 == "minzoned" && $7 ~ /^lib\//')" ]; then
    bad "minzoned must carry no lib/ component on any platform"
else
    ok "the answerer row stages no lib/ component"
fi
if [ -n "$(printf '%s\n' "$answerer_out" | awk '$6 == "file" && $7 !~ /^(bin|lib|data)\//')" ]; then
    bad "the manifest carries a dest outside the bin/lib/data prefixes — no unit or plist path may appear"
else
    ok "no row stages a unit or plist: only bin/lib/data paths"
fi

# Optional until release.yml ships it (temporary, gominimal/inbox#899): a
# build that produced no answerer warns, names the omitted row, and stages
# every other artifact. The fixture dir carries an artifact for every other
# `file` row of the component table, read from the script itself, so the
# answerer is the only thing missing and the run uses no --allow-missing.
mkdir -p "$root/artifacts-no-answerer"
awk -F'|' '/^    "[a-z-]+\|(linux|darwin)\|/ && $4 == "file" {
        sub(/".*$/, "", $6); print $6
    }' "$script" | sort -u | while read -r base; do
    case "$base" in minzoned-*) continue ;; esac
    printf 'fake %s\n' "$base" >"$root/artifacts-no-answerer/$base"
done
: >"$GCLOUD_STUB_ARGS"
no_answerer_rc=0
no_answerer_out="$("$script" --artifacts-dir "$root/artifacts-no-answerer" \
    --bucket gs://test-bucket --version 0.6.0 2>&1)" || no_answerer_rc=$?
if [ "$no_answerer_rc" -eq 0 ]; then
    ok "a missing answerer artifact does not fail the stage"
else
    bad "a missing answerer artifact failed the stage (rc=$no_answerer_rc, out: $no_answerer_out)"
fi
for plat in linux/amd64 linux/arm64 darwin/arm64; do
    if [[ "$no_answerer_out" == *"warning: optional artifact missing, omitting minzoned/$plat:"* ]]; then
        ok "the stage warns that minzoned/$plat is omitted"
    else
        bad "no omission warning for minzoned/$plat (out: $no_answerer_out)"
    fi
done
if [[ "$no_answerer_out" == *"gominimal/inbox#899"* ]]; then
    ok "the warning names the issue that retires the optional state"
else
    bad "the warning does not name gominimal/inbox#899 (out: $no_answerer_out)"
fi
if [ -z "$(printf '%s\n' "$no_answerer_out" | awk '$1 == "minzoned" && $6 == "file"')" ]; then
    ok "the manifest carries no minzoned row when the artifact is missing"
else
    bad "the manifest carries a minzoned row with no artifact behind it (out: $no_answerer_out)"
fi
if [ -n "$(printf '%s\n' "$no_answerer_out" | awk '$1 == "minimal" && $2 == "darwin" && $7 == "bin/min"')" ] \
    && [ -n "$(printf '%s\n' "$no_answerer_out" | awk '$1 == "minvmd" && $2 == "linux" && $3 == "arm64"')" ]; then
    ok "every other artifact still stages"
else
    bad "the rest of the table did not stage (out: $no_answerer_out)"
fi
expect_calls 1 "/components gs://test-bucket/versions/0.6.0/components$" \
    "the manifest still uploads when only the answerer is missing"
expect_calls 0 "minzoned" "no answerer artifact is uploaded when it is missing"

# --- the macOS bundle rows match scripts/build-app-bundle.sh ----------------

# On macOS minzoned ships inside bin/Minimal.app, one manifest row per bundle
# file. Each file's flat artifact name is build-app-bundle.sh's: a row naming
# another artifact, or a bundle file with no row, would lay down a bundle
# whose signature does not verify.
mkdir -p "$root/artifacts-bundle"
cp "$root/artifacts-no-answerer"/* "$root/artifacts-bundle/"
bundle_table="$("$here/build-app-bundle.sh" table)"
while IFS=$'\t' read -r _ flat; do
    printf 'fake %s\n' "$flat" >"$root/artifacts-bundle/$flat"
done <<<"$bundle_table"
bundle_out="$("$script" --artifacts-dir "$root/artifacts-bundle" --bucket gs://test-bucket \
    --version 0.6.0 --dry-run 2>&1)"
bundle_files=0
while IFS=$'\t' read -r path flat; do
    bundle_files=$((bundle_files + 1))
    if [ -n "$(printf '%s\n' "$bundle_out" | awk -v dest="bin/Minimal.app/$path" \
        -v src="versions/0.6.0/$flat" \
        '$2 == "darwin" && $6 == "file" && $7 == dest && $8 == src')" ]; then
        ok "the darwin manifest installs $flat at bin/Minimal.app/$path"
    else
        bad "no darwin row installs $flat at bin/Minimal.app/$path (out: $bundle_out)"
    fi
done <<<"$bundle_table"
bundle_rows="$(printf '%s\n' "$bundle_out" | awk '$7 ~ /^bin\/Minimal\.app\// { n++ } END { print n + 0 }')"
if [ "$bundle_rows" -eq "$bundle_files" ]; then
    ok "the manifest carries exactly the bundle's $bundle_files files under bin/Minimal.app"
else
    bad "the manifest carries $bundle_rows rows under bin/Minimal.app, the bundle has $bundle_files files"
fi
if [ -z "$(printf '%s\n' "$bundle_out" | awk '$2 == "darwin" && $7 == "bin/minzoned"')" ]; then
    ok "darwin stages no bare bin/minzoned beside the bundle"
else
    bad "darwin still stages a bare bin/minzoned (out: $bundle_out)"
fi

# The bundle stages whole or not at all: with one of its files missing and
# the rest present, the stage fails naming the missing file and uploads
# nothing.
while IFS=$'\t' read -r _ flat; do
    mkdir -p "$root/artifacts-partial"
    rm -f "$root/artifacts-partial"/*
    cp "$root/artifacts-bundle"/* "$root/artifacts-partial/"
    rm "$root/artifacts-partial/$flat"
    : >"$GCLOUD_STUB_ARGS"
    partial_rc=0
    partial_out="$("$script" --artifacts-dir "$root/artifacts-partial" \
        --bucket gs://test-bucket --version 0.6.0 2>&1)" || partial_rc=$?
    if [ "$partial_rc" -ne 0 ] \
        && [[ "$partial_out" == *"incomplete macOS app bundle"*"missing $flat "* ]]; then
        ok "a bundle without $flat fails the stage naming it"
    else
        bad "a bundle without $flat staged (rc=$partial_rc, out: $partial_out)"
    fi
    expect_calls 0 "gs://test-bucket" "nothing uploads for a bundle without $flat"
done <<<"$bundle_table"
# --allow-missing keeps its meaning: a backfill of a release from before the
# bundle has the program alone, and that row still stages.
rm -f "$root/artifacts-partial"/minzoned-macos-arm64-*
printf 'fake minzoned-macos-arm64\n' >"$root/artifacts-partial/minzoned-macos-arm64"
partial_rc=0
partial_out="$("$script" --artifacts-dir "$root/artifacts-partial" --bucket gs://test-bucket \
    --version 0.6.0 --allow-missing --dry-run 2>&1)" || partial_rc=$?
if [ "$partial_rc" -eq 0 ] && [ -n "$(printf '%s\n' "$partial_out" \
    | awk '$1 == "minzoned" && $2 == "darwin" && $7 == "bin/Minimal.app/Contents/MacOS/minzoned"')" ]; then
    ok "--allow-missing stages the program of a release from before the bundle"
else
    bad "--allow-missing refused a bundle with the program alone (rc=$partial_rc, out: $partial_out)"
fi

# Every other binary stays required: the same fixture without minvmd's arm64
# artifact fails the stage naming it.
rm "$root/artifacts-no-answerer/minvmd-linux-arm64"
: >"$GCLOUD_STUB_ARGS"
expect 1 "missing artifact for minvmd/linux/arm64" \
    "a missing required artifact still fails the stage naming it" -- \
    "$script" --artifacts-dir "$root/artifacts-no-answerer" --bucket gs://test-bucket --version 0.6.0
expect_calls 0 "^storage cp " "nothing is uploaded when a required artifact is missing"

# --- --dry-run never talks to gcloud ------------------------------------------

expect 0 "dry run, nothing uploaded" "--dry-run over an existing version still passes" -- \
    with GCLOUD_STUB_EXISTS=1 -- stage --version 0.6.0 --dry-run
expect_calls 0 "" "--dry-run makes no gcloud call at all"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
