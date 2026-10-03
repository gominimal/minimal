#!/usr/bin/env bash
#
# deps-freshness_test.sh — test harness for scripts/deps-freshness.sh.
#
# `gh` and `curl` are stubbed by prepending a temp dir to PATH: the gh stub
# answers the release, compare, and contents endpoints from fixture values
# and logs every call, and the curl stub serves canned kernel.org and Alpine
# responses. DEPS_ROOT points the script at a fixture tree whose pins the
# cases skew. No network, no auth. The last case runs the offline checks
# against the real tree, so a duplicated pin bumped in one place only fails
# here. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/deps-freshness.sh"
[ -f "$script" ] || { echo "cannot find deps-freshness.sh next to test" >&2; exit 1; }

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-depsfreshtest)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

commit=1111111111111111111111111111111111111111

cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
# Endpoints answered: releases/latest (tag from GH_STUB_TAGS, "repo=tag" per
# line), compare/<c>...main (GH_STUB_AHEAD), contents/<path>?ref=<c> (file
# under GH_STUB_PKGS/<c>/). Every call is appended to GH_STUB_LOG.
printf '%s\n' "$*" >>"${GH_STUB_LOG:?}"
[ "${1:-}" = api ] || { echo "gh stub: unexpected $*" >&2; exit 2; }
ep="$2"
case "$ep" in
    repos/*/releases/latest)
        repo="${ep#repos/}"; repo="${repo%/releases/latest}"
        tag="$(sed -n "s|^$repo=||p" <<<"${GH_STUB_TAGS:-}")"
        [ -n "$tag" ] || { echo "HTTP 404" >&2; exit 1; }
        echo "$tag" ;;
    repos/gominimal/pkgs/compare/*)
        echo "${GH_STUB_AHEAD:?}" ;;
    repos/gominimal/pkgs/contents/*)
        rest="${ep#repos/gominimal/pkgs/contents/}"
        f="${GH_STUB_PKGS:?}/${rest#*\?ref=}/${rest%%\?*}"
        [ -f "$f" ] || { echo "HTTP 404" >&2; exit 1; }
        cat "$f" ;;
    *) echo "gh stub: unexpected endpoint $ep" >&2; exit 2 ;;
esac
EOF

cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
url="${*: -1}"
# A stalled upstream must time out into `unknown`, so every call is bounded.
case " $* " in *" --max-time "*) ;; *) echo "curl stub: unbounded call $*" >&2; exit 2 ;; esac
case "$url" in
    *kernel.org/releases.json)
        printf '{"releases":[\n{"version": "6.18.3"},\n{"version": "6.12.111"},\n{"version": "6.12.9"}\n]}\n' ;;
    *latest-releases.yaml)
        printf -- '---\n-\n  title: "Mini root filesystem"\n  version: 3.24.2\n' ;;
    *) echo "curl stub: unexpected $url" >&2; exit 22 ;;
esac
EOF
chmod +x "$tmp/bin/gh" "$tmp/bin/curl"
export PATH="$tmp/bin:$PATH"
export GH_STUB_LOG="$tmp/gh.log" GH_STUB_PKGS="$tmp/pkgs" GH_STUB_AHEAD=7
export GH_STUB_TAGS="libkrun/libkrun=v1.19.6
libkrun/libkrunfw=v5.5.0
containers/gvisor-tap-vsock=v0.8.9
goreleaser/nfpm=v2.47.0
rust-lang/rust=1.99.0
model-checking/kani=kani-0.68.0
zizmorcore/zizmor=v1.30.1
rhysd/actionlint=v1.7.12
protocolbuffers/protobuf=v36.2
koalaman/shellcheck=v0.11.0
tbhb/vale-ai-tells=v1.37.0
amoslives/vale-ste=v0.1.1"

# make_tree DIR — a fixture repo whose pins all agree with each other.
make_tree() {
    local d="$1"
    mkdir -p "$d/.minimal" "$d/vendor/libkrun" "$d/vendor/gvproxy" "$d/vendor/nfpm" "$d/.github/workflows"
    printf '[upstream]\nlocked_commit = "%s"\n' "$commit" >"$d/.minimal/minimal.toml"
    printf '# lock\nversion=v1.19.4\ncommit=abc\n' >"$d/vendor/libkrun/libkrun.lock"
    printf 'version=v0.8.9\ngvproxy-darwin=00\n' >"$d/vendor/gvproxy/gvproxy.lock"
    printf 'version=v2.47.0\n' >"$d/vendor/nfpm/nfpm.lock"
    printf '[toolchain]\nchannel = "1.97.0"\n' >"$d/rust-toolchain.toml"
    printf 'env:\n    KANI_VERSION: 0.68.0\n' >"$d/.github/workflows/ci-kani.yml"
    printf 'kani: (_need "cargo-kani" "cargo install --locked kani-verifier --version 0.68.0")\n' >"$d/justfile"
    for w in ci nightly-tests; do
        printf '  tool: zizmor@1.30.1\n  run: docker run rhysd/actionlint:1.7.12 -color\n' >"$d/.github/workflows/$w.yml"
    done
    printf '"wget .../v25.1/protoc-25.1-linux-x86_64.zip"\n' >"$d/Cross.toml"
    printf 'shellcheck 0.11.0\n' >"$d/.tool-versions"
    printf 'Packages = https://github.com/tbhb/vale-ai-tells/releases/download/v1.31.0/ai-tells.zip, https://github.com/amoslives/vale-ste/releases/download/v0.1.1/ste.zip\n' >"$d/.vale.ini"
}

p="$tmp/pkgs/$commit/packages"
mkdir -p "$p/virtio-linux" "$p/libkrun" "$p/libkrunfw" "$p/microvm-rootfs"
printf 'let version = "6.12.105" in\n' >"$p/virtio-linux/build.ncl"
printf 'let version = "1.19.4" in\n' >"$p/libkrun/build.ncl"
printf 'let version = "5.5.0" in\n' >"$p/libkrunfw/build.ncl"
printf 'let alpine_branch = "v3.24" in\nlet alpine_release = "3.24.1" in\n' >"$p/microvm-rootfs/build.ncl"

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# expect <want_rc> <description> <want_line_regex...> -- <command...>
# Every regex must match some line of the combined output.
expect() {
    local want_rc="$1" desc="$2"; shift 2
    local pats=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do pats+=("$1"); shift; done
    [ "${1:-}" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local out rc=0 pat
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -ne "$want_rc" ]; then
        bad "$desc (want rc=$want_rc, got rc=$rc, out: $out)"; return
    fi
    for pat in "${pats[@]}"; do
        grep -Eq -- "$pat" <<<"$out" || { bad "$desc (no line matching '$pat' in: $out)"; return; }
    done
    ok "$desc"
}

# fresh — a new consistent fixture tree in $tree, and an empty gh log.
fresh() { tree="$tmp/tree$((pass + fail))"; make_tree "$tree"; : >"$GH_STUB_LOG"; }
run() { DEPS_ROOT="$tree" bash "$script" "$@"; }

fresh
expect 0 "report shows pinned, latest, and status per pin" \
    '^pkgs locked_commit +111111111111 +main +behind \(7 commits\)$' \
    '^kernel \(pkgs virtio-linux\) +6\.12\.105 +6\.12\.111 +behind$' \
    '^libkrun \(vendored\) +1\.19\.4 +1\.19\.6 +behind$' \
    '^libkrunfw \(pkgs\) +5\.5\.0 +5\.5\.0 +current$' \
    '^alpine rootfs \(pkgs\) +3\.24\.1 +3\.24\.2 +behind$' \
    '^kani +0\.68\.0 +0\.68\.0 +current$' \
    '^protoc \(cross image\) +25\.1 +36\.2 +behind$' \
    '^rust toolchain +1\.97\.0 +1\.99\.0 +behind$' \
    '^shellcheck +0\.11\.0 +0\.11\.0 +current$' \
    '^vale ai-tells +1\.31\.0 +1\.37\.0 +behind$' \
    '^ok +libkrun vendored = pkgs +1\.19\.4$' \
    -- run

fresh
GH_STUB_AHEAD=0 expect 0 "pkgs locked_commit at main reads current" \
    '^pkgs locked_commit +111111111111 +main +current$' -- run

fresh
GH_STUB_TAGS="" expect 0 "unreachable upstream reports unknown and does not fail" \
    '^gvproxy +0\.8\.9 +\? +unknown \(upstream unreachable\)$' -- run

fresh
rm "$tree/.tool-versions"
expect 0 "unreadable pin reports unknown in the report" \
    '^shellcheck +\? +\? +unknown \(pin unreadable\)$' -- run

fresh
expect 0 "--check passes on a consistent tree" \
    '^ok +kani workflow = justfile +0\.68\.0$' \
    '^ok +zizmor ci = nightly-tests +1\.30\.1$' \
    -- run --check
if grep -q 'releases/latest' "$GH_STUB_LOG"; then
    bad "--check skips release lookups (it queried: $(cat "$GH_STUB_LOG"))"
else
    ok "--check skips release lookups"
fi

fresh
printf 'version=v1.19.6\n' >"$tree/vendor/libkrun/libkrun.lock"
expect 1 "vendored libkrun skewed from the pkgs recipe fails" \
    '^FAIL +libkrun vendored = pkgs +1\.19\.6 != 1\.19\.4$' -- run --check

fresh
sed -i.bak 's/0\.68\.0/0.69.0/' "$tree/justfile"
expect 1 "KANI_VERSION skewed between workflow and justfile fails" \
    '^FAIL +kani workflow = justfile +0\.68\.0 != 0\.69\.0$' -- run --check

fresh
sed -i.bak 's/zizmor@1\.30\.1/zizmor@1.31.0/' "$tree/.github/workflows/nightly-tests.yml"
expect 1 "zizmor skewed between workflows fails" \
    '^FAIL +zizmor ci = nightly-tests +1\.30\.1 != 1\.31\.0$' -- run --check

fresh
rm "$tmp/pkgs/$commit/packages/libkrun/build.ncl"
expect 1 "a check that cannot resolve its pin fails" \
    '^FAIL +libkrun vendored = pkgs +unresolved \(1\.19\.4 vs \?\)$' -- run --check
printf 'let version = "1.19.4" in\n' >"$p/libkrun/build.ncl"

fresh
sed -i.bak 's/0\.68\.0/0.69.0/' "$tree/justfile"
expect 1 "--offline still runs the local checks" \
    '^skip +libkrun vendored = pkgs +needs the network$' \
    '^FAIL +kani workflow = justfile' -- run --check --offline
if [ -s "$GH_STUB_LOG" ]; then
    bad "--offline makes no gh calls (it made: $(cat "$GH_STUB_LOG"))"
else
    ok "--offline makes no gh calls"
fi

fresh
expect 2 "--offline without --check is rejected" 'only applies to --check' -- run --offline

expect 0 "the real tree's duplicated pins agree" '^ok +kani workflow = justfile' \
    -- bash "$script" --check --offline

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
