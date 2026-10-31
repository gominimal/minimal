#!/usr/bin/env bash
#
# build-gvproxy_test.sh — test harness for scripts/build-gvproxy.sh, the
# patched gvproxy source build.
#
# `git`, `go` and `curl` are stubbed by prepending a temp dir to PATH, so no
# case touches the network or a real toolchain. The `go` stub reports the
# pinned version, so the build never fetches a toolchain, and `curl` fails if
# anything calls it. The lock and the patch dir are fixtures, passed through
# GVPROXY_LOCK and GVPROXY_PATCHES. The cases prove that a stale patch and a
# patch whose digest differs from the lock each stop the build with a message
# that names the patch. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
build="$here/build-gvproxy.sh"
[ -f "$build" ] || { echo "cannot find build-gvproxy.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-buildgvproxytest)"
trap 'rm -rf "$root"' EXIT

commit=0123456789abcdef0123456789abcdef01234567
mkdir -p "$root/bin"

# git: every call is logged. `rev-parse` answers the pinned commit, and
# `apply` refuses when STUB_APPLY_FAIL names the patch's file.
cat >"$root/bin/git" <<EOF
#!/usr/bin/env bash
echo "git \$*" >>"\${STUB_LOG:?}"
[ "\${1:-}" = "-C" ] && shift 2
case "\${1:-}" in
  init) mkdir -p "\${@: -1}" ;;
  rev-parse) echo "$commit" ;;
  apply)
    patch="\${@: -1}"
    if [ -n "\${STUB_APPLY_FAIL:-}" ] && [ "\$(basename "\$patch")" = "\$STUB_APPLY_FAIL" ]; then
      echo "error: patch failed: pkg/services/forwarder/ports.go:277" >&2
      exit 1
    fi ;;
esac
exit 0
EOF

# go: reports the pinned version, and `build -o <out>` writes a stand-in.
cat >"$root/bin/go" <<'EOF'
#!/usr/bin/env bash
echo "go $*" >>"${STUB_LOG:?}"
case "${1:-}" in
  env) echo "go1.99.0" ;;
  build)
    while [ $# -gt 0 ]; do
      if [ "$1" = "-o" ]; then echo "stub gvproxy" >"$2"; fi
      shift
    done ;;
esac
exit 0
EOF

cat >"$root/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >>"${STUB_LOG:?}"
echo "curl stub: no network in this harness" >&2
exit 7
EOF
chmod +x "$root/bin/git" "$root/bin/go" "$root/bin/curl"
export PATH="$root/bin:$PATH"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

pass=0 fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }

# setup <case> — a fresh patch dir with one patch, and a lock that pins it.
setup() {
  case_dir="$root/$1"
  mkdir -p "$case_dir/patches"
  patch_name=0001-forwarder-unexpose-closes-accepted-connections.patch
  printf 'diff --git a/x b/x\n' >"$case_dir/patches/$patch_name"
  cat >"$case_dir/gvproxy.lock" <<EOF
version=v0.9.0
commit=$commit
go=1.99.0
go-linux-amd64=unused
patch.$patch_name=$(sha256_of "$case_dir/patches/$patch_name")
EOF
  export GVPROXY_LOCK="$case_dir/gvproxy.lock" GVPROXY_PATCHES="$case_dir/patches"
  export STUB_LOG="$case_dir/calls.log"
  : >"$STUB_LOG"
  unset STUB_APPLY_FAIL
}

# run_build — runs the build for one asset. Sets $status and $err.
run_build() {
  set +e
  err="$("$build" "$case_dir/out/gvproxy" gvproxy-linux-amd64 2>&1 >/dev/null)"
  status=$?
  set -e
}

# A patch that matches the lock and applies builds the asset.
setup control
run_build
if [ "$status" -eq 0 ] && [ -f "$case_dir/out/gvproxy" ]; then
  ok "a pinned patch that applies builds the asset"
else
  bad "a pinned patch that applies builds the asset (exit $status): $err"
fi
if grep -q "^go build .*-mod=vendor -trimpath -buildvcs=false" "$STUB_LOG"; then
  ok "the build runs with -mod=vendor -trimpath -buildvcs=false"
else
  bad "the build runs with -mod=vendor -trimpath -buildvcs=false: $(cat "$STUB_LOG")"
fi
if grep -q "^curl" "$STUB_LOG"; then
  bad "a pinned go on PATH is used without a download"
else
  ok "a pinned go on PATH is used without a download"
fi

# A patch whose digest differs from the lock stops the build before any fetch.
setup digest
printf 'diff --git a/y b/y\n' >>"$case_dir/patches/$patch_name"
run_build
if [ "$status" -ne 0 ] && printf '%s' "$err" | grep -q "patch $patch_name does not match its SHA-256"; then
  ok "a patch whose digest differs from the lock stops the build and is named"
else
  bad "a patch whose digest differs from the lock stops the build and is named (exit $status): $err"
fi
if grep -q "fetch" "$STUB_LOG"; then
  bad "a patch whose digest differs stops the build before the source fetch"
else
  ok "a patch whose digest differs stops the build before the source fetch"
fi
if [ -e "$case_dir/out/gvproxy" ]; then
  bad "a refused patch leaves no asset"
else
  ok "a refused patch leaves no asset"
fi

# A stale patch, one that no longer applies to the pinned commit, stops the build.
setup stale
export STUB_APPLY_FAIL="$patch_name"
run_build
if [ "$status" -ne 0 ] && printf '%s' "$err" | grep -q "patch $patch_name does not apply"; then
  ok "a stale patch stops the build and is named"
else
  bad "a stale patch stops the build and is named (exit $status): $err"
fi
if grep -q "^go build" "$STUB_LOG"; then
  bad "a stale patch stops the build before go build"
else
  ok "a stale patch stops the build before go build"
fi

# A patch the lock does not pin stops the build.
setup unpinned
sed -i.bak '/^patch\./d' "$GVPROXY_LOCK"
run_build
if [ "$status" -ne 0 ] && printf '%s' "$err" | grep -q "patch $patch_name has no patch.$patch_name= line"; then
  ok "a patch the lock does not pin stops the build and is named"
else
  bad "a patch the lock does not pin stops the build and is named (exit $status): $err"
fi

echo "build-gvproxy_test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
