#!/usr/bin/env bash
#
# pkg-smoke_test.sh — test harness for scripts/pkg-smoke.sh.
#
# Drives the smoke end to end against a stubbed `distrobox` on PATH (no
# container engine, no images, no network): the stub answers each in-box probe
# with canned output and records every invocation, while fail-loud `podman` and
# `apx` shims prove the script never reaches for them (the distrobox-only rule).
# Asserts artifact discovery per host arch, version assertions, the uninstall
# round-trip, cleanup even when a check fails, --keep-boxes, and the
# --apparmor/--formats interaction. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/pkg-smoke.sh"
[ -f "$script" ] || { echo "cannot find pkg-smoke.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-pkgsmoketest)"
trap 'rm -rf "$root"' EXIT

# --- Fixture dist/ with one artifact per format (content never read) ---------
dist="$root/dist"
mkdir -p "$dist"
: >"$dist/minimal_9.9.9-1_amd64.deb"
: >"$dist/minimal-9.9.9-1.x86_64.rpm"
: >"$dist/minimal_9.9.9-r1_x86_64.apk"

# --- Tool shims ---------------------------------------------------------------
# distrobox stub: logs every call, answers in-box probes by marker substring.
# FAIL_AT selects which probe fails (install|version|files|binary|remove).
mkdir -p "$root/bin"
cat >"$root/bin/distrobox" <<'STUB'
#!/usr/bin/env bash
# Records "<verb> <name>" lines plus the full enter payloads to STUB_LOG.
set -u
echo "distrobox $*" >>"${STUB_LOG:?}"
case "$1" in
    create|rm|list) exit 0 ;;
    enter)
        # Args after -- are the in-box command; match on natural markers.
        payload="$*"
        case "$payload" in
            *apt-get\ install*|*dnf\ install*|*apk\ add*)
                [ "${FAIL_AT:-}" = install ] && exit 1
                exit 0 ;;
            *dpkg-query*)  echo "${STUB_DEB_VERSION:?}"; exit 0 ;;
            *rpm\ -q*)     echo "${STUB_RPM_VERSION:?}"; exit 0 ;;
            *apk\ list*)   echo "minimal-${STUB_APK_VERSION:?} x86_64 {minimal}"; exit 0 ;;
            *site-functions*)
                [ "${FAIL_AT:-}" = files ] && exit 1
                exit 0 ;;
            *does\ not\ run*)
                [ "${FAIL_AT:-}" = binary ] && exit 1
                echo "min ${STUB_BASE_VERSION:?}"
                exit 0 ;;
            *dpkg\ -r*|*dnf\ remove*|*apk\ del*)
                [ "${FAIL_AT:-}" = remove ] && exit 1
                exit 0 ;;
            *) exit 0 ;;
        esac ;;
    *) exit 0 ;;
esac
STUB
chmod +x "$root/bin/distrobox"

# Fail-loud guards: any podman/apx call from the script breaks the run.
for guard in podman apx; do
    cat >"$root/bin/$guard" <<GUARD
#!/usr/bin/env bash
echo "pkg-smoke_test: $guard was invoked (script must use distrobox only)" >&2
exit 99
GUARD
    chmod +x "$root/bin/$guard"
done

# uname shim so arch gating is testable on either host arch.
cat >"$root/bin/uname" <<'UNAME'
#!/usr/bin/env bash
echo "${FAKE_ARCH:-x86_64}"
UNAME
chmod +x "$root/bin/uname"

export PATH="$root/bin:$PATH"
export STUB_LOG="$root/stub.log"
export STUB_DEB_VERSION=9.9.9-1
export STUB_RPM_VERSION=9.9.9-1
export STUB_APK_VERSION=9.9.9-r1
export STUB_BASE_VERSION=9.9.9
: >"$STUB_LOG"

fail() { echo "pkg-smoke_test: $*" >&2; exit 1; }

run_smoke() {
    FAIL_AT="${FAIL_AT:-}" FAKE_ARCH="${FAKE_ARCH:-x86_64}" \
        bash "$script" "$@" >"$root/out.log" 2>&1
}

log_has() { grep -qF "$1" "$STUB_LOG"; }

# --- 1. happy path: all three formats -----------------------------------------
run_smoke --pkg-dir "$dist" || fail "happy path exited non-zero: $(cat "$root/out.log")"
for name in min-test-deb min-test-rpm min-test-apk; do
    log_has "create --name $name" || fail "no create for $name"
    log_has "rm --force $name" || fail "no cleanup rm for $name"
done
log_has "apt-get install -y $dist/minimal_9.9.9-1_amd64.deb" ||
    fail "deb install did not reference the fixture artifact"
log_has "apk add --allow-untrusted $dist/minimal_9.9.9-r1_x86_64.apk" ||
    fail "apk install did not reference the fixture artifact"
grep -q "all requested formats passed: deb rpm apk" "$root/out.log" ||
    fail "missing success summary: $(tail -3 "$root/out.log")"

# --- 2. a failed check still cleans every box up -------------------------------
: >"$STUB_LOG"
FAIL_AT=binary run_smoke --pkg-dir "$dist" && fail "binary failure exited zero"
for name in min-test-deb min-test-rpm min-test-apk; do
    log_has "rm --force $name" || fail "no cleanup rm for $name after failure"
done

# --- 3. a missing artifact fails fast, before any box exists -------------------
mv "$dist/minimal-9.9.9-1.x86_64.rpm" "$root/rpm.bak"
: >"$STUB_LOG"
run_smoke --pkg-dir "$dist" && fail "missing rpm artifact exited zero"
grep -q "create" "$STUB_LOG" && fail "created a box despite the missing artifact"
grep -q "no rpm artifact" "$root/out.log" || fail "missing-artifact message absent"
mv "$root/rpm.bak" "$dist/minimal-9.9.9-1.x86_64.rpm"

# --- 4. --formats selects a subset ----------------------------------------------
: >"$STUB_LOG"
run_smoke --pkg-dir "$dist" --formats apk || fail "--formats apk exited non-zero"
log_has "create --name min-test-apk" || fail "apk box not created"
grep -q "create --name min-test-deb" "$STUB_LOG" &&
    fail "deb box created despite --formats apk"

# --- 5. arch gating: arm64 host with only amd64 artifacts fails -----------------
: >"$STUB_LOG"
FAKE_ARCH=aarch64 run_smoke --pkg-dir "$dist" --formats deb &&
    fail "amd64 artifact accepted on an aarch64 host"
grep -q "no deb artifact" "$root/out.log" || fail "arch-mismatch message absent"
grep -q "create" "$STUB_LOG" && fail "created a box despite the arch mismatch"

# --- 6. --keep-boxes leaves the boxes in place ----------------------------------
: >"$STUB_LOG"
run_smoke --pkg-dir "$dist" --formats deb --keep-boxes ||
    fail "--keep-boxes run exited non-zero"
log_has "create --name min-test-deb" || fail "deb box not created"
# Only the pre-create stale-box rm may fire; no end-of-run cleanup rm.
[ "$(grep -c 'rm --force min-test-deb' "$STUB_LOG")" -eq 1 ] ||
    fail "--keep-boxes run removed the box at the end"

# --- 7. version mismatch is a hard failure --------------------------------------
: >"$STUB_LOG"
STUB_DEB_VERSION=0.0.0-wrong run_smoke --pkg-dir "$dist" --formats deb &&
    fail "version mismatch exited zero"
grep -q "version mismatch" "$root/out.log" || fail "version-mismatch message absent"

# --- 8. --apparmor drives the parser-present branch -----------------------------
: >"$STUB_LOG"
run_smoke --pkg-dir "$dist" --formats deb --apparmor ||
    fail "--apparmor run exited non-zero"
log_has "install-apparmor-profile" || fail "apparmor check never ran"
run_smoke --pkg-dir "$dist" --formats rpm --apparmor &&
    fail "--apparmor without deb exited zero"
grep -q "needs the deb box" "$root/out.log" || fail "apparmor/deb interaction message absent"

echo "pkg-smoke_test: all assertions passed"
