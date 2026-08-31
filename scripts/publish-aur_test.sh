#!/usr/bin/env bash
#
# publish-aur_test.sh — test harness for scripts/publish-aur.sh.
#
# Drives the publisher end to end against fixtures: a local file:// "bucket"
# holding the 13 artifacts it fetches, a local bare "AUR" repo to clone, and a
# stubbed `makepkg` on PATH. No network, no ssh key, no Arch host. Asserts
# that a dry run downloads, checksums, renders the PKGBUILD fully stamped (the
# reviewer-visible failure mode was five template defects reaching review
# unexercised), regenerates .SRCINFO, and pushes nothing — plus that a
# prerelease PKGVER is refused. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/publish-aur.sh"
[ -f "$script" ] || { echo "cannot find publish-aur.sh next to test" >&2; exit 1; }

# The harness needs git (fixture remotes) and curl (file:// fetches).
missing=""
for tool in git curl; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "publish-aur_test: skipping, no$missing on PATH"
    exit 0
fi

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-aurtest)"
trap 'rm -rf "$root"' EXIT

# --- fixtures -----------------------------------------------------------------

# The versioned artifacts, each with distinct content so the sha256s differ.
bucket="$root/bucket/versions/0.5.4"
mkdir -p "$bucket"
artifacts=(
    minimald.apparmor minimald.apparmor-tunable install-apparmor-profile.sh
    minimal-linux-amd64 minimald-linux-amd64 mip-linux-amd64 gvproxy-linux-amd64
    minvmd-linux-amd64 minimal-linux-arm64 minimald-linux-arm64 mip-linux-arm64
    gvproxy-linux-arm64 minvmd-linux-arm64
)
for a in "${artifacts[@]}"; do
    printf 'payload of %s\n' "$a" >"$bucket/$a"
done

# A bare "AUR" repo with a committed PKGBUILD + .SRCINFO to diff against.
aur="$root/aur.git"
git init -q --bare -b master "$aur"
seed="$root/seed"
git clone -q "$aur" "$seed"
git -C "$seed" config user.email test@example.com
git -C "$seed" config user.name test
printf 'pkgname=minimal-bin\npkgver=0.0.0\n' >"$seed/PKGBUILD"
printf 'pkgname = minimal-bin\n' >"$seed/.SRCINFO"
git -C "$seed" add -A
git -C "$seed" commit -q -m seed
git -C "$seed" push -q origin master

# A `makepkg` stub: validates the PKGBUILD enough to prove the renderer's
# output was parsed, and prints a .SRCINFO the way the real one would.
mkdir -p "$root/bin"
cat >"$root/bin/makepkg" <<'EOF'
#!/usr/bin/env bash
# Stand-in for makepkg --printsrcinfo: refuses a PKGBUILD without a stamped
# pkgver, then emits one metadata line per call site.
grep -q '^pkgver=[0-9]' PKGBUILD || { echo "makepkg: PKGBUILD does not follow package ABI" >&2; exit 1; }
echo "pkgname = minimal-bin"
echo "pkgver = $(sed -n 's/^pkgver=//p' PKGBUILD)"
EOF
chmod +x "$root/bin/makepkg"
export PATH="$root/bin:$PATH"

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

run_dry() {
    # SSH_AUTH_SOCK is dropped so the harness never depends on (or uses) an
    # ambient agent's real key: the publisher falls back to the dummy
    # AUR_SSH_PRIVATE_KEY, which a file:// clone never needs.
    env -u SSH_AUTH_SOCK \
        PKGVER=0.5.4 \
        AUR_REPO_URL="file://$aur" \
        MINIMAL_BUCKET_URL="file://$root/bucket" \
        AUR_SSH_PRIVATE_KEY="not-a-real-key" \
        "$script" --dry-run
}

# --- the dry run --------------------------------------------------------------

out="$(run_dry 2>&1)"
rc=$?

if [ "$rc" -eq 0 ]; then ok "dry run succeeds against fixtures"; else bad "dry run succeeds against fixtures (rc=$rc; out: $out)"; fi
if [[ "$out" == *"nothing committed, nothing pushed"* ]]; then
    ok "dry run commits and pushes nothing"
else
    bad "dry run commits and pushes nothing (out: $out)"
fi
# Added lines must not carry unrendered tokens. Hunk headers (`@@ -1,2 +1,98
# @@`) also contain @@, so anchor to the diff's added lines.
if grep -qE '^\+.*@@' <<<"$out"; then
    bad "rendered PKGBUILD carries unrendered @@tokens@@"
else
    ok "rendered PKGBUILD carries no @@tokens@@"
fi
if [[ "$out" == *'+pkgver=0.5.4'* ]]; then
    ok "diff shows the stamped semver pkgver"
else
    bad "diff shows the stamped semver pkgver (out: $out)"
fi
if [[ "$out" == *'minvmd'* ]]; then
    ok "the package ships minvmd (source entries and checksums rendered)"
else
    bad "the package ships minvmd (source entries and checksums rendered)"
fi

# Assert the checksums are the real digests of the fixture artifacts: every
# 64-hex digest in the diff must be one of the fixture artifacts', and all 13
# must be there.
digests="$(for a in "${artifacts[@]}"; do sha256sum "$bucket/$a"; done | cut -d' ' -f1)"
stamped_ok=1
count=0
while IFS= read -r sha; do
    count=$((count + 1))
    if ! grep -qx "$sha" <<<"$digests"; then
        stamped_ok=0
    fi
done < <(grep -oE '[0-9a-f]{64}' <<<"$out" | sort -u)
if [ "$count" -eq "${#artifacts[@]}" ] && [ "$stamped_ok" -eq 1 ]; then
    ok "checksums in the diff are the artifacts' real digests"
else
    bad "checksums in the diff are the artifacts' real digests (found $count distinct, want ${#artifacts[@]})"
fi

# Nothing was pushed to the fixture remote.
pushed="$(git -C "$seed" fetch -q origin && git -C "$seed" rev-parse origin/master)"
seeded="$(git -C "$seed" rev-parse master)"
if [ "$pushed" = "$seeded" ]; then
    ok "the fixture remote is untouched"
else
    bad "the fixture remote is untouched (advanced to $pushed)"
fi

# --- refusals -----------------------------------------------------------------

expect 1 "not a RELEASED semver" "prerelease PKGVER is refused" -- \
    env PKGVER=0.6.0-rc.1 AUR_REPO_URL="file://$aur" MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --dry-run

expect 1 "cannot download" "a missing bucket artifact fails the run" -- \
    env PKGVER=9.9.9 AUR_REPO_URL="file://$aur" MINIMAL_BUCKET_URL="file://$root/bucket" \
        AUR_SSH_PRIVATE_KEY=k "$script" --dry-run

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
