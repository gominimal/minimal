#!/usr/bin/env bash
#
# set-package-version_test.sh — tests for scripts/set-package-version.sh.
# Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/set-package-version.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-setversiontest)"
trap 'rm -rf "$root"' EXIT

pass=0 fail=0
ok() { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

cat >"$root/Cargo.toml" <<'TOML'
[workspace]
# package.version = "9.9.9" in a comment stays.
package.version = "0.8.0"
TOML
cat >"$root/Cargo.lock" <<'LOCK'
version = 4

[[package]]
name = "minimal"
version = "0.8.0"
dependencies = [
 "poly1305 0.8.0",
]

[[package]]
name = "poly1305"
version = "0.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "version"
version = "0.8.0"
LOCK

"$script" --repo "$root" 0.9.0 >/dev/null

if grep -qx 'package.version = "0.9.0"' "$root/Cargo.toml"; then ok "Cargo.toml moves"; else bad "Cargo.toml moves"; fi
if grep -q '# package.version = "9.9.9"' "$root/Cargo.toml"; then ok "a comment stays"; else bad "a comment stays"; fi
if [ "$(grep -c '^version = "0.9.0"$' "$root/Cargo.lock")" -eq 2 ]; then ok "workspace crates move"; else bad "workspace crates move"; fi
if grep -A1 'name = "poly1305"' "$root/Cargo.lock" | grep -q '"0.8.0"'; then ok "a registry crate keeps its version"; else bad "a registry crate keeps its version"; fi
if grep -q '"poly1305 0.8.0"' "$root/Cargo.lock"; then ok "a dependency line stays"; else bad "a dependency line stays"; fi
if head -n 1 "$root/Cargo.lock" | grep -qx 'version = 4'; then ok "the lock format line stays"; else bad "the lock format line stays"; fi

if "$script" --repo "$root" "bad version" 2>/dev/null; then bad "junk is refused"; else ok "junk is refused"; fi
if "$script" --repo "$root/nope" 0.9.1 2>/dev/null; then bad "a missing repo is refused"; else ok "a missing repo is refused"; fi

"$script" --repo "$root" 0.7.3-rc2 >/dev/null
"$script" --repo "$root" 0.7.3 >/dev/null
if [ "$(grep -c '^version = "0.7.3"$' "$root/Cargo.lock")" -eq 2 ]; then ok "a candidate moves to its final"; else bad "a candidate moves to its final"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
