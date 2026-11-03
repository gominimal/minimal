#!/usr/bin/env bash
#
# preflight_test.sh — test harness for scripts/preflight.sh.
#
# Every tool the script probes is a stub in a fake bin dir at the front of
# PATH, with a stubbed `uname` picking the OS branch, so each case runs the
# same on any host. A missing tool is simulated only for tools no base system
# ships in /usr/bin (rustup toolchains, Docker, protoc, libkrun), because the
# real /usr/bin stays on PATH for sed, awk and grep.
#
# Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/preflight.sh"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$here/../rust-toolchain.toml")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
pass() { echo "ok   $1"; }
bad() {
    echo "FAIL $1"
    failures=$((failures + 1))
}

# stub <name> <body>: an executable named <name> in the current fake bin dir.
stub() {
    printf '#!/bin/sh\n%s\n' "$2" >"$bin/$1"
    chmod +x "$bin/$1"
}

# setup <Darwin|Linux> <arch>: a fresh fake bin dir where every check passes.
setup() {
    bin="$work/bin-$RANDOM"
    brew_prefix="$work/brew-$RANDOM"
    mkdir -p "$bin" "$brew_prefix/lib"
    touch "$brew_prefix/lib/libkrun.dylib" "$work/kvm"
    stub uname "case \"\$1\" in -s) echo $1 ;; -m) echo $2 ;; esac"
    stub rustup "echo '$channel-aarch64-apple-darwin (active)'; echo '$channel-x86_64-unknown-linux-gnu'"
    stub docker 'exit 0'
    stub protoc 'echo "libprotoc 25.1"'
    stub brew "echo $brew_prefix"
    stub pkg-config 'exit 0'
    local t
    for t in cross python3 codesign otool install_name_tool jq zstd cpio cc git; do
        stub "$t" 'exit 0'
    done
}

# run <mode>: run preflight against the current fake bin dir.
run() {
    out="$(PATH="$bin:/usr/bin:/bin" PREFLIGHT_KVM_DEV="$work/kvm" bash "$script" "$1" 2>&1)" && rc=0 || rc=$?
}

expect() { # expect <case> <rc> <substring>
    if [ "$rc" -ne "$2" ]; then
        bad "$1: exit $rc, want $2"$'\n'"$out"
    elif ! grep -qF -- "$3" <<<"$out"; then
        bad "$1: output lacks '$3'"$'\n'"$out"
    else
        pass "$1"
    fi
}

setup Darwin arm64
run all
expect "macOS, everything present" 0 "all required checks passed"

# The reported failure: an arm64 Mac without the x86_64 Linux toolchain.
setup Darwin arm64
stub rustup "echo '$channel-aarch64-apple-darwin (active)'"
run cross
expect "macOS, no x86_64 Linux toolchain" 1 \
    "rustup toolchain add $channel-x86_64-unknown-linux-gnu --profile minimal --force-non-host"

setup Darwin arm64
stub docker 'exit 1'
run cross
expect "macOS, Docker daemon down" 1 "FAIL  running Docker daemon"

setup Darwin arm64
rm "$brew_prefix/lib/libkrun.dylib"
run all
expect "macOS, no libkrun" 1 "brew install slp/krun/libkrun"

setup Darwin arm64
stub protoc 'echo "libprotoc 3.12.4"'
run all
expect "protoc too old for proto3 optional" 1 "FAIL  protoc 3.15 or later (found 3.12.4)"

setup Linux x86_64
# shellcheck disable=SC2016 # $1 expands inside the stub, not here.
stub protoc 'case "$1" in --version) echo "libprotoc 3.21.12" ;; *) exit 1 ;; esac'
run all
expect "Linux, no well-known protos" 1 \
    "FAIL  protobuf well-known types (google/protobuf/*.proto)"$'\n'"        fix: sudo apt install protobuf-compiler libprotobuf-dev"

# The toolchain name is a fixed-string prefix: the dots in the channel are not wildcards.
setup Darwin arm64
stub rustup "echo '${channel//./x}-x86_64-unknown-linux-gnu'"
run cross
expect "macOS, toolchain name matched literally" 1 "--force-non-host"

setup Darwin arm64
stub docker 'exit 1'
run all
expect "macOS, full run also checks cross" 1 "FAIL  running Docker daemon"

# x86_64 Linux mounts its own host toolchain, so no non-host toolchain is needed.
setup Linux x86_64
stub rustup "echo '$channel-x86_64-unknown-linux-gnu (active)'"
run cross
if grep -qF "x86_64 Linux toolchain" <<<"$out"; then
    bad "x86_64 Linux, cross: checked a non-host toolchain"$'\n'"$out"
else
    expect "x86_64 Linux, cross" 0 "all required checks passed"
fi

setup Linux aarch64
stub rustup "echo '$channel-aarch64-unknown-linux-gnu (active)'"
run cross
expect "arm64 Linux, no x86_64 Linux toolchain" 1 "--force-non-host"

setup Linux x86_64
rm "$work/kvm"
run all
expect "Linux, no /dev/kvm only warns" 0 "warn  $work/kvm is missing, so this host has no KVM"
if grep -qF "usermod" <<<"$out"; then
    bad "Linux, no /dev/kvm: offered the kvm group fix"$'\n'"$out"
fi

# Root can write any file, so only a non-root run can see an unwritable device.
if [ "$(id -u)" -ne 0 ]; then
    setup Linux x86_64
    chmod a-w "$work/kvm"
    run all
    expect "Linux, unwritable /dev/kvm only warns" 0 "sudo usermod -aG kvm"
    chmod u+w "$work/kvm"
fi

# Without a native musl toolchain, `just initramfs` falls back to cross.
setup Linux x86_64
stub docker 'exit 1'
run all
expect "Linux, no native musl, Docker down only warns" 0 "warn  running Docker daemon"

setup Linux x86_64
stub docker 'exit 1'
# shellcheck disable=SC2016 # $1 expands inside the stub, not here.
stub rustup 'case "$1" in target) echo x86_64-unknown-linux-musl ;; *) echo x ;; esac'
stub x86_64-linux-musl-gcc 'exit 0'
run all
if grep -qF "Docker daemon" <<<"$out"; then
    bad "Linux, native musl: checked cross"$'\n'"$out"
else
    expect "Linux, native musl skips the cross checks" 0 "all required checks passed"
fi
FORCE_CROSS=1 run all
expect "Linux, native musl with FORCE_CROSS=1 checks cross" 0 "warn  running Docker daemon"

setup Linux x86_64
stub pkg-config 'exit 1'
run all
expect "Linux, no OpenSSL headers" 1 "sudo apt install libssl-dev"

bash "$script" bogus >/dev/null 2>&1 && rc=0 || rc=$?
if [ "$rc" -eq 2 ]; then pass "unknown mode is a usage error"; else bad "unknown mode: exit $rc, want 2"; fi

if [ "$failures" -gt 0 ]; then
    echo "$failures case(s) failed"
    exit 1
fi
echo "all preflight cases passed"
