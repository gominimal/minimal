#!/usr/bin/env bash
# Check this host for the tools the justfile recipes need, and print the
# command that fixes each one that is missing.
#
#   scripts/preflight.sh          # everything (`just preflight`)
#   scripts/preflight.sh cross    # only what `cross` needs (gates `just initramfs`
#                                 # and `just test-cross` on macOS)
#
# Installs nothing. Exits 1 when a required check fails. A check marked `warn`
# covers a tool only some recipes need, and never fails the run.
#
# The list mirrors AGENTS.md §System dependencies; change both together.
#
# Why the cross checks exist: the cross-rs images are x86_64 Linux, and `cross`
# runs the compiler from the HOST's rustup toolchain for that platform
# (<channel>-x86_64-unknown-linux-gnu). On any host that is not x86_64 Linux,
# rustup refuses to install that toolchain without --force-non-host, which
# `cross` does not pass, so the build dies with "couldn't install toolchain".
#
# PREFLIGHT_KVM_DEV overrides /dev/kvm (for scripts/preflight_test.sh).
set -euo pipefail

mode="${1:-all}"
case "$mode" in
    all | cross) ;;
    *) echo "usage: scripts/preflight.sh [all|cross]" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
os="$(uname -s)"
host_arch="$(uname -m)"

failed=0

ok() { printf '  ok    %s\n' "$1"; }
fail() {
    printf '  FAIL  %s\n        fix: %s\n' "$1" "$2"
    failed=$((failed + 1))
}
warn() { printf '  warn  %s\n        fix: %s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

# pkg <brew formula> <apt package>: the install command for this OS.
pkg() {
    if [ "$os" = Darwin ]; then echo "brew install $1"; else echo "sudo apt install $2"; fi
}

# tool <command> <brew formula> <apt package> [fail|warn]
tool() {
    if have "$1"; then ok "$1"; else "${4:-fail}" "$1" "$(pkg "$2" "$3")"; fi
}

check_rustup() {
    if have rustup; then
        ok "rustup"
    else
        fail "rustup" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi
}

check_protoc() {
    local fix
    fix="$(pkg protobuf "protobuf-compiler libprotobuf-dev")"
    if ! have protoc; then
        fail "protoc" "$fix"
        return
    fi
    # proto3 `optional` needs protoc 3.15 or later (crates/remote-proto).
    local v major minor
    v="$(protoc --version | awk '{print $2}')"
    major="${v%%.*}"
    minor="$(echo "$v" | cut -d. -f2)"
    if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 15 ]; }; then
        ok "protoc $v"
    else
        fail "protoc 3.15 or later (found $v)" "$fix"
    fi
}

check_cross() {
    if have cross; then ok "cross"; else fail "cross" "cargo install cross --locked"; fi

    if have docker && docker info >/dev/null 2>&1; then
        ok "running Docker daemon"
    else
        fail "running Docker daemon" "start Docker Desktop or OrbStack"
    fi

    # On x86_64 Linux the host toolchain is the one cross mounts.
    if [ "$os" = Linux ] && [ "$host_arch" = x86_64 ]; then
        return
    fi
    local tc="$channel-x86_64-unknown-linux-gnu"
    if have rustup && rustup toolchain list | grep -q "^$tc"; then
        ok "x86_64 Linux toolchain for cross ($tc)"
    else
        fail "x86_64 Linux toolchain for cross ($tc)" \
            "rustup toolchain add $tc --profile minimal --force-non-host"
    fi
}

check_macos() {
    local t
    for t in codesign otool install_name_tool; do
        if have "$t"; then ok "$t"; else fail "$t" "xcode-select --install"; fi
    done
    local prefix
    prefix="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
    if [ -e "$prefix/lib/libkrun.dylib" ]; then
        ok "libkrun"
    else
        fail "libkrun" "brew install slp/krun/libkrun"
    fi
    tool jq jq jq
    tool zstd zstd zstd
    tool cpio cpio cpio
}

check_linux() {
    tool cc gcc build-essential
    tool git git git
    tool pkg-config pkg-config pkg-config
    if have pkg-config && pkg-config --exists openssl; then
        ok "OpenSSL headers"
    else
        fail "OpenSSL headers" "sudo apt install libssl-dev"
    fi
    # The VM recipes (up-kvm, test-vm, e2e) need these; the native stack does not.
    local kvm="${PREFLIGHT_KVM_DEV:-/dev/kvm}"
    if [ -e "$kvm" ] && [ -w "$kvm" ]; then
        ok "writable $kvm"
    else
        warn "writable $kvm (VM recipes only)" "sudo usermod -aG kvm \"\$USER\", then log in again"
    fi
    tool jq jq jq warn
    tool zstd zstd zstd warn
    tool cpio cpio cpio warn
}

echo "preflight: $os $host_arch, Rust $channel"
check_rustup
if [ "$mode" = all ]; then
    check_protoc
    tool python3 python python3
    case "$os" in
        Darwin) check_macos ;;
        Linux) check_linux ;;
    esac
fi
if [ "$mode" = cross ] || [ "$os" = Darwin ]; then
    check_cross
fi

if [ "$failed" -gt 0 ]; then
    echo "preflight: $failed check(s) failed; run each fix above, then run this again" >&2
    exit 1
fi
echo "preflight: all required checks passed"
