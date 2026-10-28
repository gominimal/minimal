#!/usr/bin/env bash
# Check this host for the tools the justfile recipes need, and print the
# command that fixes each one that is missing.
#
#   scripts/preflight.sh          # everything (`just preflight`)
#   scripts/preflight.sh cross    # only what `cross` needs (gates `just test-cross`
#                                 # on macOS, and the cross build in
#                                 # scripts/build-initramfs.sh on macOS)
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
    # crates/remote-proto imports the well-known protos. On Debian they ship in
    # libprotobuf-dev, a package that protobuf-compiler only recommends.
    local tmp
    tmp="$(mktemp -d)"
    printf 'syntax = "proto3";\nimport "google/protobuf/empty.proto";\nimport "google/protobuf/timestamp.proto";\n' \
        >"$tmp/preflight.proto"
    local args=(--proto_path="$tmp")
    if [ -n "${PROTOC_INCLUDE:-}" ]; then args+=(--proto_path="$PROTOC_INCLUDE"); fi
    if protoc "${args[@]}" -o /dev/null "$tmp/preflight.proto" >/dev/null 2>&1; then
        ok "protobuf well-known types"
    else
        fail "protobuf well-known types (google/protobuf/*.proto)" "$fix"
    fi
    rm -rf "$tmp"
}

# check_cross [fail|warn]
check_cross() {
    local level="${1:-fail}"
    if have cross; then ok "cross"; else "$level" "cross" "cargo install cross --locked"; fi

    if have docker && docker info >/dev/null 2>&1; then
        ok "running Docker daemon"
    else
        if [ "$os" = Darwin ]; then
            "$level" "running Docker daemon" "start Docker Desktop or OrbStack"
        else
            "$level" "running Docker daemon" "install Docker Engine if it is missing, then run: sudo systemctl start docker"
        fi
    fi

    # On x86_64 Linux the host toolchain is the one cross mounts.
    if [ "$os" = Linux ] && [ "$host_arch" = x86_64 ]; then
        return
    fi
    local tc="$channel-x86_64-unknown-linux-gnu" list=""
    # Capture first: under pipefail, `grep -q` can SIGPIPE rustup into a false FAIL.
    if have rustup; then list="$(rustup toolchain list 2>/dev/null || true)"; fi
    if awk -v tc="$tc" 'index($0, tc) == 1 { found = 1 } END { exit !found }' <<<"$list"; then
        ok "x86_64 Linux toolchain for cross ($tc)"
    else
        "$level" "x86_64 Linux toolchain for cross ($tc)" \
            "rustup toolchain add $tc --profile minimal --force-non-host"
    fi
}

# native_musl: true when scripts/build-initramfs.sh can build the guest
# minimald without `cross`. Keep this in step with the detection there.
native_musl() {
    local target="$host_arch-unknown-linux-musl" list=""
    if have rustup; then list="$(rustup target list --installed 2>/dev/null || true)"; fi
    grep -qx -- "$target" <<<"$list" && have "$host_arch-linux-musl-gcc"
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
    if [ ! -e "$kvm" ]; then
        warn "$kvm is missing, so this host has no KVM (VM recipes only)" \
            "enable virtualization in the firmware or hypervisor, then run: sudo modprobe kvm_intel (Intel) or sudo modprobe kvm_amd (AMD)"
    elif [ -w "$kvm" ]; then
        ok "writable $kvm"
    else
        warn "writable $kvm (VM recipes only)" "sudo usermod -aG kvm \"\$USER\", then log in again"
    fi
    tool jq jq jq warn
    tool zstd zstd zstd warn
    tool cpio cpio cpio warn
    # Without a native musl toolchain, `just initramfs` falls back to `cross`.
    if ! native_musl; then
        check_cross warn
    fi
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
