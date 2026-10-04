#!/usr/bin/env bash
#
# check-answerer-links.sh — the min-answerer binary must resolve only system
# libraries.
#
# WHY: min-answerer is the always-on box-zone answerer the host's service
# manager holds as a root service (NET-122 to NET-128 in
# docs/specs/18-spec-box-networking): every process on the machine resolves
# `*.min.internal` through it, so it starts as root and runs unattended. A
# dynamic dependency it resolves from a user-writable path — or an
# RPATH/RUNPATH/LC_RPATH entry baked into the binary pointing at one — lets
# any user on the machine plant a library that root then loads: user-chosen
# code running as root. This gate fails the release naming each offender,
# so a build that would install such a service never ships.
#
# What it refuses, per OS:
#
#   * Linux (`ldd` + `readelf -d`): every ldd entry must resolve inside the
#     loader's default dirs (/lib, /lib64, /usr/lib, /usr/lib64 — their
#     multiarch subdirs included) or be the kernel's linux-vdso, and an
#     entry that resolves from nowhere is an offender too (nothing is
#     "system" until it is shown to resolve from a system dir). The binary
#     must also carry no RPATH and no RUNPATH entry at all: an embedded
#     search path decides where root loads libraries from, and every system
#     library is already on the loader's default path, so there is no
#     legitimate use for one here.
#   * macOS (`otool -L` + `otool -l`): every entry must live under /usr/lib
#     or /System, and the binary must carry no LC_RPATH load command at all
#     (minvmd's dev-build @loader_path rpath is exactly the shape a root
#     answerer must not ship — see scripts/rewrite-macos-linkage.sh for the
#     minvmd side of that rewrite).
#
# Every dependency and every rpath entry it finds is printed with its
# verdict, one line per entry, so the log shows what the binary resolves
# and why it failed. ldd honours LD_LIBRARY_PATH, so the check sees the
# binary as the invoking environment would resolve it.
#
# Usage: scripts/check-answerer-links.sh <binary>
#
# Exit codes: 0 = resolves only system libraries, no embedded search path;
# 1 = at least one offender named, or the binary could not be verified
# (the gate fails closed: an input it cannot inspect is never waved
# through).

set -euo pipefail

# die <message> — print it with the script prefix on stderr and exit 1.
die() {
    printf 'check-answerer-links: %s\n' "$1" >&2
    exit 1
}

# usage [code] — print the header comment block as help and exit.
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

if [ $# -eq 0 ]; then
    usage 1
fi
case "$1" in
    -h|--help) usage 0 ;;
    -*) die "unknown argument: $1 (try --help)" ;;
esac
[ $# -eq 1 ] || die "takes one binary, got $#"
bin="$1"
[ -f "$bin" ] || die "no such binary: $bin"

offenders=0
offender_names=""

# offender <what> <why> — record one offender and print its verdict line.
offender() {
    offenders=$((offenders + 1))
    offender_names="${offender_names:+$offender_names; }$1"
    printf 'check-answerer-links: %s — verdict: offender (%s)\n' "$1" "$2"
}

# linux_check — ldd for the dependencies, readelf -d for RPATH/RUNPATH.
linux_check() {
    command -v ldd >/dev/null 2>&1 || die "ldd is not on PATH — cannot inspect $bin"
    command -v readelf >/dev/null 2>&1 || die "readelf is not on PATH — cannot inspect $bin"

    printf 'check-answerer-links: checking %s (Linux: ldd + readelf -d)\n' "$bin"

    local ldd_out ldd_rc=0
    ldd_out="$(ldd "$bin" 2>&1)" || ldd_rc=$?

    # ldd exits 1 for a binary with no dynamic section as well — that is
    # the static case this gate passes, not an error.
    if grep -qE 'not a dynamic executable|statically linked' <<<"$ldd_out"; then
        printf 'check-answerer-links: not dynamically linked — no dynamic dependencies to check\n'
    else
        if [ "$ldd_rc" -ne 0 ]; then
            die "ldd could not inspect $bin: $ldd_out"
        fi
        local state item note
        while IFS=$'\t' read -r state item note; do
            case "$state" in
                vdso)
                    printf 'check-answerer-links: %s — verdict: ok (the kernel vDSO)\n' "$item"
                    ;;
                ok)
                    printf 'check-answerer-links: %s — verdict: ok (%s)\n' "$item" "$note"
                    ;;
                bad)
                    offender "$item" "resolves outside the loader's default dirs /lib, /lib64, /usr/lib, /usr/lib64; a root service loading a library from a user-writable path runs user-chosen code as root"
                    ;;
                missing)
                    offender "$item" "a dependency that resolves from nowhere is not provably a system library"
                    ;;
                unknown)
                    die "unrecognized ldd line for $bin: $item"
                    ;;
            esac
        done < <(
            awk '
                function sysdir(p) {
                    if (p ~ /^\/lib\//) return "/lib"
                    if (p ~ /^\/lib64\//) return "/lib64"
                    if (p ~ /^\/usr\/lib\//) return "/usr/lib"
                    if (p ~ /^\/usr\/lib64\//) return "/usr/lib64"
                    return ""
                }
                function emit(state, item, note) { print state "\t" item "\t" note }
                NF == 0 { next }
                $1 ~ /^linux-vdso/ { emit("vdso", $1, ""); next }
                $2 == "=>" && $3 == "not" && $4 == "found" { emit("missing", $1 " => not found", ""); next }
                $2 == "=>" {
                    p = $3
                    emit(sysdir(p) == "" ? "bad" : "ok", $1 " => " p, sysdir(p))
                    next
                }
                $1 ~ /^\// {
                    emit(sysdir($1) == "" ? "bad" : "ok", $1, sysdir($1))
                    next
                }
                { emit("unknown", $0, "") }
            ' <<<"$ldd_out"
        )
    fi

    local rpath_out rpath_rc=0
    rpath_out="$(readelf -d "$bin" 2>&1)" || rpath_rc=$?
    if [ "$rpath_rc" -ne 0 ]; then
        die "readelf -d could not inspect $bin: $rpath_out"
    fi

    local saw_rpath=0 tag entry
    while IFS=$'\t' read -r tag entry; do
        saw_rpath=1
        offender "($tag) $entry" "the answerer must carry no $tag entry at all: an embedded search path decides where root loads libraries from, and every system library is on the loader default path already"
    done < <(
        awk '
            $2 == "(RPATH)" || $2 == "(RUNPATH)" {
                v = $0
                sub(/^.*Library (run|r)path: \[/, "", v)
                sub(/\]$/, "", v)
                print substr($2, 2, length($2) - 2) "\t" v
            }
        ' <<<"$rpath_out"
    )
    if [ "$saw_rpath" -eq 0 ]; then
        printf 'check-answerer-links: no RPATH or RUNPATH entries — verdict: ok\n'
    fi
}

# macos_check — otool -L for the dependencies, otool -l for LC_RPATH.
macos_check() {
    command -v otool >/dev/null 2>&1 || die "otool is not on PATH (install the Xcode Command Line Tools) — cannot inspect $bin"

    printf 'check-answerer-links: checking %s (macOS: otool -L + otool -l)\n' "$bin"

    local deps_out deps_rc=0
    deps_out="$(otool -L "$bin" 2>&1)" || deps_rc=$?
    if [ "$deps_rc" -ne 0 ]; then
        die "otool -L could not inspect $bin: $deps_out"
    fi

    local state item note
    while IFS=$'\t' read -r state item note; do
        case "$state" in
            ok)
                printf 'check-answerer-links: %s — verdict: ok (%s)\n' "$item" "$note"
                ;;
            bad)
                offender "$item" "resolves outside /usr/lib and /System; a root service loading a library from a user-writable path runs user-chosen code as root"
                ;;
        esac
    done < <(
        awk '
            function emit(state, item, note) { print state "\t" item "\t" note }
            NR == 1 { next } # the binary path otool -L prints as its header
            NF == 0 { next }
            {
                n = $0
                sub(/^[ \t]+/, "", n)
                if (n ~ /:$/) { next } # a slice header (fat binaries)
                if (match(n, / \(/)) n = substr(n, 1, RSTART - 1)
                if (n ~ /^\/usr\/lib\//) emit("ok", n, "/usr/lib")
                else if (n ~ /^\/System\//) emit("ok", n, "/System")
                else emit("bad", n, "")
            }
        ' <<<"$deps_out"
    )

    local lc_out lc_rc=0
    lc_out="$(otool -l "$bin" 2>&1)" || lc_rc=$?
    if [ "$lc_rc" -ne 0 ]; then
        die "otool -l could not inspect $bin: $lc_out"
    fi

    local saw_lcrpath=0 rpath
    while IFS= read -r rpath; do
        [ -n "$rpath" ] || continue
        saw_lcrpath=1
        offender "LC_RPATH $rpath" "the answerer must carry no LC_RPATH load command at all: an embedded search path decides where root loads libraries from"
    done < <(
        awk '
            /^[ \t]*cmd / { want = ($2 == "LC_RPATH") ? 1 : 0; next }
            want && /^[ \t]*path / {
                p = $0
                sub(/^[ \t]*path[ \t]+/, "", p)
                sub(/[ \t]*\(offset [0-9]+\)[ \t]*$/, "", p)
                print p
                want = 0
            }
        ' <<<"$lc_out"
    )
    if [ "$saw_lcrpath" -eq 0 ]; then
        printf 'check-answerer-links: no LC_RPATH load commands — verdict: ok\n'
    fi
}

case "$(uname -s)" in
    Linux) linux_check ;;
    Darwin) macos_check ;;
    *)
        die "unsupported OS: $(uname -s) — this gate knows the Linux (ldd, readelf) and macOS (otool) halves; refusing to pass a binary it cannot verify"
        ;;
esac

if [ "$offenders" -gt 0 ]; then
    die "$offenders offender(s) in $bin: $offender_names — a root answerer that resolves any of these runs user-chosen code as root; link the system libraries only and strip every rpath entry, or do not ship this build"
fi

printf 'check-answerer-links: %s resolves only system libraries with no embedded search path — verdict: ok\n' "$bin"
