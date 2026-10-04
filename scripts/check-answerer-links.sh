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
#   * Linux (`readelf -l`, then `ldd`, then `readelf -d`): the program
#     interpreter (PT_INTERP) must be a system loader path — root runs it
#     before any library, so it is the first thing checked, and a binary
#     that is statically linked has none and passes. Every ldd entry must
#     resolve inside the loader's default dirs (/lib, /lib64, /usr/lib,
#     /usr/lib64 — their multiarch subdirs included) or be the kernel's
#     vDSO (linux-vdso, or linux-gate on 32-bit x86), and an entry that
#     resolves from nowhere is an offender too (nothing is "system" until
#     it is shown to resolve from a system dir). The binary must also
#     carry no RPATH and no RUNPATH entry at all: an embedded search path decides where root loads libraries
#     from, and every system library is already on the loader's default
#     path, so there is no legitimate use for one here.
#   * macOS (`otool -L` + `otool -l`): every entry must live under /usr/lib
#     or /System, and the binary must carry no LC_RPATH load command at all
#     (minvmd's dev-build @loader_path rpath is exactly the shape a root
#     answerer must not ship — see scripts/rewrite-macos-linkage.sh for the
#     minvmd side of that rewrite).
#
# "Inside a system dir" means a whole path component: a path is in /usr/lib
# only when it starts /usr/lib/, so /usr/local/lib, /usr/lib-x and
# /usr/libexec are not /usr/lib; and no path the gate accepts may carry a
# `..` component, which the loader walks to wherever it lands —
# /usr/lib/../../tmp/libnope.so starts inside a system dir and names a place
# root would load from.
#
# Every path it inspects — the interpreter, each dependency, each rpath
# entry — is printed with its verdict, one line per entry, so the log shows
# what the binary resolves and why it failed. The service manager starts
# the answerer with a clean environment, so ldd runs under
# `env -u LD_LIBRARY_PATH -u LD_PRELOAD`: the verdict must not depend on
# who ran the gate or on what their environment would have injected into
# the loader's search path.
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

# system_dir <path> — the system directory a path lives under, or nothing.
# The prefix has to be a whole path component: /usr/local/lib, /usr/lib-x
# and /usr/libexec do not start /usr/lib/, so they are not /usr/lib. Which
# directories count depends on the half being run (`gate_os`, set in the
# dispatch below): the loader's default dirs on Linux, /usr/lib and /System
# on macOS.
system_dir() {
    if [ "$gate_os" = Darwin ]; then
        case "$1" in
            /usr/lib/*)   printf '/usr/lib' ;;
            /System/*)    printf '/System' ;;
        esac
    else
        case "$1" in
            /lib/*)       printf '/lib' ;;
            /lib64/*)     printf '/lib64' ;;
            /usr/lib/*)   printf '/usr/lib' ;;
            /usr/lib64/*) printf '/usr/lib64' ;;
        esac
    fi
}

# carries_dotdot <path> — true when the path has a `..` component. The
# loader walks such a path to wherever it lands, so a system-dir prefix
# proves nothing about where it ends up.
carries_dotdot() {
    [[ $1 =~ (^|/)\.\.(/|$) ]]
}

# path_state <path> — the shared verdict for one path: "dotdot" when it
# carries a `..` component, "bad" when it lives under none of the system
# dirs, or the system dir it lives under (the ok case). Every path the gate
# inspects — dependencies, install names, the program interpreter — goes
# through here, so the component rule is one rule on every OS.
path_state() {
    if carries_dotdot "$1"; then
        printf 'dotdot'
    else
        local dir
        dir="$(system_dir "$1")"
        if [ -n "$dir" ]; then
            printf '%s' "$dir"
        else
            printf 'bad'
        fi
    fi
}

# classify_dep <item> <path> — the verdict line for one resolved
# dependency: an ldd entry on Linux, an install name on macOS.
classify_dep() {
    local item="$1" path="$2" state
    state="$(path_state "$path")"
    case "$state" in
        bad)
            offender "$item" "resolves outside $sysdirs; a root service loading a library from a user-writable path runs user-chosen code as root"
            ;;
        dotdot)
            offender "$item" "carries a '..' path component; the loader walks it to wherever it lands, which is not provably a system directory"
            ;;
        *)
            printf 'check-answerer-links: %s — verdict: ok (%s)\n' "$item" "$state"
            ;;
    esac
}

# linux_check — readelf -l for the interpreter, ldd for the dependencies,
# readelf -d for RPATH/RUNPATH.
linux_check() {
    command -v ldd >/dev/null 2>&1 || die "ldd is not on PATH — cannot inspect $bin"
    command -v readelf >/dev/null 2>&1 || die "readelf is not on PATH — cannot inspect $bin"

    printf 'check-answerer-links: checking %s (Linux: readelf -l, ldd, readelf -d)\n' "$bin"

    # The program interpreter first: root runs it before any library, and
    # the string is baked into the binary, so a loader path that is not
    # provably the system's is user-chosen code running as root before
    # anything else loads. A statically linked binary has none.
    local interp_out interp_rc=0 interp interp_state interp_seen=0
    interp_out="$(readelf -l "$bin" 2>&1)" || interp_rc=$?
    if [ "$interp_rc" -ne 0 ]; then
        die "readelf -l could not inspect $bin: $interp_out"
    fi
    while IFS= read -r interp; do
        [ -n "$interp" ] || continue
        interp_seen=$((interp_seen + 1))
        interp_state="$(path_state "$interp")"
        case "$interp_state" in
            bad)
                offender "interpreter $interp" "the program interpreter is not a system loader path: root runs it before any library, so a loader a user could plant there is user-chosen code running as root"
                ;;
            dotdot)
                offender "interpreter $interp" "the program interpreter carries a '..' path component; the loader walks it to wherever it lands, which is not provably a system loader"
                ;;
            *)
                printf 'check-answerer-links: interpreter %s — verdict: ok (%s)\n' "$interp" "$interp_state"
                ;;
        esac
    done < <(
        awk '
            /Requesting program interpreter:/ {
                s = $0
                sub(/^.*Requesting program interpreter: /, "", s)
                sub(/\]$/, "", s)
                print s
            }
        ' <<<"$interp_out"
    )
    if [ "$interp_seen" -eq 0 ]; then
        printf 'check-answerer-links: no program interpreter (statically linked) — verdict: ok\n'
    fi

    # ldd, under a scrubbed loader environment: the answerer is started by
    # the service manager with a clean environment, so a verdict that
    # depended on LD_LIBRARY_PATH or LD_PRELOAD would depend on who ran the
    # gate rather than on what the release ships.
    local ldd_out ldd_rc=0 state item path
    ldd_out="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD ldd "$bin" 2>&1)" || ldd_rc=$?

    # ldd exits 1 for a binary with no dynamic section as well — that is
    # the static case this gate passes, not an error.
    if grep -qE 'not a dynamic executable|statically linked' <<<"$ldd_out"; then
        printf 'check-answerer-links: not dynamically linked — no dynamic dependencies to check\n'
    else
        if [ "$ldd_rc" -ne 0 ]; then
            die "ldd could not inspect $bin: $ldd_out"
        fi
        while IFS=$'\t' read -r state item path; do
            case "$state" in
                vdso)
                    printf 'check-answerer-links: %s — verdict: ok (the kernel vDSO)\n' "$item"
                    ;;
                missing)
                    offender "$item" "a dependency that resolves from nowhere is not provably a system library"
                    ;;
                dep)
                    classify_dep "$item" "$path"
                    ;;
                unknown)
                    die "unrecognized ldd line for $bin: $item"
                    ;;
            esac
        done < <(
            awk '
                function emit(s, i, p) { print s "\t" i "\t" p }
                NF == 0 { next }
                # glibc ldd warns about a missing exec bit, then lists the
                # dependencies as usual: the warning is not one of them.
                /^ldd: warning: you do not have execution permission/ { next }
                $1 ~ /^linux-(vdso|gate)\.so/ { emit("vdso", $1, ""); next }
                $2 == "=>" && $3 == "not" && $4 == "found" {
                    emit("missing", $1 " => not found", "")
                    next
                }
                $2 == "=>" { emit("dep", $1 " => " $3, $3); next }
                $1 ~ /^\// { emit("dep", $1, $1); next }
                { emit("unknown", $0, "") }
            ' <<<"$ldd_out"
        )
    fi

    local rpath_out rpath_rc=0 saw_rpath=0 tag entry
    rpath_out="$(readelf -d "$bin" 2>&1)" || rpath_rc=$?
    if [ "$rpath_rc" -ne 0 ]; then
        die "readelf -d could not inspect $bin: $rpath_out"
    fi
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

    local deps_out deps_rc=0 path
    deps_out="$(otool -L "$bin" 2>&1)" || deps_rc=$?
    if [ "$deps_rc" -ne 0 ]; then
        die "otool -L could not inspect $bin: $deps_out"
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        classify_dep "$path" "$path"
    done < <(
        awk '
            NR == 1 { next } # the binary path otool -L prints as its header
            NF == 0 { next }
            {
                n = $0
                sub(/^[ \t]+/, "", n)
                if (n ~ /:$/) { next } # a slice header (fat binaries)
                if (match(n, / \(/)) n = substr(n, 1, RSTART - 1)
                print n
            }
        ' <<<"$deps_out"
    )

    local lc_out lc_rc=0 saw_lcrpath=0 rpath
    lc_out="$(otool -l "$bin" 2>&1)" || lc_rc=$?
    if [ "$lc_rc" -ne 0 ]; then
        die "otool -l could not inspect $bin: $lc_out"
    fi
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

gate_os=""
sysdirs=""
case "$(uname -s)" in
    Linux)
        gate_os=Linux
        sysdirs="the loader's default dirs /lib, /lib64, /usr/lib, /usr/lib64"
        linux_check
        ;;
    Darwin)
        gate_os=Darwin
        sysdirs='/usr/lib and /System'
        macos_check
        ;;
    *)
        die "unsupported OS: $(uname -s) — this gate knows the Linux (readelf, ldd) and macOS (otool) halves; refusing to pass a binary it cannot verify"
        ;;
esac

if [ "$offenders" -gt 0 ]; then
    die "$offenders offender(s) in $bin: $offender_names — a root answerer that resolves any of these runs user-chosen code as root; link the system libraries only and strip every rpath entry, or do not ship this build"
fi

printf 'check-answerer-links: %s resolves only system libraries with no embedded search path — verdict: ok\n' "$bin"
