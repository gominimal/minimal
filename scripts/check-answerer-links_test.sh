#!/usr/bin/env bash
#
# check-answerer-links_test.sh — test harness for
# scripts/check-answerer-links.sh.
#
# Builds real fixture binaries with the host's compiler and drives the gate
# against every verdict it can reach. The positives: a static Linux binary
# (and a plain dynamic one linking only loader-default dirs), and a macOS
# binary linking only /usr/lib and /System. The negatives are one fixture
# each, so a failure is attributable to its class: a dependency resolved
# from a user-writable path (a non-system .so on Linux, a non-system dylib
# on macOS), an RPATH entry, a RUNPATH entry, and — on macOS — an LC_RPATH
# load command. Every negative asserts the check fails *and names the
# offender*: a red gate that does not say why is the failure mode the
# diagnostics exist to prevent.
#
# Each OS runs only its own half — the Linux fixtures need ldd/readelf and
# the macOS ones need otool, and no host here builds for the other. The
# half that does not run says so on one named line: it is skipped, never
# silently. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-answerer-links.sh"
[ -f "$script" ] || { echo "cannot find check-answerer-links.sh next to test" >&2; exit 1; }

pass=0 fail=0 skip=0
# ok / bad / skip <description> — count and print one case.
ok()   { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad()  { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }
skip() { skip=$((skip + 1)); printf 'skip - %s\n' "$*"; }

# expect <want_rc> <want_substring> <description> -- <command...>
#   Asserts the command's exit code and that its combined output carries the
#   substring — the substring is how "names the offender" is asserted.
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

# build <output> <compiler-args...> — compile one fixture. A host that
# cannot build the fixtures cannot prove the gate, so this fails loudly
# rather than skipping to green.
build() {
    local out="$1"; shift
    if ! "$@" -o "$out"; then
        printf 'check-answerer-links_test: cannot build fixture %s with: %s\n' "$out" "$*" >&2
        exit 1
    fi
}

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-answererlinks)"
trap 'rm -rf "$root"' EXIT

# Two mains and one answer body: hello.c is self-contained (every fixture
# that offends through the search path), hello_linked.c calls into the
# fixture library so --as-needed can never drop it from DT_NEEDED.
printf 'int main(void) { return 0; }\n' >"$root/hello.c"
printf 'extern int fixture_answer(void);\nint main(void) { return fixture_answer(); }\n' >"$root/hello_linked.c"
printf 'int fixture_answer(void) { return 42; }\n' >"$root/answer.c"

os="$(uname -s)"

if [ "$os" = Linux ]; then
    # --- the Linux half ------------------------------------------------------
    missing=""
    for tool in gcc ldd readelf; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [ -n "$missing" ]; then
        skip "linux half: no$missing on PATH — the static, dynamic, non-system .so, RPATH and RUNPATH fixtures were not built or checked"
    else
        # Positives: nothing to resolve at all, and everything from the
        # loader's default dirs.
        build "$root/static" gcc -static "$root/hello.c"
        expect 0 "no dynamic dependencies" "the static binary passes" -- \
            "$script" "$root/static"

        build "$root/dynamic" gcc "$root/hello.c"
        expect 0 "resolves only system libraries" "a system-only dynamic binary passes" -- \
            "$script" "$root/dynamic"

        # Negative: a dependency resolved from a user-writable directory.
        # LD_LIBRARY_PATH is how the loader reaches it without giving the
        # fixture an rpath entry, so this binary offends in one class only.
        build "$root/libfixture.so" gcc -shared -fPIC "$root/answer.c"
        build "$root/non_system" gcc "$root/hello_linked.c" -L"$root" -lfixture
        expect 1 "$root/libfixture.so" "a non-system .so fails the gate named" -- \
            env LD_LIBRARY_PATH="$root" "$script" "$root/non_system"
        expect 1 "libfixture.so => not found" "a dependency that resolves from nowhere fails the gate named" -- \
            "$script" "$root/non_system"

        # Negatives: one embedded-search-path fixture per ELF tag, each
        # carrying no non-system dependency, so the tag alone offends.
        mkdir "$root/rpath_dir" "$root/runpath_dir"
        build "$root/rpath_fixture" gcc "$root/hello.c" -Wl,--disable-new-dtags -Wl,-rpath,"$root/rpath_dir"
        expect 1 "(RPATH)" "an RPATH entry fails the gate" -- "$script" "$root/rpath_fixture"
        expect 1 "$root/rpath_dir" "the RPATH entry is named with its directory" -- "$script" "$root/rpath_fixture"

        build "$root/runpath_fixture" gcc "$root/hello.c" -Wl,--enable-new-dtags -Wl,-rpath,"$root/runpath_dir"
        expect 1 "(RUNPATH)" "a RUNPATH entry fails the gate" -- "$script" "$root/runpath_fixture"
        expect 1 "$root/runpath_dir" "the RUNPATH entry is named with its directory" -- "$script" "$root/runpath_fixture"

        # Fail closed: ldd calls a non-ELF input "not a dynamic executable"
        # just like a static binary, and the readelf leg must refuse it.
        expect 1 "readelf -d could not inspect" "a non-ELF input is refused, not waved through as static" -- \
            "$script" "$root/hello.c"
    fi
    skip "macos half: not run on $os (otool and a Mach-O toolchain are a macOS concern) — the /usr/lib-only positive, the non-system dylib negative and the LC_RPATH negative were not checked here; run this harness on macOS"
elif [ "$os" = Darwin ]; then
    # --- the macOS half ------------------------------------------------------
    missing=""
    for tool in clang otool; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [ -n "$missing" ]; then
        skip "macos half: no$missing on PATH — the /usr/lib-only positive, the non-system dylib negative and the LC_RPATH negative were not built or checked"
    else
        # Positive: the default link is libSystem only, under /usr/lib.
        build "$root/positive" clang "$root/hello.c"
        expect 0 "resolves only system libraries" "a macOS binary linking only /usr/lib and /System passes" -- \
            "$script" "$root/positive"

        # Negative: a dependency whose install name is this harness's own
        # temp directory — user-writable, and no LC_RPATH needed to reach
        # it, so this binary offends in one class only.
        build "$root/libfixture.dylib" clang -dynamiclib "$root/answer.c"
        build "$root/non_system" clang "$root/hello_linked.c" "$root/libfixture.dylib"
        expect 1 "$root/libfixture.dylib" "a non-system dylib fails the gate named" -- \
            "$script" "$root/non_system"

        # Negative: an LC_RPATH load command, on a binary whose only
        # dependency is libSystem.
        mkdir "$root/lcrpath_dir"
        build "$root/lcrpath_fixture" clang "$root/hello.c" -Wl,-rpath,"$root/lcrpath_dir"
        expect 1 "LC_RPATH" "an LC_RPATH load command fails the gate" -- "$script" "$root/lcrpath_fixture"
        expect 1 "$root/lcrpath_dir" "the LC_RPATH entry is named with its path" -- "$script" "$root/lcrpath_fixture"
    fi
    skip "linux half: not run on $os (ldd/readelf and an ELF toolchain are a Linux concern) — the static and dynamic positives, the non-system .so negative and the RPATH and RUNPATH negatives were not checked here; run this harness on Linux"
else
    skip "linux half: not run on $os (no ldd/readelf) — the Linux fixtures were not built or checked here"
    skip "macos half: not run on $os (no otool) — the macOS fixtures were not built or checked here"
fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
