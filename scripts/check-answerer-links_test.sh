#!/usr/bin/env bash
#
# check-answerer-links_test.sh — test harness for
# scripts/check-answerer-links.sh.
#
# Two halves:
#
#   * the native half builds real fixture binaries with the host's compiler
#     and drives the gate with the host's real tools. The positives: a
#     static Linux binary (and a plain dynamic one linking only
#     loader-default dirs), and a macOS binary linking only /usr/lib and
#     /System. The negatives are one fixture each, so a failure is
#     attributable to its class: a dependency resolved from a
#     user-writable path (a non-system .so on Linux, a non-system dylib on
#     macOS), a dependency spelled with a `..` component, an RPATH entry, a
#     RUNPATH entry, a non-system program interpreter (Linux), and — on
#     macOS — an LC_RPATH load command. Every negative asserts the check
#     fails *and names the offender*: a red gate that does not say why is
#     the failure mode the diagnostics exist to prevent.
#   * the table half feeds the gate canned ldd/readelf/otool output through
#     a fake bin dir on PATH, with a stubbed `uname` picking the branch. It
#     exists because the paths the component rule has to refuse cannot be
#     built: /usr/local/lib takes root to write, and a loader would not
#     keep a `..`-spelled dependency canonical. The table half needs no
#     toolchain, so it runs on every host — which is also why the macOS
#     half's parsing is checked here at all: no macOS CI lane runs this
#     harness (crates/common's shell-harnesses gate runs on the Linux
#     lanes only), so a macOS-only parsing bug would otherwise ship
#     unnoticed.
#
# Each OS runs only its own native half — the Linux fixtures need
# gcc/ldd/readelf and the macOS ones need clang/otool, and no host here
# builds for the other. The native half that does not run says so on one
# named line: it is skipped, never silently. Run directly or via
# `just test-shell`.

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

# The table cases pass this file where the binary would go: every tool that
# could look at it is canned, so its contents never matter — and if a fake
# went missing, the real tool would refuse it and the case would fail
# loudly instead of passing on nothing.
printf 'table input: the tools are canned in these cases, so this is never read\n' >"$root/table-input"

os="$(uname -s)"

if [ "$os" = Linux ]; then
    # --- the Linux native half -----------------------------------------------
    missing=""
    for tool in gcc ldd readelf; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [ -n "$missing" ]; then
        skip "linux native half: no$missing on PATH — the static, dynamic, non-system .so, ..-spelled, RPATH, RUNPATH and interpreter fixtures were not built or checked here (the Linux parsing is still table-checked below)"
    else
        # Positives: nothing to resolve at all, and everything from the
        # loader's default dirs — including the interpreter the dynamic
        # one carries.
        build "$root/static" gcc -static "$root/hello.c"
        expect 0 "no program interpreter" "the static binary passes, with no interpreter to check" -- \
            "$script" "$root/static"
        expect 0 "no dynamic dependencies" "the static binary passes" -- \
            "$script" "$root/static"

        build "$root/dynamic" gcc "$root/hello.c"
        expect 0 "resolves only system libraries" "a system-only dynamic binary passes" -- \
            "$script" "$root/dynamic"
        expect 0 "interpreter" "the system program interpreter is checked and passes" -- \
            "$script" "$root/dynamic"

        # The gate scrubs the loader environment (the answerer is started
        # with a clean one), so a dirty environment changes no verdict: the
        # positive stays a positive, and LD_LIBRARY_PATH cannot rescue a
        # dependency the clean environment cannot resolve.
        expect 0 "resolves only system libraries" "LD_LIBRARY_PATH at a non-system dir does not change the verdict on the positive fixture" -- \
            env LD_LIBRARY_PATH="$root" "$script" "$root/dynamic"

        # Negative: a dependency resolved from a user-writable directory.
        # Linking the fixture library by path (it has no SONAME) records
        # that path in DT_NEEDED, and the loader loads an absolute DT_NEEDED
        # directly — no LD_LIBRARY_PATH, no rpath — so this binary offends
        # in exactly one class: it really resolves a library from outside
        # the system dirs.
        build "$root/libfixture.so" gcc -shared -fPIC "$root/answer.c"
        build "$root/non_system" gcc "$root/hello_linked.c" -Wl,--no-as-needed "$root/libfixture.so"
        expect 1 "$root/libfixture.so" "a non-system .so fails the gate named" -- \
            "$script" "$root/non_system"

        # Negative: a dependency that resolves from nowhere (a -l name the
        # clean environment cannot find). LD_LIBRARY_PATH at the directory
        # that really holds it does not rescue it, which is the scrub being
        # proved rather than asserted.
        build "$root/not_found" gcc "$root/hello_linked.c" -Wl,--no-as-needed -L"$root" -lfixture
        expect 1 "libfixture.so => not found" "a dependency that resolves from nowhere fails the gate named" -- \
            "$script" "$root/not_found"
        expect 1 "libfixture.so => not found" "LD_LIBRARY_PATH cannot rescue it: the gate scrubs the loader environment" -- \
            env LD_LIBRARY_PATH="$root" "$script" "$root/not_found"

        # Negative: a `..`-spelled dependency. DT_NEEDED records the path
        # exactly as it was named to the linker, so the path is spelled
        # /<system dir>/../../<the temp dir>: it starts inside a system dir
        # — the prefix a prefix-only rule would accept — and the loader
        # walks it out to this harness's own directory. /<system dir>/../..
        # is /, so the path names the library that is really there.
        dotprefix=""
        for d in /usr/lib /usr/lib64 /lib /lib64; do
            if [ -d "$d" ]; then
                dotprefix="$d"
                break
            fi
        done
        if [ -n "$dotprefix" ]; then
            dotted="$dotprefix/../../${root#/}/libfixture.so"
            build "$root/dotdep" gcc "$root/hello_linked.c" -Wl,--no-as-needed "$dotted"
            expect 1 "$dotted" "a dependency spelled with .. fails the gate named" -- \
                "$script" "$root/dotdep"
            expect 1 "..' path component" "a dependency spelled with .. is named as a .. path, not merely as a non-system one" -- \
                "$script" "$root/dotdep"
        else
            skip "the ..-spelled dependency fixture: no /lib, /lib64, /usr/lib or /usr/lib64 to spell the path from (the .. rule is still table-checked below)"
        fi

        # Negatives: one embedded-search-path fixture per ELF tag, each
        # carrying no non-system dependency, so the tag alone offends.
        mkdir "$root/rpath_dir" "$root/runpath_dir"
        build "$root/rpath_fixture" gcc "$root/hello.c" -Wl,--disable-new-dtags -Wl,-rpath,"$root/rpath_dir"
        expect 1 "(RPATH)" "an RPATH entry fails the gate" -- "$script" "$root/rpath_fixture"
        expect 1 "$root/rpath_dir" "the RPATH entry is named with its directory" -- "$script" "$root/rpath_fixture"

        build "$root/runpath_fixture" gcc "$root/hello.c" -Wl,--enable-new-dtags -Wl,-rpath,"$root/runpath_dir"
        expect 1 "(RUNPATH)" "a RUNPATH entry fails the gate" -- "$script" "$root/runpath_fixture"
        expect 1 "$root/runpath_dir" "the RUNPATH entry is named with its directory" -- "$script" "$root/runpath_fixture"

        # Negative: a program interpreter outside the system loader paths.
        # The interpreter string is recorded at link time and needs to
        # exist nowhere for the gate to see it — and ldd, which maps a
        # non-system interpreter onto the system loader and reports it
        # satisfied, would not catch it on its own.
        build "$root/interp_fixture" gcc "$root/hello.c" -Wl,--dynamic-linker="$root/evil-loader.so"
        expect 1 "$root/evil-loader.so" "a non-system program interpreter fails the gate named" -- \
            "$script" "$root/interp_fixture"

        # Fail closed: a non-ELF input. readelf -l runs first on Linux, so
        # that is the leg that refuses it — never waved through as static.
        expect 1 "readelf -l could not inspect" "a non-ELF input is refused, not waved through as static" -- \
            "$script" "$root/hello.c"
    fi
    skip "macos native half: not run on $os (otool and a Mach-O toolchain are a macOS concern) — the /usr/lib-only positive, the non-system dylib and the LC_RPATH fixtures were not built or checked here; the macOS parsing is still table-checked below; run this harness on macOS for the real fixtures"
elif [ "$os" = Darwin ]; then
    # --- the macOS native half ------------------------------------------------
    missing=""
    for tool in clang otool; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [ -n "$missing" ]; then
        skip "macos native half: no$missing on PATH — the /usr/lib-only positive, the non-system dylib and the LC_RPATH fixtures were not built or checked (the macOS parsing is still table-checked below)"
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
    skip "linux native half: not run on $os (ldd/readelf and an ELF toolchain are a Linux concern) — the static and dynamic positives, the non-system .so, ..-spelled, RPATH and RUNPATH negatives and the interpreter fixture were not built or checked here; the Linux parsing is still table-checked below; run this harness on Linux for the real fixtures"
else
    skip "linux native half: not run on $os (no ldd/readelf) — the Linux fixtures were not built or checked here"
    skip "macos native half: not run on $os (no otool) — the macOS fixtures were not built or checked here"
fi

# ── the table half: canned tool output, on every host ──────────────────────
#
# One case per rejected path, so a failure is attributable to its class. The
# fake tools read their canned output from per-case files, so the cases below
# spell out exactly what the gate was shown; a call with a flag no canned
# output exists for fails loudly, so a mis-wired case cannot pass by printing
# nothing.

table_n=0
tbin=""  # the fake bin dir for the case being built
tdata="" # the canned output files for the same case

# fake <tool> <flag> <body> — install a fake <tool> in the case's bin dir
# with <body> as its output when called with <flag> as its first argument.
# ldd is called with the binary's path rather than a flag, so its flag is
# `-`: the fake prints its body whatever it was called with. Every other
# fake picks its canned file by the flag it was called with, so one tool can
# carry several (readelf -d and readelf -l), and a flag no canned output
# exists for fails loudly rather than printing nothing.
fake() {
    local tool="$1" flag="$2" body="$3"
    printf '%s\n' "$body" >"$tdata/$tool.$flag"
    if [ "$flag" = "-" ]; then
        printf '#!/usr/bin/env bash\ncat "%s"\n' "$tdata/$tool.-" >"$tbin/$tool"
    else
        # shellcheck disable=SC2016  # $1 is expanded by the fake, not here
        printf '#!/usr/bin/env bash\nf="%s.$1"\n[ -f "$f" ] || { echo "fake %s: no canned output for $1" >&2; exit 1; }\ncat "$f"\n' \
            "$tdata/$tool" "$tool" >"$tbin/$tool"
    fi
    chmod +x "$tbin/$tool"
}

# new_table <os-to-pretend> — start one table case: a fresh fake bin dir
# whose uname reports <os-to-pretend>, so the gate takes that half.
new_table() {
    table_n=$((table_n + 1))
    tbin="$root/table-$table_n/bin"
    tdata="$root/table-$table_n"
    mkdir -p "$tbin"
    fake uname -s "$1"
}

# table <want_rc> <want_msg> <desc> — run the gate on the case just built.
table() {
    expect "$1" "$2" "$3" -- env PATH="$tbin:$PATH" "$script" "$root/table-input"
}

# Canned output for the Linux half. The dependency lines are indented as ldd
# prints them (the parser strips leading whitespace either way); the
# readelf -l line is the one real readelf prints for PT_INTERP.
LDD_ALL_SYSTEM='linux-vdso.so.1 (0x00007ffd0a3f2000)
libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x00007f293b495000)
/lib64/ld-linux-x86-64.so.2 (0x00007f293b677000)'
READELF_L_SYSTEM='  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]'
READELF_L_NON_SYSTEM='  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
      [Requesting program interpreter: /usr/local/lib/evil-loader.so]'
READELF_D_CLEAN=' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]'

# linux_dep_case <dep-line> <desc> — one Linux table case whose ldd output
# carries one extra dependency line; everything else is system-only.
linux_dep_case() {
    new_table Linux
    fake ldd - "$LDD_ALL_SYSTEM
$1"
    fake readelf -l "$READELF_L_SYSTEM"
    fake readelf -d "$READELF_D_CLEAN"
    table 1 "$1" "$2"
}

# The whole-component rule: the prefix has to be the whole directory.
linux_dep_case '/usr/local/lib/libnope.so' "a dependency under /usr/local/lib fails the gate named"
linux_dep_case '/usr/lib-x/libnope.so' "a dependency under /usr/lib-x fails the gate named"
linux_dep_case '/usr/libexec/libnope.so' "a dependency under /usr/libexec fails the gate named"
# A `..` component, starting inside a system dir — the prefix a prefix-only
# rule would accept.
new_table Linux
fake ldd - "$LDD_ALL_SYSTEM
/usr/lib/../../tmp/libnope.so (0x00007f293b000000)"
fake readelf -l "$READELF_L_SYSTEM"
fake readelf -d "$READELF_D_CLEAN"
table 1 "/usr/lib/../../tmp/libnope.so" "a dependency spelled with .. fails the gate named"
table 1 "..' path component" "a dependency spelled with .. is named as a .. path"

# The all-system table passes, multiarch dirs included.
new_table Linux
fake ldd - "$LDD_ALL_SYSTEM"
fake readelf -l "$READELF_L_SYSTEM"
fake readelf -d "$READELF_D_CLEAN"
table 0 "resolves only system libraries" "the Linux table's all-system case passes (a multiarch dir is a whole component)"

# The program interpreter, through the same rule.
new_table Linux
fake ldd - "$LDD_ALL_SYSTEM"
fake readelf -l "$READELF_L_NON_SYSTEM"
fake readelf -d "$READELF_D_CLEAN"
table 1 "/usr/local/lib/evil-loader.so" "a non-system program interpreter fails the gate named"
table 1 "the program interpreter is not a system loader path" "the interpreter is named as the interpreter, not as a dependency"

# Canned output for the macOS half: otool -L prints the binary as its first
# line (which the parser skips), then one install name per dependency;
# otool -l prints load commands, of which LC_RPATH carries a path.
OTOOL_L_ALL_SYSTEM='/usr/local/bin/answerer:
    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1345.100.2)
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation (current version 1643.0.0)'
OTOOL_L_NO_RPATH='Load command 1
          cmd LC_SEGMENT_64
      cmdsize 72
      segname __PAGEZERO
Load command 2
          cmd LC_LOAD_DYLINKER
      cmdsize 32
         name /usr/lib/dyld (offset 12)'
OTOOL_L_RPATH='Load command 1
          cmd LC_SEGMENT_64
      cmdsize 72
      segname __PAGEZERO
Load command 2
          cmd LC_RPATH
      cmdsize 48
         path /tmp/lcrpath-dir (offset 12)'

# macos_dep_case <install-name-line> <expected-name> <desc> — one macOS
# table case whose otool -L output carries one extra install name;
# everything else is system-only and carries no LC_RPATH. The line keeps
# otool's shape (indented, with the version in parentheses) and the expected
# name is the path the gate should strip out of it.
macos_dep_case() {
    new_table Darwin
    fake otool -L "$OTOOL_L_ALL_SYSTEM
$1"
    fake otool -l "$OTOOL_L_NO_RPATH"
    table 1 "$2" "$3"
}

macos_dep_case '    /usr/local/lib/libnope.dylib (compatibility version 1.0.0)' \
    '/usr/local/lib/libnope.dylib' \
    "a dependency under /usr/local/lib fails the gate named"
macos_dep_case '    /System/../Users/attacker/libnope.dylib (compatibility version 1.0.0)' \
    '/System/../Users/attacker/libnope.dylib' \
    "a dependency spelled with .. fails the gate named"
table 1 "..' path component" "a ..-spelled install name is named as a .. path"

new_table Darwin
fake otool -L "$OTOOL_L_ALL_SYSTEM"
fake otool -l "$OTOOL_L_NO_RPATH"
table 0 "resolves only system libraries" "the macOS table's all-system case passes (/System is a whole component)"

new_table Darwin
fake otool -L "$OTOOL_L_ALL_SYSTEM"
fake otool -l "$OTOOL_L_RPATH"
table 1 "LC_RPATH /tmp/lcrpath-dir" "an LC_RPATH load command fails the gate named"

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
