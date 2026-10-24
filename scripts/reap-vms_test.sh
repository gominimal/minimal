#!/usr/bin/env bash
#
# reap-vms_test.sh — test harness for scripts/reap-vms.sh, the reap of a
# checkout's leftover minvmd, __krun-vmm and gvproxy processes.
#
# `pkill` and `sudo` are stubbed by prepending a temp dir to PATH. The stubs
# record the command they were asked to run and signal nothing, so the real
# pkill is unreachable from this harness. The script under test is a copy in
# a stand-in checkout whose path carries ERE metacharacters, so the recorded
# patterns prove the scoping (NET-056) rather than echo the real checkout's
# path. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
reap="$here/reap-vms.sh"
[ -f "$reap" ] || { echo "cannot find reap-vms.sh next to test" >&2; exit 1; }

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-reaptest)"
trap 'rm -rf "$tmp"' EXIT
# Resolve symlinks (macOS /var -> /private/var) so the script's own
# `cd .. && pwd` sees the same path as this harness.
tmp="$(cd "$tmp" && pwd)"

checkout="$tmp/a.checkout+1"
mkdir -p "$checkout/scripts" "$tmp/bin"
cp "$reap" "$checkout/scripts/reap-vms.sh"
chmod +x "$checkout/scripts/reap-vms.sh"

log="$tmp/pkill.log"
for name in pkill sudo; do
    cat >"$tmp/bin/$name" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "$name \$*" >>"\$PKILL_LOG"
exit 0
EOF
    chmod +x "$tmp/bin/$name"
done
export PKILL_LOG="$log"

pass=0 fail=0
# ok / bad <description> — count and print one passing / failing case.
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# run_reap <args...> — run the stand-in checkout's script with the stubs on
# PATH. Sets `rc` and `err`, and leaves the recorded commands in $log.
rc=0 err=""
run_reap() {
    : >"$log"
    rc=0
    err="$(PATH="$tmp/bin:/usr/bin:/bin" bash "$checkout/scripts/reap-vms.sh" "$@" 2>&1)" || rc=$?
}

# ere_quote <s> — <s> as an ERE literal, escaping what reap-vms.sh escapes.
ere_quote() {
    printf '%s' "$1" | sed -e 's/[][\\.*^+|(){}?$]/\\&/g'
}

# expect_lines <description> <line...> — the log holds exactly these lines,
# in any order.
expect_lines() {
    local desc="$1"; shift
    local want got
    want="$(printf '%s\n' "$@" | sort)"
    got="$(sort "$log")"
    if [ "$rc" -eq 0 ] && [ "$want" = "$got" ]; then
        ok "$desc"
    else
        bad "$desc (rc=$rc, err: $err)"
        printf '       want:\n%s\n       got:\n%s\n' "$want" "$got"
    fi
}

# patterns — the `pkill -f` patterns the last run recorded, one per line.
patterns() {
    sed -e 's/^.*pkill -9 -f //' "$log"
}

# expect_matching <description> <want 0|1> <cmdline> — whether any recorded
# pattern matches <cmdline> as pkill's ERE would (1 = matched).
expect_matching() {
    local desc="$1" want="$2" cmdline="$3" got=0 pat
    while IFS= read -r pat; do
        if printf '%s\n' "$cmdline" | grep -Eq -- "$pat"; then got=1; fi
    done < <(patterns)
    if [ "$got" -eq "$want" ]; then ok "$desc"; else bad "$desc (cmdline: $cmdline)"; fi
}

root="$(ere_quote "$checkout")"

# Bare invocation: every pattern is SIGKILL (a VM in `krun_start_enter`
# ignores SIGTERM) and is pinned to this checkout's path, never a bare name.
run_reap
expect_lines "bare reap sends -9, pinned to the quoted checkout" \
    "pkill -9 -f $root/.*minvmd" \
    "pkill -9 -f $root/.*gvproxy" \
    "sudo -n pkill -9 -f $root/.*minvmd" \
    "sudo -n pkill -9 -f $root/.*gvproxy"
bare="$(sort "$log")"
expect_matching "checkout's own minvmd is matched" 1 \
    "$checkout/target/debug/minvmd run"
expect_matching "checkout's own named-VM minvmd is matched" 1 \
    "$checkout/target/debug/minvmd run --vm alpha"
expect_matching "checkout's own gvproxy is matched" 1 \
    "$checkout/.scratch/gvproxy -listen unix:///x/gvproxy-switch.sock"
expect_matching "look-alike checkout (regex characters read as regex) is not matched" 0 \
    "$tmp/aXcheckout1/target/debug/minvmd run"
expect_matching "system gvproxy is not matched" 0 \
    "/opt/homebrew/bin/gvproxy -listen unix:///x.sock"

# `--vm default` is the bare invocation: the default VM's processes carry no
# `--vm` flag, so name-pinned patterns would reap nothing.
run_reap --vm default
if [ "$rc" -eq 0 ] && [ "$(sort "$log")" = "$bare" ]; then
    ok "--vm default reaps what the bare invocation reaps"
else
    bad "--vm default reaps what the bare invocation reaps (rc=$rc, log: $(cat "$log"))"
fi

# By name: the same checkout and the one named VM.
run_reap --vm alpha
expect_lines "--vm alpha pins the checkout and the VM name" \
    "pkill -9 -f $root/.*minvmd.*--vm[= ]alpha( |\$)" \
    "sudo -n pkill -9 -f $root/.*minvmd.*--vm[= ]alpha( |\$)" \
    "pkill -9 -f $root/.*gvproxy.*local-minvmd[0-9]+/alpha/" \
    "sudo -n pkill -9 -f $root/.*gvproxy.*local-minvmd[0-9]+/alpha/"
expect_matching "--vm alpha leaves another VM of this checkout alone" 0 \
    "$checkout/target/debug/minvmd run --vm beta"

# A name with ERE metacharacters is quoted, not interpreted.
run_reap --vm a.b+c
if [ "$rc" -eq 0 ] && grep -qF -- '--vm[= ]a\.b\+c( |$)' "$log"; then
    ok "a VM name is matched literally"
else
    bad "a VM name is matched literally (rc=$rc, log: $(cat "$log"))"
fi

# A flag without its value, and an unknown flag, are usage errors.
for args in "--vm" "--root" "--bogus"; do
    run_reap "$args"
    if [ "$rc" -eq 2 ] && [[ "$err" == *usage* ]] && [ ! -s "$log" ]; then
        ok "$args alone exits 2 with the usage line and signals nothing"
    else
        bad "$args alone exits 2 with the usage line and signals nothing (rc=$rc, err: $err)"
    fi
done

# `--root <DIR>` pins DIR in place of the checkout; a trailing slash does not
# change the match.
elsewhere="$tmp/runner.temp+1"
other="$(ere_quote "$elsewhere")"
run_reap --root "$elsewhere/"
expect_lines "--root DIR/ pins the quoted DIR in place of the checkout" \
    "pkill -9 -f $other/.*minvmd" \
    "pkill -9 -f $other/.*gvproxy" \
    "sudo -n pkill -9 -f $other/.*minvmd" \
    "sudo -n pkill -9 -f $other/.*gvproxy"
expect_matching "--root matches DIR's testbed minvmd" 1 \
    "$elsewhere/testbed/bin/minvmd run"
expect_matching "--root matches DIR's fetched gvproxy" 1 \
    "$elsewhere/minimal-gvproxy/gvproxy -listen unix:///x.sock"
expect_matching "--root does not match the checkout" 0 \
    "$checkout/target/debug/minvmd run"
expect_matching "--root does not match a look-alike DIR" 0 \
    "$tmp/runnerXtemp1/testbed/bin/minvmd run"

# `--root /` strips to an empty root, which would match every minvmd and
# gvproxy on the machine: refused before anything is signalled.
run_reap --root /
if [ "$rc" -eq 2 ] && [ ! -s "$log" ]; then
    ok "--root / exits 2 and signals nothing"
else
    bad "--root / exits 2 and signals nothing (rc=$rc, log: $(cat "$log"))"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
