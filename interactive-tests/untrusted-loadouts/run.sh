#!/usr/bin/env bash
# Interactive test suite for untrusted loadouts: the gating of
# loadouts-untrusted/ by the user policy. See README.md next to this script.
# Run it through `just interactive-test untrusted-loadouts`.
#
# Isolation, so nothing touches your own config, daemon or sessions:
#   - config:  fixtures/config is copied to $WORK/config/minimal each run and
#              passed as --config-dir, so user_policy.toml is the test one
#   - state:   --minimal-dir $STATE, so the suite boots its own daemon/VM
#   - project: a fresh, empty temp dir, activated with --sync none
# Between scenarios every session in $STATE is destroyed and the test
# user_policy.toml is removed. On exit the test daemon is stopped and $WORK
# and the project dir are deleted.
#
# Env knobs:
#   SKIP_BUILD=1    skip `just artifacts gvproxy initramfs-nodocker minvmd-build minimal-cli`
#                   (initramfs-nodocker needs zig, cargo-zigbuild and the musl target)
#   INTERACTIVE=0   skip the prompt steps (default: on when stdin is a terminal)
#   KEEP_DAEMON=1   leave the test daemon running at exit
#   LIST_ONLY=1     run only scenario 0 (`min loadout list`), which needs no daemon
#   STATE=<dir>     daemon state dir (default ~/.local/state/minimal-interactive-tests).
#                   Keep it short: socket paths under it hit the ~104-byte limit.
#
# A literal `~` throughout is deliberate: it is expanded by min's policy
# matcher or by the session's shell, never by this script.
# shellcheck disable=SC2088
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
FIXTURES="$HERE/fixtures"
WORK="$REPO/.scratch/interactive-tests/untrusted-loadouts"
CFG="$WORK/config"
STATE="${STATE:-$HOME/.local/state/minimal-interactive-tests}"
POLICY="$CFG/minimal/user_policy.toml"
UT="$CFG/minimal/loadouts-untrusted"
TOKEN="s3cret-from-host-$$"
LOG='~/untrusted-loadout-test.log'
if [ -t 0 ]; then INTERACTIVE="${INTERACTIVE:-1}"; else INTERACTIVE=0; fi

# Scenarios 5–9 write `~/`-relative policy rules, so the config dir must
# live under $HOME for `~/` to reach it.
case "$CFG" in
  "$HOME"/*) UT_TILDE="~/${UT#"$HOME"/}" ;;
  *) echo "this checkout ($REPO) must be under \$HOME: the policy rules use ~/ paths" >&2; exit 2 ;;
esac

pass=0; fail=0; failed=()
ok()   { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { fail=$((fail + 1)); failed+=("$1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       | /'; }
hdr()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

m() { min --config-dir "$CFG" --minimal-dir "$STATE" "$@"; }

# ── setup ────────────────────────────────────────────────────────────────────
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  hdr "build (this checkout's min, minvmd, and guest minimald)"
  just -f "$REPO/justfile" artifacts gvproxy initramfs-nodocker minvmd-build minimal-cli || { echo "build failed" >&2; exit 2; }
fi
eval "$(just -f "$REPO/justfile" env)"
export UT_TEST_TOKEN="$TOKEN"
command -v min | grep -q "^$REPO/" || { echo "min on PATH is not from $REPO: $(command -v min)" >&2; exit 2; }

# Host files a patch must never produce outside a session.
host_strays=("$HOME/ut-greeting.txt" "$HOME/ut-fake-key")
for f in "${host_strays[@]}"; do [ -e "$f" ] && { echo "refusing to run: $f already exists on the host" >&2; exit 2; }; done

rm -rf "$WORK"
mkdir -p "$CFG"
cp -Rp "$FIXTURES/config" "$CFG/minimal"
sed -i.bak "s|@LOADOUTS_UNTRUSTED@|$UT|" "$UT/ut-var-attack.toml" && rm -f "$UT/ut-var-attack.toml.bak"

PROJ="$(mktemp -d "${TMPDIR:-/tmp}/ut-proj.XXXXXX")"
cd "$PROJ" || exit 2

reset() {
  m session destroy --all -f >/dev/null 2>&1 || true
  rm -f "$POLICY"
}
cleanup() {
  hdr "cleanup"
  if [ "${LIST_ONLY:-0}" = 1 ]; then rm -rf "$PROJ" "$WORK"; printf '\n%d passed, %d failed\n' "$pass" "$fail"; return; fi
  reset
  if [ "${KEEP_DAEMON:-0}" != 1 ]; then m stop >/dev/null 2>&1 || true; echo "  test daemon stopped (if a VM lingers: just reap)"; fi
  rm -rf "$PROJ" "$WORK"
  for f in "${host_strays[@]}"; do [ -e "$f" ] && echo "  WARNING: $f appeared on the host"; done
  printf '\n%d passed, %d failed\n' "$pass" "$fail"
  for t in "${failed[@]+"${failed[@]}"}"; do echo "  - $t"; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM

policy() { printf '%s\n' "$@" > "$POLICY"; }

# activate NAME ARGS... → sets $out and $rc. Non-interactive unless PROMPT=1.
# --sync none: the scenarios need no project files (loadout patches and hook
# scripts upload separately), and it skips the "create a minimal.toml?" and
# "upload this non-VCS directory?" prompts.
activate() {
  local name="$1"; shift
  if [ "${PROMPT:-0}" = 1 ]; then
    m session activate --name "$name" --sync none "$@" .; rc=$?; out=""
  else
    out="$(m --no-input session activate --name "$name" --sync none "$@" . 2>&1 </dev/null)"; rc=$?
  fi
}
has_session() { m session list --json 2>/dev/null | grep -q "\"$1\""; }
sx() { m session exec "$1" "$2" 2>&1; }
# Hooks may land just after activate returns: poll the session log briefly.
log_has() {
  local s="$1" want="$2"
  for _ in 1 2 3 4 5 6 7 8 9 10; do sx "$s" "cat $LOG 2>/dev/null" | grep -qF "$want" && return 0; sleep 1; done
  return 1
}

expect_ok() {  # label
  if [ "$rc" -eq 0 ]; then ok "$1"; else bad "$1 (exit $rc)" "$out"; fi
}
expect_fail() {  # label grep-pattern session
  if [ "$rc" -eq 0 ]; then bad "$1 (succeeded, expected failure)" "$out"; return; fi
  if [ -n "$2" ] && ! printf '%s' "$out" | grep -qiE "$2"; then bad "$1 (failed, but output lacks /$2/)" "$out"; return; fi
  ok "$1"
  if has_session "$3"; then bad "$1: refusal left session $3 behind"; else ok "$1: no session left behind"; fi
}

# ── 0. listing (no daemon needed) ────────────────────────────────────────────
hdr "0. min loadout list"
out="$(m --no-input loadout list 2>&1)"; rc=$?
expect_ok "lists the scenario loadouts"
untagged="$(printf '%s\n' "$out" | grep -E '^[[:space:]]*[*]?[[:space:]]*ut-' | grep -v '(untrusted)')"
[ -z "$untagged" ] && ok "every ut-* row is tagged (untrusted)" || bad "untagged ut-* rows" "$untagged"
printf '%s\n' "$out" | grep -E '^[[:space:]]*[*]?[[:space:]]*t-' | grep -q '(untrusted)' && bad "a t-* row is tagged (untrusted)" "$out" || ok "no t-* row is tagged"

out="$(min --no-input loadout list --dir "$FIXTURES/list-test" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok "broken listing exits non-zero" || bad "broken listing exited 0" "$out"
printf '%s' "$out" | grep -qF '3 loadouts failed to load'          && ok "3 loadouts failed to load"           || bad "lacks '3 loadouts failed to load'" "$out"
printf '%s' "$out" | grep -q 'dup` is defined in both loadouts directories'   && ok "dup: both directories"   || bad "dup error" "$out"
printf '%s' "$out" | grep -q 'twice` is defined in both loadouts directories' && ok "twice: both directories" || bad "twice both-directories error" "$out"
printf '%s' "$out" | grep -q 'twice` is defined twice'                        && ok "twice: flat and layout"  || bad "twice defined-twice error" "$out"
printf '%s' "$out" | grep -q 'Warning: `missing`'                  && ok "warns about missing"                 || bad "no warning for missing" "$out"
printf '%s' "$out" | grep -qE '^\* alpha +'                         && ok "alpha starred, untagged"             || bad "alpha row" "$out"
printf '%s' "$out" | grep -qE '^\* beta \(untrusted\)'              && ok "beta starred, tagged (untrusted)"    || bad "beta row" "$out"

[ "${LIST_ONLY:-0}" = 1 ] && exit "$((fail > 0))"

# ── preflight ────────────────────────────────────────────────────────────────
hdr "preflight: test daemon"
reset
m version 2>&1 | sed 's/^/  /'
m ls >/dev/null 2>&1 || { echo "test daemon did not come up" >&2; exit 2; }

# ── 1. trusted hook ──────────────────────────────────────────────────────────
hdr "1. t-hook (trusted inline hook)"
reset
activate ut-1 --no-prompt --loadout t-hook
expect_ok "activates with --no-prompt"
log_has ut-1 "t-hook-inline kind=loadout name=t-hook" && ok "hook logged kind=loadout" || bad "hook log" "$(sx ut-1 "cat $LOG")"

# ── 2. trusted inherit ───────────────────────────────────────────────────────
hdr "2. t-inherit (trusted inherited var)"
reset
activate ut-2 --no-prompt --loadout t-inherit
expect_ok "activates with --no-prompt"
v="$(sx ut-2 'printf %s "$UT_TEST_TOKEN"')"; [ "$v" = "$TOKEN" ] && ok "UT_TEST_TOKEN inherited" || bad "UT_TEST_TOKEN = '$v'"

# ── 3. untrusted literal ─────────────────────────────────────────────────────
# Unlike a project's, an untrusted loadout's literal is gated: its value is
# what runs code (BASH_ENV, PATH).
hdr "3. ut-literal (untrusted literal var, gated by name)"
reset
activate ut-3a --no-prompt --loadout ut-literal
expect_fail "--no-prompt refuses, prints a [vars] snippet" '\[vars\]' ut-3a
printf '%s' "$out" | grep -q UT_LITERAL && ok "snippet names UT_LITERAL" || bad "snippet lacks UT_LITERAL" "$out"
reset
policy '[vars]' 'allow = ["UT_LITERAL"]'
activate ut-3b --no-prompt --loadout ut-literal
expect_ok "allowed by [vars] allow rule"
v="$(sx ut-3b 'printf %s "$UT_LITERAL"')"; [ "$v" = "hello-from-ut-literal" ] && ok "UT_LITERAL set" || bad "UT_LITERAL = '$v'"

# ── 4. untrusted inherit ─────────────────────────────────────────────────────
hdr "4. ut-inherit (untrusted inherited var)"
reset
activate ut-4a --no-prompt --loadout ut-inherit
expect_fail "--no-prompt refuses, prints a [vars] snippet" '\[vars\]' ut-4a
printf '%s' "$out" | grep -q UT_TEST_TOKEN && ok "snippet names UT_TEST_TOKEN" || bad "snippet lacks UT_TEST_TOKEN" "$out"
reset
policy '[vars]' 'allow = ["UT_TEST_TOKEN"]'
activate ut-4b --no-prompt --loadout ut-inherit
expect_ok "allowed by [vars] allow rule"
v="$(sx ut-4b 'printf %s "$UT_TEST_TOKEN"')"; [ "$v" = "$TOKEN" ] && ok "UT_TEST_TOKEN inherited" || bad "UT_TEST_TOKEN = '$v'"

# ── 5. untrusted patch ───────────────────────────────────────────────────────
hdr "5. ut-patch (untrusted patch)"
reset
activate ut-5a --no-prompt --loadout ut-patch
expect_fail "--no-prompt refuses, prints a [patches] snippet" '\[patches\]' ut-5a
reset
policy '[patches]' "allow = [\"$UT_TILDE/ut-patch/files/**\"]"
activate ut-5b --no-prompt --loadout ut-patch
expect_ok "allowed by [patches] allow rule"
v="$(sx ut-5b 'cat ~/ut-greeting.txt')"; [ "$v" = "hello from ut-patch" ] && ok "patch landed in session" || bad "~/ut-greeting.txt = '$v'"

# ── 6. untrusted hooks ───────────────────────────────────────────────────────
hdr "6. ut-hook (untrusted inline + external hooks)"
reset
activate ut-6a --no-prompt --loadout ut-hook
expect_fail "--no-prompt refuses, prints a [hooks] snippet" '\[hooks\]' ut-6a
reset
activate ut-6b --no-prompt --no-hooks --loadout ut-hook
expect_ok "--no-hooks activates"
sleep 2; sx ut-6b "cat $LOG 2>/dev/null" | grep -q ut-hook && bad "--no-hooks still ran hooks" || ok "--no-hooks: no hook output"
reset
policy '[hooks]' "allow = [\"$UT_TILDE/ut-hook\"]"
activate ut-6c --no-prompt --loadout ut-hook
expect_ok "allowed by [hooks] allow rule on the loadout dir"
log_has ut-6c "ut-hook-inline kind=loadout-untrusted name=ut-hook"   && ok "inline hook: kind=loadout-untrusted"   || bad "inline hook log" "$(sx ut-6c "cat $LOG")"
log_has ut-6c "ut-hook-external kind=loadout-untrusted name=ut-hook" && ok "external hook: kind=loadout-untrusted" || bad "external hook log" "$(sx ut-6c "cat $LOG")"

# ── 7. missing external script ───────────────────────────────────────────────
hdr "7. ut-missing-script"
reset
policy '[hooks]' "allow = [\"$UT_TILDE/ut-missing-script\"]"
activate ut-7a --no-prompt --loadout ut-missing-script
if [ "$rc" -ne 0 ]; then ok "allowed: fails at staging"; printf '%s\n' "$out" | head -3 | sed 's/^/       | /'; else bad "allowed: expected staging failure, got success"; fi
reset
policy '[hooks]' "ignore = [\"$UT_TILDE/ut-missing-script\"]"
activate ut-7b --no-prompt --loadout ut-missing-script
expect_ok "ignored by policy: succeeds"

# ── 8. HOME redefinition vs deny ─────────────────────────────────────────────
hdr "8. ut-home-attack (HOME=/nonexistent vs a ~/ deny rule)"
reset
# The absolute allow would pass the patch if the ~/ deny failed to match,
# so only a working deny can refuse it. HOME itself is allowed so the run
# gets past the var gate to the patch.
policy '[vars]' 'allow = ["HOME"]' '[patches]' \
  "allow = [\"$UT/ut-home-attack/**\"]" \
  "deny = [\"$UT_TILDE/ut-home-attack/secret/**\"]"
activate ut-8 --no-prompt --loadout ut-home-attack
expect_fail "denied despite untrusted HOME" 'den' ut-8

# ── 9. var injection into a policy pattern ───────────────────────────────────
hdr "9. ut-var-attack (\$UT_TRUST_ROOT in a hooks allow rule)"
reset
# UT_TRUST_ROOT itself is allowed so the run gets past the var gate to the
# hooks rule that names it.
policy '[vars]' 'allow = ["UT_TRUST_ROOT"]' '[hooks]' 'allow = ["$UT_TRUST_ROOT"]'
activate ut-9 --no-prompt --loadout ut-var-attack
expect_fail "unresolved variable, not auto-allowed" 'UT_TRUST_ROOT' ut-9
printf '%s' "$out" | grep -qF 'not a resolved session variable' && ok "error says the var is unresolved" || bad "error lacks 'not a resolved session variable'" "$out"

# ── 10. mixed trusted + untrusted ────────────────────────────────────────────
hdr "10. t-hook + ut-hook together"
reset
policy '[hooks]' "allow = [\"$UT_TILDE/ut-hook\"]"
activate ut-10 --no-prompt --loadout t-hook --loadout ut-hook
expect_ok "activates"
log_has ut-10 "t-hook-inline kind=loadout name=t-hook"            && ok "t-hook kind=loadout"            || bad "t-hook log" "$(sx ut-10 "cat $LOG")"
log_has ut-10 "ut-hook-inline kind=loadout-untrusted name=ut-hook" && ok "ut-hook kind=loadout-untrusted" || bad "ut-hook log" "$(sx ut-10 "cat $LOG")"

# ── 11. a hooks deny aborts ──────────────────────────────────────────────────
# `ignore` skips a source's hooks and carries on; `deny` stops the activation.
hdr "11. ut-hook with a [hooks] deny rule"
reset
policy '[hooks]' "deny = [\"$UT_TILDE/ut-hook\"]"
activate ut-11 --no-prompt --loadout ut-hook
expect_fail "deny rule fails the activation" 'den' ut-11
reset
policy '[hooks]' "ignore = [\"$UT_TILDE/ut-hook\"]"
activate ut-11b --no-prompt --loadout ut-hook
expect_ok "ignore rule: activates"
sleep 2; sx ut-11b "cat $LOG 2>/dev/null" | grep -q ut-hook && bad "ignored hooks still ran" || ok "ignore: no hook output"

# ── interactive prompts ──────────────────────────────────────────────────────
# Each step prints a box: what will appear, which option to pick, and what
# the script checks afterwards. Prompts are menus: move with ↑/↓, pick with
# Enter. The cursor starts on "Allow once".
if [ "$INTERACTIVE" = 1 ]; then
  # instruct TITLE EXPECT PICK [AFTER]
  instruct() {
    printf '\n\033[1;36m┌─ YOUR TURN: %s\033[0m\n' "$1"
    printf '\033[36m│\033[0m \033[1mYou will see:\033[0m %s\n' "$2"
    printf '\033[36m│\033[0m \033[1mDo this:\033[0m      \033[1;33m%s\033[0m\n' "$3"
    [ -n "${4:-}" ] && printf '\033[36m│\033[0m \033[1mThen:\033[0m         %s\n' "$4"
    printf '\033[36m└─\033[0m press Enter to start… '
    read -r _ </dev/tty
  }
  # confirm QUESTION → a y/n answer you give from what you saw on screen.
  confirm() {
    local a
    printf '\n\033[1;36m? %s\033[0m\n' "$1"
    while :; do
      read -r -p "  answer y or n: " a </dev/tty
      a="$(printf '%s' "$a" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
      case "$a" in
        y|yes) ok "$1"; return ;;
        n|no)  bad "$1"; return ;;
        *)     echo "  '$a' is not y or n; try again" ;;
      esac
    done
  }

  hdr "INTERACTIVE PART: 7 steps, about 3 minutes"
  echo "  From here on, the script stops and waits for you at each step."
  echo "  Prompts are menus: ↑/↓ to move, Enter to choose. The cursor starts on \"Allow once\"."
  echo "  Pick only the option a step tells you to. Never pick a \"permanent\" option."

  hdr "Step 1 of 7: approve an inherited var (ut-inherit)"
  reset
  instruct "approve the var" \
    "ONE menu: \"Untrusted loadout \`ut-inherit\` wants to read \`UT_TEST_TOKEN\` from your environment and pass it into the session\"" \
    "Press Enter on \"Allow once\"" \
    "the session is created; the script checks the var reached it"
  PROMPT=1 activate ut-p1 --loadout ut-inherit
  confirm "Did exactly one menu appear, naming ut-inherit and UT_TEST_TOKEN?"
  v="$(sx ut-p1 'printf %s "$UT_TEST_TOKEN"')"; [ "$v" = "$TOKEN" ] && ok "approved var inherited" || bad "UT_TEST_TOKEN = '$v'"

  hdr "Step 2 of 7: refuse the same var (ut-inherit)"
  reset
  instruct "refuse the var" \
    "the same menu as step 1" \
    "Press ↓ until \"Abort activation\" is highlighted, then Enter" \
    "activation fails; the script checks no session was created"
  PROMPT=1 activate ut-p2 --loadout ut-inherit
  [ "$rc" -ne 0 ] && ok "abort fails activation" || bad "abort: activation succeeded"
  has_session ut-p2 && bad "abort left a session" || ok "abort: no session left behind"

  hdr "Step 3 of 7: approve a patch (ut-patch)"
  reset
  instruct "approve the patch" \
    "ONE menu: \"Untrusted loadout \`ut-patch\` wants to patch \`…/loadouts-untrusted/ut-patch/files/greeting.txt\`\"" \
    "Press Enter on \"Allow once\"" \
    "the script checks ~/ut-greeting.txt exists inside the session"
  PROMPT=1 activate ut-p3 --loadout ut-patch
  confirm "Did exactly one menu appear, naming ut-patch and greeting.txt?"
  v="$(sx ut-p3 'cat ~/ut-greeting.txt')"; [ "$v" = "hello from ut-patch" ] && ok "approved patch landed" || bad "~/ut-greeting.txt = '$v'"

  hdr "Step 4 of 7: approve hooks (ut-hook has TWO hooks)"
  reset
  instruct "approve the hooks, and count the menus" \
    "ONE menu: \"The untrusted loadout \`ut-hook\` at \`…/loadouts-untrusted/ut-hook\` wants to run its own scripts inside the session (lifecycle hooks)…\"" \
    "Press Enter on \"Allow once\". If a SECOND hook menu appears, that's a bug: pick \"Allow once\" again and answer n below" \
    "the script checks both hooks ran"
  PROMPT=1 activate ut-p4 --loadout ut-hook
  confirm "Did exactly ONE hook menu appear (not one per hook)?"
  log_has ut-p4 "ut-hook-inline kind=loadout-untrusted"   && ok "inline hook ran"   || bad "inline hook log" "$(sx ut-p4 "cat $LOG")"
  log_has ut-p4 "ut-hook-external kind=loadout-untrusted" && ok "external hook ran" || bad "external hook log" "$(sx ut-p4 "cat $LOG")"

  hdr "Step 5 of 7: a literal shows its value (ut-literal)"
  reset
  instruct "approve the literal, and read its value" \
    "ONE menu: \"Untrusted loadout \`ut-literal\` wants to set \`UT_LITERAL\` to \"hello-from-ut-literal\" in the session\"" \
    "Press Enter on \"Allow once\"" \
    "the script checks the var reached the session"
  PROMPT=1 activate ut-p5 --loadout ut-literal
  confirm "Did exactly one menu appear, showing the value \"hello-from-ut-literal\"?"
  v="$(sx ut-p5 'printf %s "$UT_LITERAL"')"; [ "$v" = "hello-from-ut-literal" ] && ok "approved literal set" || bad "UT_LITERAL = '$v'"

  hdr "Step 6 of 7: a denied patch must not prompt (ut-home-attack)"
  reset
  # HOME is allowed so its own menu doesn't appear; only the patch is tested.
  policy '[vars]' 'allow = ["HOME"]' '[patches]' "deny = [\"$UT_TILDE/ut-home-attack/secret/**\"]"
  instruct "watch, don't approve" \
    "NO menu. Activation should fail straight away with an error saying the patch is denied" \
    "Nothing. If a menu DOES appear, that's a bug: press ↓ to \"Abort activation\", Enter, and answer n below" \
    "the script checks no session was created"
  PROMPT=1 activate ut-p6 --loadout ut-home-attack
  confirm "Did it fail with a denial and NO menu?"
  has_session ut-p6 && bad "deny left a session" || ok "no session left behind"

  hdr "Step 7 of 7: min dash refuses, it does not ask (ut-inherit as a default loadout)"
  reset
  printf '[loadouts]\ndefault_loadouts = ["ut-inherit"]\n' > "$CFG/minimal/config.toml"
  instruct "create a session from the dashboard" \
    "the dashboard. After you create, NO menu: an error on the bottom line, \"…1 item from untrusted loadouts needs your approval, which min dash cannot ask for while it is open: UT_TEST_TOKEN…\"" \
    "Press n, then Enter three times to create with the defaults. Read the bottom line, then press q to quit" \
    "the script checks no session was created"
  before="$(m session list --json 2>/dev/null)"
  m dash
  rm -f "$CFG/minimal/config.toml"
  confirm "Did the bottom line show that error, naming UT_TEST_TOKEN, with no menu?"
  [ "$(m session list --json 2>/dev/null)" = "$before" ] && ok "dash refusal created no session" || bad "dash created a session"
else
  hdr "interactive steps skipped (INTERACTIVE=0 or no tty)"
fi
