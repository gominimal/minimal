#!/usr/bin/env bash
# Record the README's dash-demo gif: several sessions of ONE repository
# running at once, and `min dash` listing them with each row's branch
# visible. Sessions and `min dash` only — no worktree step, and nothing
# implying a remote host or another machine (gominimal/inbox#657, AC3 of
# gominimal/inbox#638).
#
# Usage: scripts/record-dash-demo.sh
#
# Env overrides:
#   DEMO_DIR         scratch dir for clones + recording (default: mktemp)
#   REPO_URL         repo to clone (default: gominimal/minimal on GitHub)
#   BRANCHES         space-separated branch list, first is shown first
#                     (default: three branches verified to exist on origin
#                     at the time this script was written; pass your own if
#                     any have since been merged/deleted)
#   SESSION_PREFIX   session name prefix (default: demo)
#   OUT              output gif path (default: docs/public/dash-demo.gif)
#   KEEP             set to 1 to keep DEMO_DIR and the sessions after a run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DEMO_DIR="${DEMO_DIR:-$(mktemp -d /tmp/min-dash-demo.XXXXXX)}"
REPO_URL="${REPO_URL:-https://github.com/gominimal/minimal.git}"
BRANCHES="${BRANCHES:-main chore/vale-lint oss/integration}"
SESSION_PREFIX="${SESSION_PREFIX:-demo}"
OUT="${OUT:-$REPO_ROOT/docs/public/dash-demo.gif}"
KEEP="${KEEP:-0}"

# Matches the loadout-demo.cast terminal geometry (docs/public/loadout-demo.cast).
COLS=90
ROWS=25
export COLS ROWS
MAX_GIF_BYTES=4194304 # 4 MB README asset budget

# Cold VM boots can take 60-150s (AGENTS.md "Footguns"); use the same
# generous timeouts the justfile exports for its VM-backed recipes.
export MINVMD_READY_TIMEOUT_SECS="${MINVMD_READY_TIMEOUT_SECS:-150}"
export MINIMAL_SPAWN_TIMEOUT_SECS="${MINIMAL_SPAWN_TIMEOUT_SECS:-150}"
export MINVMD_LIFECYCLE_BOOT_TIMEOUT_SECS="${MINVMD_LIFECYCLE_BOOT_TIMEOUT_SECS:-150}"

SESSION_NAMES=()

cleanup() {
  local status=$?
  for name in "${SESSION_NAMES[@]:-}"; do
    [ -n "$name" ] && min session destroy "$name" -f >/dev/null 2>&1
  done
  if [ "$KEEP" = "1" ]; then
    echo "KEEP=1: leaving $DEMO_DIR and its sessions in place"
  else
    rm -rf "$DEMO_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

for tool in min asciinema agg python3 git jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "record-dash-demo: '$tool' not found on PATH" >&2
    exit 1
  }
done

read -r -a branch_array <<<"$BRANCHES"
if [ "${#branch_array[@]}" -lt 3 ]; then
  echo "record-dash-demo: BRANCHES must list at least 3 branches (got: $BRANCHES)" >&2
  exit 1
fi
for branch in "${branch_array[@]}"; do
  if ! git ls-remote --exit-code --heads "$REPO_URL" "$branch" >/dev/null 2>&1; then
    echo "record-dash-demo: branch '$branch' not found on $REPO_URL" >&2
    echo "Pass BRANCHES=\"main <existing-branch> <existing-branch>\" with branches that exist now." >&2
    exit 1
  fi
done

mkdir -p "$DEMO_DIR"
mkdir -p "$(dirname "$OUT")"

# Warm the daemon with one `min ls` before fanning out per-branch activations:
# concurrent `min` invocations against a cold daemon race to autospawn it, and
# the losers report a false "daemon exited during startup" (AGENTS.md /
# minimal-setup skill). We still activate sequentially below, but a session
# may itself trigger a first spawn, so this keeps that spawn out of the loop.
min ls >/dev/null 2>&1 || true

echo "==> Cloning $REPO_URL once (bare) into $DEMO_DIR/_source.git"
git clone --quiet --bare "$REPO_URL" "$DEMO_DIR/_source.git"

for branch in "${branch_array[@]}"; do
  safe_name="${branch//\//-}"
  checkout_dir="$DEMO_DIR/$safe_name"
  session_name="${SESSION_PREFIX}-${safe_name}"

  echo "==> Cloning $branch into $checkout_dir (plain clone, not a worktree)"
  git clone --quiet --branch "$branch" --single-branch "$DEMO_DIR/_source.git" "$checkout_dir"

  echo "==> Activating session '$session_name' for $branch"
  (cd "$checkout_dir" && min session activate . --name "$session_name" --no-prompt >/dev/null)
  SESSION_NAMES+=("$session_name")
done

echo "==> Waiting for ${#SESSION_NAMES[@]} sessions to become active (timeout 180s)"
poll_deadline=$((SECONDS + 180))
while true; do
  json="$(min session list --json)"
  active_count=0
  for name in "${SESSION_NAMES[@]}"; do
    status="$(printf '%s' "$json" | jq -r --arg n "$name" '[.sessions[] | select(.name == $n) | .status][0] // empty')"
    [ "$status" = "active" ] && active_count=$((active_count + 1))
  done
  if [ "$active_count" -eq "${#SESSION_NAMES[@]}" ]; then
    break
  fi
  if [ "$SECONDS" -ge "$poll_deadline" ]; then
    echo "record-dash-demo: timed out waiting for sessions to become active" >&2
    printf '%s\n' "$json" >&2
    exit 1
  fi
  sleep 3
done
echo "==> All ${#SESSION_NAMES[@]} sessions active"

CAST="$DEMO_DIR/dash-demo.cast"
DRIVER="$DEMO_DIR/driver.sh"

# A plain path with no arguments, so it can be handed to `asciinema rec
# --command` without any quoting questions. It prints the sessions as plain
# text first (2s pause to let a viewer read them), then hands off to the
# pty-driving python helper for the `min dash` portion.
cat >"$DRIVER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
min session list
sleep 2
python3 "$SCRIPT_DIR/record-dash-pty.py" 8
EOF
chmod +x "$DRIVER"

echo "==> Recording asciinema cast to $CAST"
# asciinema 3.x defaults to asciicast-v3; agg and the existing
# docs/public/loadout-demo.cast are asciicast-v2, so request that format
# explicitly (asciinema --version to confirm which generation is installed).
asciinema rec \
  --command "$DRIVER" \
  --output-format asciicast-v2 \
  --window-size "${COLS}x${ROWS}" \
  --overwrite \
  --title "min dash" \
  "$CAST"

echo "==> Rendering $OUT with agg"
# --cols/--rows/--line-height match docs/public/loadout-demo.cast's recorded
# geometry; --font-size is agg's own default (also what loadout-demo used).
# No --theme: like the loadout-demo render, this relies on the cast's own
# embedded theme so the two gifs share a look. --speed 1.2 is a fresh choice
# for this recording, not something matched from loadout-demo.
agg \
  --cols "$COLS" \
  --rows "$ROWS" \
  --font-size 16 \
  --line-height 1.3 \
  --speed 1.2 \
  "$CAST" "$OUT"

gif_bytes=$(wc -c <"$OUT" | tr -d ' ')
echo "==> Wrote $OUT ($gif_bytes bytes)"

if [ "$gif_bytes" -gt "$MAX_GIF_BYTES" ]; then
  echo "record-dash-demo: $OUT is $gif_bytes bytes, over the 4 MB README asset budget" >&2
  echo "Re-run with a shorter dwell, or pass agg --idle-time-limit 2 by editing the agg call above." >&2
  exit 1
fi

cat <<'CHECKLIST'

Review the gif before using it:
  [ ] three rows are visible, one per session
  [ ] each row shows its branch (the small branch glyph + name)
  [ ] nothing in the recording implies a worktree, a remote host, or another machine
CHECKLIST
