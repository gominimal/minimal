#!/usr/bin/env python3
"""Drive an interactive `min session attach` over a REAL pty, like a user at a terminal.

The session-exit path shows a Detach/Delete prompt (`async_dialog::Select`) and
reads the answer as keystrokes from the channel. A piped stdin cannot answer it
(and is not a real tty), so the session e2e drives the attach through a pty here
instead: pump the sandbox-proof command stream, wait for the exit prompt, then
read the rendered menu and send the arrow-keys + Enter that select the
requested lane by label — exercising the genuine interactive teardown a user
performs.

Usage: e2e-attach-pty.py <add_tool> <argv...>
  <add_tool>  package to `min add` (also its binary + `--version` subject)
  <argv...>   the command to spawn under the pty, e.g. `min --provider local-minvmd session attach <sid>`

Two environment variables retarget it for callers that want a pty and a
transcript but not the sandbox proof's command stream (the lifecycle-hooks
proof drives an attach to observe `on_attach` on the terminal, then leaves
to fire `on_detach`):

  E2E_PTY_COMMANDS  newline-separated lines to type instead of the default
                    `min add` stream. `<add_tool>` is then unused; pass `-`.
  E2E_PTY_ANSWER    how to answer the session-exit prompt: `delete` (the
                    default, what the sandbox proof needs) or `keep`, which
                    leaves the session alive — a detach.
  E2E_PTY_DETACH    set to leave via the session detach chord (the shipped
                    default: `ctrl-]` then `d`) once the command stream goes
                    quiet, instead of ending it with `exit`. The session's
                    SHELL then survives, which is what a test of re-attaching
                    to a still-running shell needs: `exit` ends that shell,
                    and the next attach mints a new one.

Prints the full captured terminal output on stdout. Exits 0 iff the attach
process exited 0.
"""

import os
import pty
import re
import select
import signal
import sys
import time

add_tool = sys.argv[1]
attach_argv = sys.argv[2:]
if not attach_argv:
    sys.stderr.write("e2e-attach-pty: missing attach argv\n")
    sys.exit(2)

if os.environ.get("E2E_PTY_COMMANDS") is not None:
    commands = os.environ["E2E_PTY_COMMANDS"].split("\n")
else:
    # Built so the absence marker `TOOL_ABSENT_BEFORE` appears ONLY as executed
    # output, never as echoed input (the pty echoes what we type).
    commands = [
        f"if command -v {add_tool} >/dev/null 2>&1; then "
        f"printf 'TOOL_%s_BEFORE\\n' PRESENT; else printf 'TOOL_%s_BEFORE\\n' ABSENT; fi",
        f"min add {add_tool}",
        "hash -r",
        f"{add_tool} --version",
        "exit",
    ]

EXIT_PROMPT = b"would you like to do with this session"  # SHELL_EXIT_PROMPT, lowercased
# The daemon builds the exit menu conditionally: a "Save changes ..., then
# delete" lane is inserted between "Exit, leaving ... in place" (a detach) and
# "Delete, ..." only when the session's file delta is non-empty, so a lane's
# row index is not fixed. Navigate by label instead — each answer names its row
# by the word the label starts with, and we count Down presses to reach it.
ANSWER_LABEL_PREFIX = {"keep": "Exit", "delete": "Delete"}
answer = os.environ.get("E2E_PTY_ANSWER", "delete")
DETACH = os.environ.get("E2E_PTY_DETACH") is not None
if answer not in ANSWER_LABEL_PREFIX:
    sys.stderr.write(f"e2e-attach-pty: unknown E2E_PTY_ANSWER {answer!r}\n")
    sys.exit(2)

ANSI_CSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


def menu_rows(raw):
    """The exit menu's item labels, in render order.

    The Select prompt draws each item on its own line — prefixed with "> " for
    the highlighted row, two spaces otherwise — after a header line carrying
    EXIT_PROMPT. Strip the ANSI control sequences, anchor on that header (its
    last occurrence, so a re-render wins), and return the labels that follow.
    """
    text = ANSI_CSI.sub(b"", raw).decode("utf-8", "replace")
    lines = [ln.replace("\r", "") for ln in text.split("\n")]
    header = None
    for i, ln in enumerate(lines):
        if EXIT_PROMPT.decode() in ln.lower():
            header = i
    if header is None:
        return []
    rows = []
    for ln in lines[header + 1:]:
        if ln.startswith("> ") or ln.startswith("  "):
            rows.append(ln[2:].rstrip())
        else:
            break
    return rows


def answer_keystrokes(raw):
    """Keys selecting the requested lane, or None until its row is rendered.

    The menu opens highlighted on the top row, so it is one Down per row down
    to the target, then Enter. Returns None while the target row has not yet
    appeared in `raw` — the caller keeps reading, and tells a not-yet-rendered
    menu from a genuinely absent lane by whether the frame has settled.
    """
    prefix = ANSWER_LABEL_PREFIX[answer]
    for idx, label in enumerate(menu_rows(raw)):
        if label.startswith(prefix):
            return b"\x1b[B" * idx + b"\r"
    return None


DEADLINE = time.monotonic() + 240  # overall safety cap

pid, fd = pty.fork()
if pid == 0:  # child
    os.execvp(attach_argv[0], attach_argv)
    os._exit(127)

buf = bytearray()
answered = False


def drain_ready(timeout):
    if select.select([fd], [], [], timeout)[0]:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            return None
        return chunk or None
    return b""


try:
    # The shell only starts once the sandbox is minted (seconds, more on a VM);
    # bytes we write buffer in the pty until then, so pump the whole stream up
    # front. The shell runs the commands in order and `exit` ends it.
    time.sleep(1.5)
    os.write(fd, ("\n".join(commands) + "\n").encode())

    quiet = 0
    detached = False
    while time.monotonic() < DEADLINE:
        chunk = drain_ready(1.0)
        if chunk is None:
            break  # EOF / closed
        buf.extend(chunk)
        quiet = 0 if chunk else quiet + 1
        # The detach chord has to arrive as a WRITE OF ITS OWN, sent once the
        # command stream goes quiet — so the commands have run first and the
        # chord can't be mistaken for their tail. It is the shipped default
        # chord (leader `ctrl-]` = 0x1d, then the detach subcommand `d`), in a
        # single coalesced chunk, which is exactly the shape the daemon's
        # ChordMatcher accepts (sessions::keys matches chords across and within
        # stdin chunks). An earlier era of this script sent a bare ctrl-w
        # (0x17) here; that key retired as a detach, so a stale byte now just
        # reaches the shell — where readline eats it as delete-previous-word
        # and rings the bell — and the attach never ends.
        if DETACH and not detached and quiet >= 2:
            os.write(fd, b"\x1dd")
            detached = True
        if not answered and EXIT_PROMPT in bytes(buf).lower():
            keys = answer_keystrokes(bytes(buf))
            if keys is not None:
                os.write(fd, keys)  # navigate to the requested lane like a user
                answered = True
            elif not chunk:
                # The frame has settled (the daemon is now blocking on input)
                # yet no row matches the request — fail loudly rather than
                # silently answering whatever lane a fixed keystroke lands on.
                sys.stderr.write(
                    f"e2e-attach-pty: no {answer!r} lane in the session-exit "
                    f"menu; saw {menu_rows(bytes(buf))!r}\n"
                )
                break
finally:
    # Don't let a hung attach wedge the lane.
    try:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            time.sleep(2)
            wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0

sys.stdout.buffer.write(bytes(buf))
sys.stdout.flush()
ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
sys.exit(0 if ok else 1)
