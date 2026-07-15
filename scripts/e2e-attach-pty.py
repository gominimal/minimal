#!/usr/bin/env python3
"""Drive an interactive `min attach` over a REAL pty, like a user at a terminal.

The session-exit path shows a Detach/Delete prompt (`async_dialog::Select`) and
reads the answer as keystrokes from the channel. A piped stdin cannot answer it
(and is not a real tty), so the session e2e drives the attach through a pty here
instead: pump the sandbox-proof command stream, wait for the exit prompt, then
send the arrow-key + Enter that selects "Delete" — exercising the genuine
interactive teardown a user performs.

Usage: e2e-attach-pty.py <add_tool> <argv...>
  <add_tool>  package to `min add` (also its binary + `--version` subject)
  <argv...>   the command to spawn under the pty, e.g. `min --minvmd attach <sid>`

Prints the full captured terminal output on stdout. Exits 0 iff the attach
process exited 0.
"""

import os
import pty
import select
import signal
import sys
import time

add_tool = sys.argv[1]
attach_argv = sys.argv[2:]
if not attach_argv:
    sys.stderr.write("e2e-attach-pty: missing attach argv\n")
    sys.exit(2)

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
DELETE_KEY = b"\x1b[B\r"  # Down arrow -> "Delete", Enter to confirm
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

    while time.monotonic() < DEADLINE:
        chunk = drain_ready(1.0)
        if chunk is None:
            break  # EOF / closed
        buf.extend(chunk)
        if not answered and EXIT_PROMPT in bytes(buf).lower():
            os.write(fd, DELETE_KEY)  # answer the prompt like a user
            answered = True
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
