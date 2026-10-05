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

The terminal-relay proof (the client relays the attached terminal to ssh
through a local pty) adds a second stage, run once the command stream goes
quiet, in this order:

  E2E_PTY_RESIZE    `<rows> <cols>`: resize the terminal the attach runs on,
                    as a user dragging the window would.
  E2E_PTY_PASTE_FILE  a file whose bytes are written as one paste, while the
                    session's output keeps being read (a terminal emulator
                    never stops reading while it writes).
  E2E_PTY_AFTER     newline-separated lines to type after the above.

and then, once that stage goes quiet in turn, either the detach chord
(E2E_PTY_DETACH) or:

  E2E_PTY_KILL_TRANSPORT  set to SIGKILL the attach's ssh transport (the
                    `min proxy` ssh runs as its ProxyCommand), as a dropped
                    connection would. The driver then prints
                    `OUTER_STTY_UNCHANGED` when the terminal's termios after
                    the attach equals the one before it (what `stty -g` would
                    show), or `OUTER_STTY_CHANGED` with both.
  E2E_PTY_EXPECT_EXIT  the attach's expected exit status (default 0); a
                    killed transport is ssh's 255.

`E2E_PTY_SIZE` (`<rows> <cols>`) sets the terminal's starting size; unset,
it keeps the pty's default.

Prints the full captured terminal output on stdout. Exits 0 iff the attach
process exited with the expected status.
"""

import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
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


def size_env(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    rows, cols = (int(v) for v in raw.split())
    return rows, cols


START_SIZE = size_env("E2E_PTY_SIZE", None)
RESIZE = size_env("E2E_PTY_RESIZE", None)
PASTE_FILE = os.environ.get("E2E_PTY_PASTE_FILE")
AFTER = os.environ.get("E2E_PTY_AFTER")
KILL_TRANSPORT = os.environ.get("E2E_PTY_KILL_TRANSPORT") is not None
EXPECT_EXIT = int(os.environ.get("E2E_PTY_EXPECT_EXIT", "0"))
SECOND_STAGE = RESIZE is not None or PASTE_FILE is not None or AFTER is not None

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

def set_size(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def termios_of(tty):
    """The terminal's termios: what `stty -g` reports.

    macOS's PENDIN is masked: the kernel sets that bit itself when there is
    input to reprint, it is not a mode anyone chose."""
    attrs = termios.tcgetattr(tty)
    attrs[3] &= ~getattr(termios, "PENDIN", 0)
    return attrs


def transport_pids(root):
    """The attach's ssh transport: every descendant of `root` running the
    `min proxy` ProxyCommand."""
    table = subprocess.run(
        ["ps", "-A", "-o", "pid=,ppid=,command="],
        capture_output=True, text=True, check=True,
    ).stdout
    children, commands = {}, {}
    for line in table.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        pid_, ppid_ = int(parts[0]), int(parts[1])
        children.setdefault(ppid_, []).append(pid_)
        commands[pid_] = parts[2] if len(parts) > 2 else ""
    found, stack = [], [root]
    while stack:
        for kid in children.get(stack.pop(), []):
            stack.append(kid)
            command = commands.get(kid, "")
            # ssh's own command line names the ProxyCommand too; only the
            # proxy process itself is the transport.
            if os.path.basename(command.split(" ", 1)[0]) == "ssh":
                continue
            if " proxy --socket " in f" {command} ":
                found.append(kid)
    return found


def watch_outer_termios():
    """Run the attach as a child of this (session-leading) process and
    report whether the terminal's termios survived it unchanged.

    The attach cannot lead the session itself here: when a session leader
    exits, macOS revokes its controlling terminal, and the termios it left
    behind can no longer be read. So this process stays behind as the
    leader, reads the termios before and after, and prints the verdict on
    the terminal, where it lands in the transcript after everything the
    attach wrote."""
    before = termios_of(0)
    child = os.fork()
    if child == 0:
        os.execvp(attach_argv[0], attach_argv)
    _, wstatus = os.waitpid(child, 0)
    after = termios_of(0)
    if after == before:
        os.write(1, b"\r\nOUTER_STTY_UNCHANGED\r\n")
    else:
        os.write(1, f"\r\nOUTER_STTY_CHANGED before={before!r} after={after!r}\r\n".encode())
    if os.WIFEXITED(wstatus):
        os._exit(os.WEXITSTATUS(wstatus))
    os._exit(128 + os.WTERMSIG(wstatus))


pid, fd = pty.fork()
if pid == 0:  # child
    try:
        if START_SIZE is not None:
            set_size(0, *START_SIZE)
        if KILL_TRANSPORT:
            watch_outer_termios()
        os.execvp(attach_argv[0], attach_argv)
    finally:
        os._exit(127)

buf = bytearray()
answered = False
failed = False


def write_while_reading(data):
    """Write `data` to the terminal in chunks, reading the session's output
    whenever it is ready, so neither side ever blocks on the other."""
    view = memoryview(data)
    # Nonblocking for the paste: a blocking write to a pty master can wait
    # for room past what select() promised, and then nothing reads the
    # session's output, which waits on this very read.
    os.set_blocking(fd, False)
    try:
        write_nonblocking(view)
    finally:
        os.set_blocking(fd, True)


def write_nonblocking(view):
    while view and time.monotonic() < DEADLINE:
        readable, writable, _ = select.select([fd], [fd], [], 1.0)
        if readable:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                chunk = b""
            except OSError:
                return
            else:
                if not chunk:
                    return
            buf.extend(chunk)
        if writable:
            try:
                view = view[os.write(fd, view[:4096]):]
            except BlockingIOError:
                pass
            except OSError:
                return  # the attach is gone; the main loop sees the EOF


def second_stage():
    if RESIZE is not None:
        # The size lands on the attach's terminal; the kernel tells its
        # foreground process (`min`) with SIGWINCH.
        set_size(fd, *RESIZE)
        time.sleep(0.5)
    if PASTE_FILE is not None:
        with open(PASTE_FILE, "rb") as f:
            write_while_reading(f.read())
    if AFTER is not None:
        write_while_reading((AFTER + "\n").encode())


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
    staged = not SECOND_STAGE
    killed = False
    while time.monotonic() < DEADLINE:
        chunk = drain_ready(1.0)
        if chunk is None:
            break  # EOF / closed
        buf.extend(chunk)
        quiet = 0 if chunk else quiet + 1
        if not staged and quiet >= 2:
            second_stage()
            staged = True
            quiet = 0
            continue
        if staged and KILL_TRANSPORT and not killed and quiet >= 2:
            victims = transport_pids(pid)
            if not victims:
                sys.stderr.write("e2e-attach-pty: no ssh transport found to kill\n")
                failed = True
                break
            for victim in victims:
                os.kill(victim, signal.SIGKILL)
            killed = True
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
        if DETACH and staged and not detached and quiet >= 2:
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
                failed = True
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
ok = not failed and os.WIFEXITED(status) and os.WEXITSTATUS(status) == EXPECT_EXIT
sys.exit(0 if ok else 1)
