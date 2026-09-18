#!/usr/bin/env python3
"""Drive `min dash` for the README dash-demo recording.

Invoked as the last step of scripts/record-dash-demo.sh's asciinema driver,
after `min session list` has already printed the sessions in plain text.
`min dash` is a full-screen TUI: it needs a real pty, and since nothing is
watching a terminal to press a key by hand, it needs a scripted quit
keystroke to end the recording.

This mirrors scripts/e2e-attach-pty.py's approach for `min session attach`'s
exit prompt: fork a pty, exec the target program in the child, and drive it
as the parent — reading the child's output and relaying it to our own
stdout (which is what `asciinema rec` actually captures) as we go, then
writing the quit key into the pty once the dwell time has elapsed. Stdlib
only, no packages to install.

Usage: record-dash-pty.py <dwell-seconds>
  <dwell-seconds>  how long to let `min dash` render before sending `q`
"""

import os
import pty
import select
import fcntl
import struct
import termios
import signal
import sys
import time

if len(sys.argv) != 2:
    sys.stderr.write("usage: record-dash-pty.py <dwell-seconds>\n")
    sys.exit(2)

dwell = float(sys.argv[1])
QUIT_KEY = b"q"  # min dash: 'q' quits immediately, no confirmation

COLS = int(os.environ.get("COLS", "90"))
ROWS = int(os.environ.get("ROWS", "25"))
# crossterm asks the terminal where the cursor is (CSI 6 n) before it draws
# and gives up with "The cursor position could not be read" if nothing
# answers, so the parent replies to every query with a cursor-position
# report, the way a real terminal would.
CPR_QUERY = b"\x1b[6n"
CPR_REPLY = b"\x1b[1;1R"

pid, fd = pty.fork()
if pid == 0:  # child
    os.execvp("min", ["min", "dash"])
    os._exit(127)

# Give the pty a real size; a 0x0 window makes a TUI lay out nothing.
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

# parent: fd is the pty master for the `min dash` child
quit_at = time.monotonic() + dwell
sent_quit = False
hard_deadline = quit_at + 15  # safety cap: don't let a hung dash wedge recording

try:
    while time.monotonic() < hard_deadline:
        now = time.monotonic()
        if not sent_quit and now >= quit_at:
            if os.environ.get("DASH_EXIT", "kill") == "quit":
                os.write(fd, QUIT_KEY)
            else:
                # End the recording on the dash itself: a clean quit restores
                # the main screen and the gif's last frame goes blank, so
                # by default the child is terminated while still drawing.
                os.kill(pid, signal.SIGTERM)
            sent_quit = True
        ready, _, _ = select.select([fd], [], [], 0.2)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break  # pty closed (child exited)
        if not chunk:
            break
        if CPR_QUERY in chunk:
            os.write(fd, CPR_REPLY * chunk.count(CPR_QUERY))
            chunk = chunk.replace(CPR_QUERY, b"")
        sys.stdout.buffer.write(chunk)
        sys.stdout.flush()
finally:
    try:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            time.sleep(1)
            wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0

ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
sys.exit(0 if ok else 1)
