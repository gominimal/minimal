#!/usr/bin/env python3
"""A stand-in node for scripts/zoned-macos-e2e.sh: publishes one box row
into the installed minzoned service over its channel, the way a VM host
daemon does, without a VM.

The channel is newline-delimited JSON over a unix stream
(crates/minvmd/src/net/answerer.rs): a hello, then an address allocation for
the box, then a publish of the box's row. The service holds the row only
while the connection stays open, so `hold` keeps it open, and reconnects and
re-publishes when the service restarts, as a node does.

  zoned-e2e-publisher.py once CHANNEL NODE BOX VERSION
      Connect, hello, allocate, publish, print the reply lines, exit.
      Exits non-zero if any reply is not ok.
  zoned-e2e-publisher.py hold CHANNEL NODE BOX VERSION ADDRESS_FILE
      Publish, write the allocated address to ADDRESS_FILE, and hold the
      connection until SIGTERM; reconnect and re-publish when it drops.

Stdlib only.
"""

import json
import os
import signal
import socket
import sys
import time


def request(stream, sock, message):
    sock.sendall((json.dumps(message) + "\n").encode())
    line = stream.readline()
    if not line:
        raise ConnectionError("the channel closed before replying")
    reply = json.loads(line)
    print(json.dumps({"sent": message, "reply": reply}), flush=True)
    return reply


def publish(channel, node, box, version):
    """Connect and publish the box's row. Returns (socket, address), or
    raises with the refusal the service gave."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(channel)
    stream = sock.makefile("r")
    hello = request(stream, sock, {"node": node, "version": version})
    if not hello.get("ok"):
        raise PermissionError(hello.get("error", "hello refused"))
    allocated = request(stream, sock, {"allocate": box})
    if not allocated.get("ok") or not allocated.get("address"):
        raise RuntimeError(f"allocation refused: {allocated}")
    address = allocated["address"]
    row = {"name": f"{box}.min.internal", "address": address, "live": True}
    published = request(stream, sock, {"rows": [row]})
    if not published.get("ok") or published.get("refused"):
        raise RuntimeError(f"publish refused: {published}")
    return sock, address


def hold(channel, node, box, version, address_file):
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    while not stopping:
        try:
            sock, address = publish(channel, node, box, version)
        except (OSError, ConnectionError, RuntimeError) as error:
            print(f"publish failed, retrying: {error}", flush=True)
            time.sleep(0.25)
            continue
        tmp = address_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(address + "\n")
        os.replace(tmp, address_file)
        # Block until the service drops the connection (a restart) or
        # SIGTERM arrives; the timeout lets the loop see the signal.
        sock.settimeout(0.25)
        while not stopping:
            try:
                if not sock.recv(1):
                    print("the channel closed; reconnecting", flush=True)
                    break
            except socket.timeout:
                continue
            except OSError:
                break
        sock.close()


def main(argv):
    if len(argv) >= 5 and argv[0] == "once":
        _, channel, node, box, version = argv[:5]
        try:
            sock, _ = publish(channel, node, box, int(version))
        except (OSError, ConnectionError, PermissionError, RuntimeError) as error:
            print(f"refused: {error}", flush=True)
            return 1
        sock.close()
        return 0
    if len(argv) >= 6 and argv[0] == "hold":
        _, channel, node, box, version, address_file = argv[:6]
        hold(channel, node, box, int(version), address_file)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
