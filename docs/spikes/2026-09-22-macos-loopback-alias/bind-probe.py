#!/usr/bin/env python3
"""Bind probe: one TCP bind(addr, 0) per address, EADDRNOTAVAIL means absent."""
import errno, socket, sys, time

def probe(addr):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    t0 = time.perf_counter()
    try:
        s.bind((addr, 0))
        return "OK", s.getsockname()[1], (time.perf_counter() - t0) * 1e6
    except OSError as e:
        return f"{errno.errorcode.get(e.errno, e.errno)} ({e.errno}) {e.strerror}", None, (time.perf_counter() - t0) * 1e6
    finally:
        s.close()

addrs = sys.argv[1:] or ["127.0.0.1", "::1", "127.0.64.1", "127.0.64.2", "127.0.64.100", "127.0.64.254"]
t_all = time.perf_counter()
for a in addrs:
    r, port, us = probe(a)
    print(f"{a:<14} {r:<48} {'port='+str(port) if port else '':<12} {us:7.1f} us")
print(f"total {len(addrs)} probes in {(time.perf_counter()-t_all)*1e3:.2f} ms")
