#!/usr/bin/env python3
"""Stand-in for the loopback answerer: a UDP DNS server on 127.0.0.1:15353.

Answers A queries from a fixed table, an empty NOERROR for AAAA, NXDOMAIN
otherwise. Only what the scoped resolver needs for the two-box browser check.
"""
import socket, struct, sys

TABLE = {"a.min.internal.": "127.0.64.10", "b.min.internal.": "127.0.64.11"}
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 15353

def name_wire(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.rstrip(".").split(".")) + b"\0"

ZONE = name_wire("min.internal.")
SOA_RDATA = name_wire("ns.min.internal.") + name_wire("hostmaster.min.internal.") + struct.pack("!IIIII", 1, 3600, 600, 86400, 30)
SOA = ZONE + struct.pack("!HHIH", 6, 1, 30, len(SOA_RDATA)) + SOA_RDATA

def parse_name(msg, off):
    labels = []
    while True:
        n = msg[off]; off += 1
        if n == 0: break
        labels.append(msg[off:off + n].decode()); off += n
    return ".".join(labels) + ".", off

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", PORT))
print(f"answerer on 127.0.0.1:{PORT} {TABLE}", flush=True)
while True:
    msg, peer = s.recvfrom(4096)
    print(f"raw {peer[1]} {msg.hex()}", flush=True)
    try:
        qid, flags, qd = struct.unpack("!HHH", msg[:6])
        name, off = parse_name(msg, 12)
        qtype, qclass = struct.unpack("!HH", msg[off:off + 4]); off += 4
    except Exception as e:  # never stall the resolver on a packet we cannot read
        print(f"unparsed from {peer[1]}: {e}", flush=True)
        continue
    question = msg[12:off]
    ip = TABLE.get(name.lower())
    if ip and qtype == 1:
        rcode, an, ns = 0, 1, 0
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)
    else:
        # NODATA or NXDOMAIN: an SOA in the authority section (RFC 2308) so the
        # resolver can cache the negative instead of retrying.
        rcode, an, ns = (0 if ip else 3), 0, 1
        answer = SOA
    hdr = struct.pack("!HHHHHH", qid, 0x8580 | rcode, 1, an, ns, 0)
    s.sendto(hdr + question + answer, peer)
    print(f"{peer[1]} {name} type={qtype} -> {ip if an else 'rcode=' + str(rcode)}", flush=True)
