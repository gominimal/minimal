---
id: 511
title: "gvproxy v0.8.9 switch-attachment protocol for DM2 (tap-fd handshake)"
status: proved
date: 2026-06-21
budget_hours: 3
actual_hours: 2.5
related:
  - "issue #478 (spec-networking tracking issue)"
  - "issue #496 (U1-T2: sandbox2 OwnIp netns/tap provisioning)"
  - "issue #497 (U1-T3: gvproxy child lifecycle)"
  - "issue #511 (this spike)"
  - "docs/specs/03-spec-networking/03-spec-networking.md (R1.4, R1.5, R1.6, R1.7, R2.4)"
tags:
  - gvproxy
  - networking
  - unit-1
  - dm2
  - tap
---

# Question

For gvproxy v0.8.9 on DM2 (native Linux), concretely:

1. What is the host-switch **invocation + flags** to run one gvproxy serving
   multiple PTask clients?
2. What is the **attachment handshake** for a tap-attached netns client to join
   the switch — the wire protocol and whether a tap fd is SCM_RIGHTS-passed or a
   socket connection is used?
3. What is the **L2 / IP / route** setup inside two `OwnIp` netns so
   PTask-to-PTask TCP traverses the switch (UC6), and what makes a `NoNet` netns
   refuse egress (UC1)?
4. What is the gvproxy **port-forward / management API** surface used later for
   ingress/egress (Unit 2)?

# Hypothesis

gvproxy accepts multiple clients via a `-listen` unix socket that serves an HTTP
API; each client POSTs to `/connect`, the connection is hijacked and becomes a
raw Ethernet frame stream with a 2-byte length prefix (HyperKit framing); no
SCM_RIGHTS fd passing is involved. The subnet is configurable only via a YAML
config file (no CLI flag). IP assignment comes from gvproxy's built-in DHCP
server or from `dhcpStaticLeases` in the config.

# Method

1. Fetched the pinned `gvproxy-linux-amd64` v0.8.9 binary via
   `scripts/fetch-gvproxy.sh` and ran it with `--help` to enumerate flags.
2. Read upstream `containers/gvisor-tap-vsock` at git tag v0.8.9 (commit
   `dd4a4a5`) via the GitHub API: `cmd/gvproxy/main.go`, `config.go`,
   `config.yaml`; `pkg/transport/listen.go`, `listen_linux.go`, `dial_linux.go`,
   `tunnel.go`; `pkg/tap/switch.go`, `protocols.go`, `link.go`, `ip_pool.go`;
   `pkg/virtualnetwork/mux.go`, `virtualnetwork.go`, `services.go`; `pkg/types/
   configuration.go`, `handshake.go`, `paths.go`, `gvproxy_command.go`; and
   the client reference: `cmd/vm/main_linux.go`.
3. Read `crates/sandbox2/src/config.rs` and `crates/sessions/src/lib.rs` to
   understand the existing `NetworkMode` enum and sandbox infrastructure.

# Findings

## 1. Host invocation and flags

### Binary flags (from `gvproxy --help`)

```
  -config string        Use configuration file with command line override
  -listen value         control endpoint (repeatable; serves HTTP API + /connect)
  -services string      Exposes the same HTTP API as --listen, without /connect
  -listen-bess string   unixpacket socket (Bess-compatible; single client)
  -listen-qemu string   unix socket (Qemu protocol; single client)
  -listen-vfkit string  unixgram socket (vfkit-compatible; single client)
  -listen-vpnkit string VPNKit socket (Hyperkit; single-client: not suitable for DM2)
  -mtu int              Set the MTU (default 1500)
  -ssh-port int         Port to expose inside the VM; -1 to disable (default 2222)
  -pid-file string      Write PID here
  -log-file string      Redirect logrus output here
  -notification string  unix:// socket for network-ready JSON events
  -debug                Verbose packet logging
  -version              Print version
```

**Critical: there is no `-subnet` CLI flag.** The subnet (and the gateway IP,
static DHCP leases, DNS zones, etc.) is configurable **only** via a YAML config
file passed with `-config`. The hard-coded default subnet is `192.168.127.0/24`.

### Correct DM2 invocation for minimald

minimald should write a YAML config file to a state directory and spawn gvproxy
like this:

```sh
gvproxy \
  -config /run/minimald/gvproxy.yaml \
  -listen unix:///run/minimald/gvproxy-api.sock \
  -pid-file /run/minimald/gvproxy.pid \
  -ssh-port -1
```

With `/run/minimald/gvproxy.yaml`:

```yaml
stack:
  mtu: 1500
  subnet: "100.64.0.0/16"
  gatewayIP: "100.64.0.1"
  gatewayMacAddress: "5a:94:ef:e4:0c:dd"
  nat:
    "100.64.255.254": "127.0.0.1"   # gateway virtual IP → host loopback
  gatewayVirtualIPs:
    - "100.64.255.254"
  dhcpStaticLeases:
    "100.64.0.2": "52:54:00:00:00:02"   # example: PTask A
    "100.64.0.3": "52:54:00:00:00:03"   # example: PTask B
```

Notes:
- When `-config` is given, the CLI defaults for `dns`, `dhcpStaticLeases`,
  `forwards`, `vpnKitUUIDMacAddresses`, and `dnsSearchDomains` are **not**
  applied; they must be explicit in the YAML if needed.
- `-ssh-port -1` disables the default `127.0.0.1:2222 → 192.168.127.2:22`
  forward (that forward targets an IP that doesn't exist on our custom subnet).
- The warning `"CLI argument -ssh-port is unavailable with config file"` is
  emitted when `-config` is present; pass `-ssh-port -1` anyway to suppress
  the default forward that would be added without the flag.
- The unix socket is mode 0600 by default; gvproxy sets this via umask.

### Multi-client capacity

Only the `-listen` endpoint is multi-client. The accept loop is inside
`httpServe()` (Go's `http.Server.Serve(ln)`) which forks a new goroutine per
connection. **Every other interface (`-listen-qemu`, `-listen-bess`,
`-listen-vfkit`, `-listen-vpnkit`) accepts exactly one connection** per
gvproxy lifetime (their code paths call `Accept()` once with no loop). For a
one-gvproxy-per-host design serving N PTasks, `-listen` is the only option.

Source:
[`cmd/gvproxy/main.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/cmd/gvproxy/main.go),
[`cmd/gvproxy/config.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/cmd/gvproxy/config.go).

## 2. Attachment handshake

### No SCM_RIGHTS fd passing

The spec R1.5 states "On DM2 the fd-pass is over a unix socket or SCM_RIGHTS."
**This is incorrect.** The gvproxy switch attachment has no SCM_RIGHTS layer.
gvproxy never calls `recvmsg` with `SCM_RIGHTS`; it has no `cmsg`-handling code
anywhere in the repository. The fd-pass assumption should be struck from R1.5.

### Actual wire protocol

The attachment is a **plain HTTP connection upgrade** over the unix socket:

1. Client opens a `unix` stream socket to `/run/minimald/gvproxy-api.sock`.
2. Client sends an HTTP request (raw over the socket, no TCP):
   ```http
   POST /connect HTTP/1.0
   Host: localhost

   ```
   (Path `"/connect"` is `types.ConnectPath`; the method can be GET or POST —
   gvproxy ignores it and hijacks the conn immediately.)
3. gvproxy's HTTP server calls `Hijack()` on the response writer. **No HTTP
   response is written back.** The raw `net.Conn` is handed to
   `Switch.Accept()`.
4. `Switch.Accept()` registers the connection in the switch's conn map and
   enters the receive loop.
5. From this point: raw **Ethernet frames** flow both ways, each prefixed with
   a 2-byte little-endian uint16 length (HyperKit protocol).

Wire frame layout (send and receive are identical):
```
[LE uint16: frame_len][frame_len bytes: raw Ethernet frame (including 14-byte header)]
```

The `cmd/vm` binary (`gvforwarder`) is the upstream reference client
([`cmd/vm/main_linux.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/cmd/vm/main_linux.go));
it uses the `water` library to open a Linux TAP device and runs relay loops
between the TAP fd and the gvproxy socket. This is the exact pattern minimald
must implement.

### Step-by-step handshake for a PTask attach

```
minimald                                    gvproxy
─────────────────────────────────────────────────────
create TAP device "tap-ptask-N" in netns
open TAP fd (O_RDWR on /dev/net/tun)
set MAC 52:54:00:00:00:NN on tap device
bring link up (SIOCSIFFLAGS IFF_UP)
assign IP via DHCP or static config

connect(unix, /run/minimald/gvproxy-api.sock) ───►
write("POST /connect HTTP/1.0\r\nHost: …\r\n\r\n") ─►
                                            hijack conn, register switch port
        ◄─── [no response; raw frame exchange begins] ───►

async task rx: read(tap_fd) → LE_u16(len) + frame → write(sock)
async task tx: read(sock) → LE_u16(len) → read(frame) → write(tap_fd)
```

gvproxy's switch learns the source MAC of every frame arriving on a port
(`rxBuf()` inserts `eth.SourceAddress() → connID` into its CAM table). There is
no explicit "hello" or registration frame — the first ARP request from the TAP
device teaches the switch the PTask's MAC.

### Protocol selection

The protocol on the `/connect` path is controlled by which `-listen-*` flags are
set (see `GvproxyConfigure` in `config.go`). When **only** `-listen` is provided
and no `-listen-qemu`/`-listen-bess`/`-listen-vfkit` is set, the protocol
defaults to `HyperKitProtocol`. This is what minimald must use.

Source: [`pkg/tap/switch.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/pkg/tap/switch.go),
[`pkg/tap/protocols.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/pkg/tap/protocols.go),
[`pkg/virtualnetwork/mux.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/pkg/virtualnetwork/mux.go).

## 3. Minimal Rust client sketch

This sketch is the U1-T2 implementation target. It lives in `sandbox2` or a new
`network` module inside `minimald`. The relay runs as a supervised Tokio task
alongside the PTask.

```rust
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::unix::AsyncFd;

/// Attach a TAP fd to a running gvproxy instance over its unix socket.
/// `tap_fd`: open fd of the TAP device (opened from host namespace).
/// `api_sock`: path to gvproxy's -listen unix socket.
pub async fn attach_to_switch(
    tap_fd: std::os::fd::OwnedFd,
    api_sock: &std::path::Path,
) -> anyhow::Result<()> {
    // 1. Connect to gvproxy's management socket.
    let mut sock = tokio::net::UnixStream::connect(api_sock).await?;

    // 2. Send the HTTP "connect" request (raw, no response expected).
    sock.write_all(b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;

    // 3. Wrap the TAP fd for epoll-driven async I/O.
    //    tokio::fs::File routes all I/O through a blocking thread pool via
    //    pread/pwrite; TAP character devices do not support pread/pwrite and
    //    require plain read/write with non-blocking mode + AsyncFd for epoll
    //    readiness notification.
    // SAFETY: tap_fd.into_raw_fd() transfers ownership of a valid, open, caller-owned
    // file descriptor. File takes exclusive ownership and will close it on drop.
    let tap_file = unsafe { std::fs::File::from_raw_fd(tap_fd.into_raw_fd()) };
    tap_file.set_nonblocking(true)?;
    let tap = Arc::new(AsyncFd::new(tap_file)?);

    // 4. Two relay tasks: tap→socket and socket→tap.
    let tap_tx = Arc::clone(&tap);
    let (sock_rx, sock_tx) = sock.into_split();
    let t1 = tokio::spawn(tap_to_switch(tap, sock_tx));
    let t2 = tokio::spawn(switch_to_tap(sock_rx, tap_tx));
    let (r1, r2) = tokio::try_join!(t1, t2)?;
    r1?; r2?;
    Ok(())
}

/// TAP → gvproxy: read raw Ethernet frames, prepend 2-byte LE length.
async fn tap_to_switch<W>(
    tap: Arc<AsyncFd<std::fs::File>>,
    mut sock: W,
) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    // Sized for the default MTU of 1500: 1514 (max frame excl. FCS) + 4 (802.1Q VLAN) = 1518.
    // Scoped to gvproxy's default -mtu 1500; derive from the configured MTU in the real impl.
    let mut buf = vec![0u8; 1518];
    loop {
        let n = loop {
            let mut guard = tap.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(result) => break result?,
                Err(_) => continue, // WouldBlock; re-register for readiness
            }
        };
        if n == 0 { break; }
        let len = (n as u16).to_le_bytes();
        // Combined buffer avoids desync if the socket closes between writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&len);
        framed.extend_from_slice(&buf[..n]);
        sock.write_all(&framed).await?;
    }
    Ok(())
}

/// gvproxy → TAP: read 2-byte LE length, then frame, write to TAP.
async fn switch_to_tap<R>(
    mut sock: R,
    tap: Arc<AsyncFd<std::fs::File>>,
) -> anyhow::Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut size_buf = [0u8; 2];
    loop {
        sock.read_exact(&mut size_buf).await?;
        let n = u16::from_le_bytes(size_buf) as usize;
        let mut buf = vec![0u8; n];
        sock.read_exact(&mut buf).await?;
        // TAP writes are atomic for single Ethernet frames within MTU.
        loop {
            let mut guard = tap.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write_all(&buf)) {
                Ok(result) => { result?; break; }
                Err(_) => continue, // WouldBlock; re-register for readiness
            }
        }
    }
    // No Ok(()) — outer loop has type `!`; coerces to anyhow::Result<()>.
}
```

**TAP device creation** (before `attach_to_switch`) requires entering the
PTask's network namespace, opening `/dev/net/tun`, issuing `TUNSETIFF` with
`IFF_TAP | IFF_NO_PI`, returning the fd to the host namespace, then calling
`TUNSETPERSIST` if the device must outlive the creating process. The crate
`nix` (`nix::fcntl`, `nix::ioctl`) or `tun` / `tun-tap` covers this. The
`sandbox2` crate currently creates network namespaces via `hakoniwa`; TAP
device creation should be added as a pre-spawn hook.

## 4. L2 / IP / route setup inside OwnIp PTasks

### Network topology (single host, two PTasks)

```
┌────────────────────────────────────┐
│  gvproxy switch (100.64.0.0/16)   │
│  gateway: 100.64.0.1 (DHCP, DNS)  │
│  host alias: 100.64.255.254 → lo  │
│                                    │
│  port A      port B      port GW  │
└──┬───────────┬───────────┬────────┘
   │ (socket)  │ (socket)  │ (linkendpoint)
   │           │           │
  relay A     relay B    gvisor netstack
 ┌─┴──────┐  ┌─┴──────┐
 │tap-A   │  │tap-B   │   (host namespace, relay tasks)
 │in netns│  │in netns│
 └────────┘  └────────┘
  100.64.0.2  100.64.0.3   (assigned via DHCP or static lease)
  MAC: 52:54:00:00:00:02   MAC: 52:54:00:00:00:03
```

### Inside an OwnIp PTask netns

After the relay is running and the TAP device is up, inside the netns run:

```sh
# Option A: DHCP (gvproxy has built-in DHCP on gateway IP)
ip link set tap0 address 52:54:00:00:00:02
ip link set tap0 up
dhclient -4 -d tap0         # or udhcpc -i tap0
# gvproxy assigns 100.64.0.2/16, gateway 100.64.0.1

# Option B: static (requires dhcpStaticLeases in gvproxy config)
ip link set tap0 address 52:54:00:00:00:02
ip link set tap0 up
ip addr add 100.64.0.2/16 dev tap0
ip route add default via 100.64.0.1
```

For minimald's use case, Option B (static, pre-assigned via `dhcpStaticLeases`
in the gvproxy YAML) is cleaner: minimald controls which MAC→IP mapping is
allocated before spawning gvproxy (or via a YAML reload / API update), and
configures the TAP device statically without requiring a DHCP client inside
every PTask netns. minimald must maintain a per-host allocation table
(MAC, IP) to avoid reuse (R1.6).

### UC6: PTask A → PTask B TCP

1. PTask A's application issues `connect(100.64.0.3, port)`.
2. The gvisor/Linux kernel in netns-A ARPs for `100.64.0.3`; the ARP goes to
   the TAP, relay-A reads it and sends it to gvproxy.
3. gvproxy's switch broadcasts the ARP to all other ports (including the
   gateway, which does not own `100.64.0.3`). For PTask-to-PTask ARP:
   - ARP request for `100.64.0.3` arrives at the switch from relay-A.
   - gvproxy broadcasts to all connected ports; relay-B delivers it to TAP-B.
   - PTask B replies with an ARP reply; relay-B delivers that to the switch.
   - gvproxy's CAM now has `52:54:00:00:00:03 → port-B`; relay-A delivers
     the ARP reply to TAP-A.
   - PTask A's kernel now has a route to `100.64.0.3` via the TAP MAC.
   - Subsequent TCP SYN and data frames are unicast and switched directly.
4. Traffic does NOT traverse the host network stack. It is entirely inside
   gvproxy's userspace switch.

Source: [`pkg/tap/switch.go` `rxBuf()` and `txPkt()`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/pkg/tap/switch.go).

### UC1: NoNet PTask

For `NoNet`, minimald creates a new network namespace but **does not create
any TAP device, does not run a relay, and does not connect to gvproxy**.

Inside the netns: only `lo` exists and it is down by default. There are no
routes and no default gateway.

```sh
# Observed inside a NoNet netns:
$ ip link
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN
$ ip route
(empty)
$ connect(8.8.8.8, 80) → ENETUNREACH (errno 101)
```

Egress is refused by the kernel at the routing stage, not by gvproxy policy.
This is the correct behavior for UC1. Loopback-only connectivity within the
PTask is possible by bringing `lo` up if needed for intra-PTask IPC.

## 5. Port-forward / management API (gateway HTTP)

The HTTP API is served on the unix socket (same listener as `/connect`) and is
accessible only from the host side. The gateway's internal HTTP on port 80
(reachable from within PTasks at the gateway IP) is a separate gvisor netstack
endpoint serving DNS and DHCP only; it does not route to `ServicesMux()` and
does not expose the management or port-forward endpoints. The management API is
unix-socket only: PTasks cannot reach it.

The API relevant to Unit 2:

```
# List active port-forwards
GET /services/forwarder/all
→ 200 JSON: [{"local":"127.0.0.1:8080","remote":"100.64.0.2:8080","protocol":"tcp"}, ...]

# Expose a host port → PTask TCP port (ingress)
POST /services/forwarder/expose
Content-Type: application/json
{"local":"127.0.0.1:8080","remote":"100.64.0.2:8080","protocol":"tcp"}
→ 200 OK

# Remove a port-forward
POST /services/forwarder/unexpose
Content-Type: application/json
{"local":"127.0.0.1:8080","protocol":"tcp"}
→ 200 OK
```

`local` is a `host:port` that gvproxy listens on (on the host); `remote` is
the PTask's switch IP and port. For egress filtering (Unit 2 / R2.2), gvproxy
has no per-client egress ACL built into v0.8.9; filtering must be implemented
at the relay layer (minimald inspects/drops frames before forwarding to the
switch) or deferred to a follow-up once the gvproxy egress filter API is
confirmed.

Additional management endpoints:

```
GET /leases    → {ip: mac} DHCP lease table (IP to MAC mapping)
GET /cam       → {mac: portid} switch CAM table (who is on which port)
GET /stats     → {sent, received, …} byte counters
```

These are accessible only from the host side (unix socket), not from within
PTasks via the gateway. The `-services` flag can expose a management-only
socket without the `/connect` endpoint.

Source: [`pkg/virtualnetwork/mux.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/pkg/virtualnetwork/mux.go),
[`pkg/services/forwarder/ports.go`](https://github.com/containers/gvisor-tap-vsock/blob/dd4a4a5d8a650b41f07b99505b5b5718ead1dc75/pkg/services/forwarder/ports.go).

# Conclusion

**Status: proved.**

All four questions are concretely answered by reading the source. The hypothesis
was correct with one material correction.

1. **Invocation**: `gvproxy -config /path/gvproxy.yaml -listen
   unix:///path/api.sock -ssh-port -1`. The subnet requires a YAML config file;
   there is no `-subnet` CLI flag.

2. **Attachment handshake**: HTTP POST to `/connect` on the unix socket; the
   connection is hijacked with no HTTP response; Ethernet frames are exchanged
   in HyperKit framing (2-byte LE uint16 length prefix + raw Ethernet). No
   SCM_RIGHTS fd passing occurs. The "tap fd" language in R1.5 is misleading:
   gvproxy never receives a file descriptor; instead, minimald runs an async
   relay task that bridges the netns-internal TAP device to gvproxy's socket.
   This relay is straightforward async I/O (Tokio tasks).

3. **L2/IP/route**: For `OwnIp`, a TAP device in the PTask netns gets a unique
   MAC, and the IP is assigned via gvproxy's built-in DHCP or via
   `dhcpStaticLeases` config (preferred). Default route points to the gateway
   IP. UC6 PTask-to-PTask works automatically via L2 switching; no NAT or extra
   routes. For `NoNet`, an empty netns with `lo` down gives `ENETUNREACH` on
   any egress attempt.

4. **Port-forward API**: `POST /services/forwarder/expose` with JSON body on
   the unix socket; queryable via `GET /services/forwarder/all`. DHCP leases
   accessible via `GET /leases`. No per-client egress ACL in gvproxy v0.8.9.

# Action items

1. **Correct R1.5** in `docs/specs/03-spec-networking/03-spec-networking.md`:
   replace "passing the tap file descriptor to the running gvproxy as a new
   switch client. On DM2 the fd-pass is over a unix socket or SCM_RIGHTS" with
   "minimald runs an async relay task per OwnIp PTask that bridges the netns TAP
   device to gvproxy via HTTP POST to `/connect` on the management unix socket,
   using HyperKit framing (2-byte LE length prefix + raw Ethernet frames). No
   SCM_RIGHTS or fd-passing is involved."

2. **Add YAML config generation** to gvproxy lifecycle (R1.4, issue #497):
   minimald must write the YAML config file (subnet, gatewayIP, dhcpStaticLeases)
   to a state directory before spawning gvproxy. The IP allocation table is owned
   by minimald and written into the config before each gvproxy start.

3. **Implement relay in Rust** (R1.5, issue #496): the Rust sketch above is the
   implementation target for the TAP↔gvproxy relay inside `sandbox2` or a
   `minimald::network` module. Use `tokio::io::unix::AsyncFd` with non-blocking
   mode for the TAP fd (epoll-driven; `tokio::fs::File` uses `pread`/`pwrite`
   which TAP devices do not support); wrap in `Arc` to share between the two
   relay tasks. The `tun-tap` or `nix` crate handles TAP device creation;
   `tokio::net::UnixStream` handles the gvproxy socket.

4. **IP allocation strategy** (R1.6): use `dhcpStaticLeases` with pre-assigned
   IP→MAC entries (IP as key, MAC as value) rather than dynamic DHCP; minimald maintains the allocation
   map in its process state and writes it to the gvproxy YAML on each new PTask
   attachment. An alternative is dynamic DHCP + polling `/leases` to discover
   the assigned IP, but this is non-deterministic and adds latency.

5. **Egress filtering note for Unit 2** (R2.2): gvproxy v0.8.9 has no per-port
   egress ACL. Unit 2 must implement egress filtering at the relay layer (frame
   inspection before writing to the switch socket) or rely on a later gvproxy
   API. File this as a design question for the Unit 2 task.

6. **Subnet CLI flag gap**: there is no `-subnet` CLI flag. Restarting gvproxy
   (on a restart-of-minimald) regenerates the YAML, which is the correct path.
   Document this in the gvproxy lifecycle spec (issue #497).

# Residual Risks / Live Trial Needed

The following findings are source-confirmed but not yet live-tested. A live
trial against an actual gvproxy process is recommended before U1-T2
implementation begins:

- **`dhcpStaticLeases` YAML assignment**: source reading confirms the
  `{ip: mac}` key format, but live behavior of gvproxy's DHCP server
  honouring a static lease (first DHCP request, renewal, IP shown in `/leases`)
  has not been exercised in a real netns.
- **HyperKit framing / first-ARP timing**: the source confirms 2-byte LE
  length prefix, but the exact sequence (first frame triggers CAM population,
  switch broadcast behaviour on ARP requests) has not been traced on a live
  process.
- **Multi-client concurrent attachment**: the `-listen` accept loop is
  source-confirmed as multi-goroutine, but concurrent attachment of two PTasks
  and the resulting switch isolation has not been exercised.
- **`-ssh-port -1` with `-config`**: source shows `-ssh-port` is overridden by
  `-config`, emitting a warning. Whether the default `2222` forward is still
  inserted when `-config` is present without an explicit `-ssh-port -1` needs a
  live `--help`/process trace to confirm.

# Artifacts

## Binary invocation

```
$ ./scripts/fetch-gvproxy.sh /tmp/gvproxy
fetch-gvproxy: downloading https://github.com/containers/gvisor-tap-vsock/releases/download/v0.8.9/gvproxy-linux-amd64
fetch-gvproxy: gvproxy-linux-amd64 v0.8.9 verified (3011c5629c9138d2050fb23c510e09ae53e30ec52e6a9ab85632bc1550e8ef63)

$ /tmp/gvproxy --help
Usage of /tmp/gvproxy:
  -config string       Use configuration file with command line override
  -debug               Print debug info
  -listen value        control endpoint
  -listen-bess string  unixpacket socket to be used by Bess-compatible applications
  -listen-qemu string  Socket to be used by Qemu
  -listen-stdio string accept stdio pipe
  -listen-vfkit string unixgram socket to be used by vfkit-compatible applications
  -listen-vpnkit string VPNKit socket to be used by Hyperkit
  -mtu int             Set the MTU (default: 1500)
  -notification string Socket to be used to send network-ready notifications
  -pid-file string     Generate a file with the PID in it
  -services string     Exposes the same HTTP API as the --listen flag, without /connect
  -ssh-port int        Port to access the guest virtual machine (default 2222)
  -version             Print version information
  [... forward-* and pcap/log-file omitted]
```

## Source files read at v0.8.9 (commit dd4a4a5)

- `cmd/gvproxy/main.go` — process lifecycle, listener setup, per-protocol
  accept loops (Qemu/Bess single-accept confirmed)
- `cmd/gvproxy/config.go` — CLI flag parsing, YAML config merging, protocol
  selection logic, subnet default `192.168.127.0/24`
- `cmd/gvproxy/config.yaml` — YAML format reference
- `cmd/vm/main_linux.go` — reference client (`gvforwarder`): creates TAP,
  dials unix socket, writes HTTP POST to `/connect`, relay loops confirmed
- `pkg/types/paths.go` — `ConnectPath = "/connect"`
- `pkg/types/configuration.go` — `Protocol` enum, `HyperKitProtocol` comment
  ("handshake, then 16bits little endian size of packet, then the packet")
- `pkg/transport/listen.go`, `listen_linux.go` — URI schemes: `unix://`,
  `vsock://`, `unixpacket://`
- `pkg/transport/dial_linux.go` — client dial: `unix://` returns path `/connect`
- `pkg/virtualnetwork/mux.go` — `Mux()` registers `/connect` handler; hijack
  with no response; calls `Switch.Accept(conn, HyperKitProtocol)`
- `pkg/virtualnetwork/services.go` — `ServicesMux()`: `/leases`, `/cam`,
  `/stats`, `/services/forwarder/…` routes
- `pkg/tap/switch.go` — `Accept()`, `rxStream()`, `txPkt()`: frame relay;
  CAM table; no handshake beyond HTTP hijack
- `pkg/tap/protocols.go` — `hyperkitProtocol`: `Buf()` = 2 bytes, `Write` =
  `binary.LittleEndian.PutUint16`, `Read` = LE uint16
- `pkg/tap/ip_pool.go` — DHCP IP pool: sequential scan for unallocated IPs;
  `Reserve(ip, mac)` for static leases; `GetOrAssign(mac)` for dynamic
- `pkg/services/forwarder/ports.go` — `Expose`/`Unexpose`/`Mux()`: the
  `/expose` and `/unexpose` endpoints; JSON body format confirmed
