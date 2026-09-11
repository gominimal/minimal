---
id: 649
title: "KVM re-run of the Linux leg: *.min.internal to a VM-backed box by identity"
status: proved-linux-kvm
date: 2026-09-11
budget_hours: 4
actual_hours: 2
related:
  - "gominimal/inbox#649 (the spike; this is its third result comment)"
  - "gominimal/inbox#646 story S1b-2 (Box ports reach the host by identity)"
  - "gominimal/arch#59 (§7.1 ruling from the spike)"
  - "docs/spikes/2026-09-10-native-host-resolution.md (the DM2 run this repeats on KVM)"
  - "crates/minimald/src/net/policy.rs (expose_request, OwnIpGuard teardown), crates/minimald/src/net/proxy.rs (Router::route)"
tags:
  - networking
  - dns
  - min-internal
  - localvm
  - kvm
  - uc2a
---

# Question

The two earlier Linux runs of spike #649 had no KVM: a Debian VM under OrbStack
and a host-native (DM2) Ubuntu daemon. Neither exercised a `local-minvmd`
session, so the `own_ip`-inside-a-VM path was never measured against native
DNS, and story S1b-2 in #646 could not be sized. This run repeats the Linux
leg on a KVM host with VM-backed sessions and proves or disproves the per-box
loopback address model end to end: hook, two boxes on the same inside port,
name to box, enforcement parity, failure modes, and the `:7654` side finding.

# Scope actually covered

| | |
|---|---|
| Host | Ubuntu 25.10 aarch64 (Lima guest with nested KVM), kernel 6.17.0-41, `/dev/kvm` via the `kvm` group |
| Resolver | systemd-resolved 257.9-0ubuntu2.5, stub mode (`127.0.0.53`), `DNSSEC=no/unsupported` |
| Link manager | **systemd-networkd active, NetworkManager inactive** (`nmcli` not installed), so the persistent variant exercised is networkd `.netdev`/`.network` |
| Tree | 8e7e72c2, `just initramfs` + `just up-kvm` (native musl toolchain, no `cross`); guest `minimald` built with `networking-proxy` |
| Daemon identity | `pgrep -af minvmd` → `target/aarch64-unknown-linux-musl/debug/minvmd run`; `minvmd.log.2026-09-11` reports `0.5.5-dev.10.g8e7e72c2`; the Aug-26 install in `~/.local/bin` was on `PATH` and would have answered if the justfile env had not been sourced |
| Guest | Linux 6.12.x generic kernel, gvproxy v0.8.9, sessions `web`, `api`, `quiet`, `d4`, all `--provider local-minvmd --network own-ip` |
| Browsers | Chromium 152.0.7977.64 and Firefox 155.0.1 (Ubuntu snaps), headless; no display |
| Rig | `dns.py` (57 lines), `web.py` (36 lines), `map.json`, all stdlib, in the scratchpad, not in the repo |
| Not run | reboot (the host is the machine this session runs on; resolved and networkd restarts measured instead), NetworkManager keyfile (NM inactive), macOS anything, `host_ip` boxes, Firefox with DoH on |

Consequences: the VM lane is measured, not inferred; the NM half of the ruling
is still unmeasured on any host with KVM; browser rows are observed beacons,
not vendor-doc reasoning.

# Method

1. Answerer on `127.0.0.1:15353` (unprivileged): A from `map.json`
   (`web`→`127.0.0.2`, `api`→`127.0.0.3`, `quiet`→`127.0.0.4`,
   `host`→`127.0.0.1`), AAAA→NODATA, `_dns.resolver.arpa` SVCB and every
   other name→NXDOMAIN, a log line per query.
2. Hook: dummy link `min0`, `resolvectl dns/domain` (runtime), then the
   networkd files (persistent).
3. Two VM-backed sessions, each running `web.py` on `0.0.0.0:3000` inside,
   both activated with `--ingress 3000:3000`. Python is not in the base image;
   `min add --session python` inside each session (2 min 14 s the first time).
4. Forwards rebound through gvproxy's forwarder API on the host-side switch
   socket (`providers/local-minvmd0/gvproxy-switch.sock`), because no daemon
   code path binds `local` anywhere but `127.0.0.1`
   (`policy.rs::expose_request`).
5. `getent`, `dig @127.0.0.53`, `curl`, then headless Chromium and Firefox at
   `http://<name>.min.internal:3000/`; the page loads jQuery from cdnjs and
   beacons `?ua=&cdn=loaded|failed` back to the box that served it.
6. A third session with no ingress; the answerer killed; sessions destroyed;
   the `:7654` proxy probed with every hostname form.

# Findings

## A. Hook: runtime and persistent (networkd) both work; two traps, not one

Root commands, in the order a fresh host needs them (the runtime form):

```
sudo ip link add min0 type dummy && sudo ip link set min0 up      # 1, 2
sudo ip addr add 100.127.255.254/32 dev min0                        # 3 (see trap)
sudo resolvectl dns    min0 127.0.0.1:15353                         # 4
sudo resolvectl domain min0 '~min.internal'                         # 5
```

As a user: `ip link add` → `RTNETLINK answers: Operation not permitted`;
`resolvectl domain` → `Interactive authentication required` (polkit).

| Check | Result |
|---|---|
| Link up, **no address** | `Current Scopes: none`; `getent` fails in 4 ms; the answerer sees **nothing**. The trap from the earlier runs, reproduced. |
| Link with a **127/8 address** (`127.0.64.254/32`) | still `Current Scopes: none`. The kernel tags any 127/8 address `scope host` and resolved ignores host-scope addresses. **A second flavour of the same trap**: "non-link-local" is not a sufficient rule; the address must be routable scope (`scope global`). |
| Link with `100.127.255.254/32` | `Current Scopes: DNS`, `Current DNS Server: 127.0.0.1:15353` |
| `getent hosts web.min.internal` | `127.0.0.2` in **2 ms** |
| `dig @127.0.0.53 web.min.internal` | `127.0.0.2`; AAAA → `NOERROR, ANSWER: 0` |
| `getent hosts nope.min.internal` | NXDOMAIN, answered by the local answerer |
| `host.min.internal` | `127.0.0.1` |
| `example.com` during the hook | 200, never reached the answerer |
| DDR probe | resolved sent `SVCB _dns.resolver.arpa` to the answerer; NXDOMAIN was accepted |

Persistent form for this host's link manager, two root-written files and one
reload (`networkctl reload`; as a user the write is `Permission denied`):

```
/etc/systemd/network/10-min0.netdev     [NetDev] Name=min0 Kind=dummy
/etc/systemd/network/10-min0.network    [Match] Name=min0
                                        [Network] Address=100.127.255.254/32
                                        DNS=127.0.0.1:15353 Domains=~min.internal
                                        DNSDefaultRoute=no LinkLocalAddressing=no IPv6AcceptRA=no
```

| Survival | Result |
|---|---|
| `systemctl restart systemd-resolved` | hook intact, resolves |
| `systemctl restart systemd-networkd` | link recreated from the files, hook re-pushed, resolves |
| both restarted at once | resolves |
| reboot | **not run** (this host hosts the session running the spike); the config is file-derived and both services re-derive it, which is the mechanism a reboot exercises |

The `:53` half of the NetworkManager variant: on this host
`net.ipv4.ip_unprivileged_port_start=0` (set by Lima in
`/etc/sysctl.d/99-lima.conf`), so `127.0.64.1:53` bound as uid 502 and the
EACCES the earlier run saw could not be reproduced here. The capability form
was run anyway: a transient unit with `DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE` bound `127.0.64.1:53` as a dynamic
user and answered `dig`. `DynamicUser` implies `PrivateTmp`, so the unit
cannot read a script under `/tmp`; place the answerer under `/usr/local/lib`
or `/usr/libexec`.

## B. Two VM sessions with `--ingress 3000:3000`: the second does not fail at `activate`

| Step | `web` | `api` |
|---|---|---|
| `min session activate … --ingress 3000:3000` | ok, 46 s (first VM session, image warm-up) | ok, 7 s |
| `min ls` after both activated | `active` | `active`, no warning |
| `min session policy` | `{"port_mappings":[{"external_port":3000,"internal_port":3000,"proto":"tcp"}]}` | identical |
| forwarder table after `activate` | **nothing**: the forward is exposed when the PTask launches (first `exec`/`attach`), not at `activate` | same |
| first `exec` | `127.0.0.1:3000 → 100.64.0.2:3000` appears; `curl 127.0.0.1:3000` → `box=web` 200 | `127.0.0.1:3000 → 100.64.0.3:3000` (it got the port because `web`'s PTask had gone away in between, see below) |
| the loser's next `exec` | `minimald: failed to spawn process: session spawn: network attach failed: gvproxy /services/forwarder/expose returned HTTP 500: proxy already running` | |

So the collision is first-come, but it is reported neither at `activate` nor
in `ls` or `policy`; it surfaces as a raw gvproxy error on the loser's next
spawn, and the loser stays `active` in `ls` with a PTask that cannot start.
The ruling's "reported at `activate` and `ls`" (arch#59 §4) is a target, not
current behaviour.

Two lifecycle facts that S1b-2 has to design around:

- **The box's switch lease changes on every PTask spawn.** `web` was
  `100.64.0.2`, then `.6`, then `.10` across three spawns in one session. A
  forward's `remote` is therefore re-derived per spawn (the daemon already
  does this), and a name must map to something stable, which the lease is
  not.
- **Losing an `exec` client abruptly tears the whole PTask down.** Twice in
  this run the harness reaped backgrounded `min session exec` clients; each
  time the guest logged `pty master error; tearing down host … errno=Some(5)`
  followed by `container received signal SIGKILL`, and the PTask, its lease,
  and its forward were gone within a second. A normally exiting `exec` does
  not do this. Not chased here; it decides how "the moment the box listens"
  can be honoured when nothing is attached.

## C. Per-box loopback addresses, live: both forwards coexist and route to their own box

No daemon path exists (`expose_request` hardcodes `127.0.0.1`), so the
forwarder API was driven directly on the host-side switch socket, the same
verbs `policy.rs` uses:

```
POST /services/forwarder/unexpose {"local":"127.0.0.1:3000","protocol":"tcp"}                          → 200
POST /services/forwarder/expose   {"local":"127.0.0.3:3000","remote":"100.64.0.3:3000","protocol":"tcp"} → 200
POST /services/forwarder/expose   {"local":"127.0.0.2:3000","remote":"100.64.0.6:3000","protocol":"tcp"} → 200
```

| Check | Result |
|---|---|
| `ss -ltn` | `127.0.0.2:3000` and `127.0.0.3:3000`, both owned by gvproxy, coexisting |
| `curl http://127.0.0.2:3000/` | `box=web` 200 |
| `curl http://127.0.0.3:3000/` | `box=api` 200 |
| `curl http://127.0.0.1:3000/` | connection refused (rc=7): nothing left on the shared address |
| host privilege needed | none: any 127/8 address binds and routes unprivileged on Linux, no alias |

Teardown caveat, measured in F: the daemon's `OwnIpGuard` remembers the
`local` it exposed (`127.0.0.1:3000`), so a forward moved out from under it is
not removed at PTask exit. The allocator has to own the address before the
expose, not move it afterwards.

## D. Name to box: every path and both browsers, CDN loaded

| Check | `web.min.internal` | `api.min.internal` |
|---|---|---|
| `getent hosts` | `127.0.0.2`, 2 ms | `127.0.0.3` |
| `dig @127.0.0.53` A / AAAA | `127.0.0.2` / `NOERROR, ANSWER: 0` | `127.0.0.3` / same |
| `curl http://<name>:3000/` | `box=web` 200, box saw `Host: web.min.internal:3000` | `box=api` 200 |
| Chromium 152 headless | beacon `ua=chromium cdn=loaded host=web.min.internal:3000` | `ua=chromium cdn=loaded host=api.min.internal:3000` |
| Firefox 155 headless | beacon `ua=firefox cdn=loaded host=web.min.internal:3000` | `ua=firefox cdn=loaded host=api.min.internal:3000` |

Two boxes, one inside port, no translation, no collision, jQuery from cdnjs
loaded in both browsers in fresh default profiles. Firefox's profile had no
`network.trr.*` or `doh-rollout` prefs, i.e. TRR off, so the DoH-fallback
question from the earlier run is still open.

## E. Enforcement parity: an undeclared port is not published and refuses in 0 ms

Session `quiet`, `--network own-ip`, no `--ingress`, `web.py` listening on
`0.0.0.0:3000` inside (lease `100.64.0.7`):

| Check | Result |
|---|---|
| `min session policy quiet` | `{"egress":null,"ingress":null}` |
| forwarder table | no entry for the box |
| `ss -ltn` for `127.0.0.4:3000` | nothing |
| `getent hosts quiet.min.internal` | `127.0.0.4` (the name resolves; resolution is not reachability) |
| `curl http://quiet.min.internal:3000/` | `connect to 127.0.0.4 port 3000 … failed: Connection refused`, curl rc=7, **0 ms** |

The refusal shape is a TCP RST from the host kernel, since nothing listens on
that address:port. Same shape as a stopped box, which is the point of the
parity rule: an undeclared port and an absent box look identical from the
browser.

## F. Failure modes

| Event | Measured |
|---|---|
| answerer killed, `getaddrinfo("web.min.internal")` | `EAI_NONAME` after **4.9 ms**; `getent` rc=2 in 0.00 s (three runs) |
| answerer killed, `dig @127.0.0.53` | `SERVFAIL`, query time 0 ms |
| answerer killed, `curl` | rc=6 (could not resolve), 0.00 s, no hang |
| answerer killed, `example.com` | 200 in 54 ms, unaffected |
| answerer restarted + cache flush | resolves on the next lookup |
| name removed from the map, SIGHUP | NXDOMAIN on the next lookup |
| `min session destroy d4 --force` (daemon-owned forward `127.0.0.1:3001 → 100.64.0.11:3000`) | host listener gone **1.0 s** after the command was issued; `deregistered PTask hostname d4.local.min.internal` 6 s after; RPC returned after 13.8 s |
| `min session destroy api --force` (forward hand-moved to `127.0.0.3:3000`) | daemon logs `removing ingress port mapping … local=127.0.0.1:3000 error=… proxy not found`; **`127.0.0.3:3000` stays listening** and every connect hangs to the 2 s cap against the dead lease; RPC 16.5 s |

## G. The `:7654` proxy answers 502 for every hostname form on the VM lane; reproduced

With `web` (`100.64.0.10`, published on `127.0.0.2:3000`) live:

| `curl -x http://127.0.0.1:7654 …` | Result |
|---|---|
| `http://web.min.internal:3000/` | `502 Bad Gateway`, `Content-Length: 0` |
| `http://web.local.min.internal:3000/` | 502 |
| `http://api.local.min.internal:3000/` | 502 |
| `http://web.local.min.internal/` | 502 |
| `http://example.com/` (control, expected 502 by design) | 502 |

Daemon log lines captured during the requests: **none**. The proxy's 502
paths in `proxy.rs::handle_connection_io` write the status without a
`tracing` event. The only related line is at `FinalizeSession`:

```
INFO minimald::net::dns: registered PTask hostname session_id=… session_name="api"
     hostname=api.local.min.internal ip=127.0.0.1 action="registered"
```

Stopped there per the brief. The one observation worth carrying to the issue:
the registry maps the name to `127.0.0.1`, and on the VM lane the proxy runs
inside the guest, where `127.0.0.1:3000` is the guest's loopback, not the
host's forward. Filed as a separate inbox issue.

# What this changes for S1b-2

Per acceptance criterion in #646:

1. *Discover listening ports, publish identically on the box's host-loopback
   address, gated by ingress; undeclared ports not published.* **Not met, gate
   half proved.** No discovery exists; publishing is the static `--ingress`
   list, exposed at PTask spawn (not `activate`). The gate holds (E): an
   undeclared 3000 is unpublished and refuses in 0 ms.
2. *Per-box `127.0.0.N`; forwarder binds `local` there at the internal port;
   Linux unprivileged.* **Mechanism met live, code not.** C and D prove it end
   to end with two boxes on 3000 and both browsers. `expose_request` binds
   `127.0.0.1`; teardown is keyed by that string, so the address must be
   allocated before the expose (F).
3. *`host_ip` boxes need no publishing.* **Not run** (no `host_ip` session in
   this run).
4. *Linux leg re-run on KVM with `local-minvmd`.* **Met**, this document.

Needs change: criterion 2 should say the address is allocated per **session**
at `activate` and persisted in the session record, because the switch lease is
per spawn and the name must resolve to the same address before, during, and
between spawns. Criterion 1 should say where discovery runs (the guest daemon
can read the PTask netns; the host cannot) and what "the moment the box
listens" means when no client is attached, given B's teardown behaviour.

Proposed size: three slices, three PRs, L overall.

- **S1b-2a, address allocation + bind (M):** a `127.0.0.N` allocator in the
  session record, surfaced in `ls --json` and `policy`; `expose_request` binds
  `local` at that address and the internal port; `OwnIpGuard` keyed by it;
  `activate` refuses a second session claiming the same address:port and
  `ls` shows the address. macOS keeps `127.0.0.1` with first-come until the
  `lo0` alias lands.
- **S1b-2b, name → address (S–M):** the S1b-1 answerer reads the session
  record; register at `FinalizeSession`, deregister at destroy (the hooks
  that already log `registered/deregistered PTask hostname`), independent of
  PTask spawn.
- **S1b-2c, listener discovery + auto-publish (L):** guest-daemon poll of the
  PTask netns listeners, expose/unexpose against the ingress rules, and the
  lifecycle answer for boxes with no attached client. This is the previously
  unestimated unit; it can ship after 2a/2b, which already deliver
  `http://<name>.min.internal:<port>` for declared ports.

# Residual risks / live trial needed

1. **NetworkManager hosts**: still unmeasured on any KVM host; both Linux runs
   with KVM or with a real daemon were networkd hosts.
2. **Reboot** on a networkd host: service restarts measured, boot not.
3. **PTask teardown on abrupt client loss** (B): decides whether an unattended
   box can keep a port published; needs its own look.
4. **Firefox with DoH on**: still not observed.
5. **macOS**, entirely, for this leg (`lo0` alias per box).

# Action items

- [ ] Post the A–G tables to gominimal/inbox#649 and propose the S1b-2 size.
- [ ] Refine arch#59 §3 wording: "non-link-local" → "routable scope"; 127/8 is
      also inert.
- [ ] Note on arch#59 §6 that the `:7654` interim surface answers 502 for every
      own-ip hostname on `local-minvmd`, so the supersession premise does not
      hold on the LocalVM profile today.
- [ ] File the proxy 502 as its own inbox issue with the capture above.

# Artifacts

- Rig (`dns.py`, `web.py`, `map.json`, `fwd.sh`, `serve.sh`) lived in the
  session scratchpad and was not retained in the repo; ~100 lines of stdlib
  Python plus two shell helpers around `curl --unix-socket`.
- Host changes made and reverted: `min0` (runtime, then the two networkd
  files), the answerer, the transient `min-dns-spike` unit and its copy under
  `/usr/local/lib`, the four sessions, the VM (`just stop`, `just reap` found
  nothing). Chromium and Firefox snaps remain installed.
- Guest console (`providers/local-minvmd0/boot.log`) was the daemon log for
  every VM-lane observation above.
