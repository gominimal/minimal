---
id: 1453
title: "SP1: Does the macOS loopback alias step hold across a reboot?"
status: proved
date: 2026-09-18
budget_hours: 16
actual_hours: 2.5
related:
  - "issue #1453 (this spike, SP1 of the box-networking plan)"
  - "issue #1437 (NET epic)"
  - "issue #1470 (T10: advise the resolver command at session start and probe the reserved range)"
  - "issue #1471 (T11: give each box its own loopback address and register its name)"
  - "docs/specs/18-spec-box-networking/18-spec-box-networking.md (NET-010, NET-122, NET-123, open question HIGH)"
  - "arch specs/networking/deployment-and-egress-gateway.md (design 7.1, 12 item 13)"
  - "docs/spikes/2026-09-10 native DNS spike (inbox#649, ruling arch#59): resolver file and answerer shape reused here"
tags:
  - macos
  - loopback
  - launchd
  - networking
  - net-spec
---

# Question

Does a root LaunchDaemon installed by the advisory command (NET-122) re-apply
the reserved range `127.0.64.0/24` on `lo0` at boot, so that per-box addresses
bind (NET-123's probe passes) and resolve by name in Safari, Chrome and
Firefox?

The assumption under test is the one NET-123 encodes: the `127.0.0.1` interim
is a temporary per-host state that the privileged step supersedes. If the
mechanism cannot work, the interim is permanent on macOS and T10 and T11 narrow
their macOS half to it.

# Hypothesis

Yes. One `ifconfig lo0 alias 127.0.64.N 255.255.255.255` per address, run from
a root-owned plist with `RunAtLoad`, re-applies the whole range within a second
of launchd starting the system domain, and the session-start bind probe passes
on every address from then on.

# Method

The plan's method needs root twice (install, reboot) and a person at three
browsers. This host's `sudo` needs a password the spike cannot supply, so the
run splits into what was measured here and what is left for a person with root.

Measured here, no privilege:

1. Baseline: `ifconfig lo0`; a Python `socket.bind((addr, 0))` probe on
   `127.0.0.1`, `::1` and four addresses in the range, timed. This is the
   interim state and what NET-123's probe sees on a stock Mac.
2. Which boot mechanism is right: `/Library/LaunchDaemons`, the legacy
   `/etc/rc.local` and `/etc/hostconfig` hooks, `man launchd.plist`,
   `man ifconfig`, `networksetup`, plus an unprivileged `ifconfig lo0 alias`
   to record the exact refusal. Prior art from Docker Desktop, OrbStack and
   published loopback-alias LaunchDaemons.
3. Draft the artifacts the advisory command would install (plist, alias
   script, resolver file), lint them, dry-run the script unprivileged, and
   time 254 sequential read-only `ifconfig lo0` invocations as a proxy for
   254 alias calls.
4. Same-port publishing stand-in: two `http.server` instances on port 18080 at
   `127.0.0.1` and `::1`, fetched by name with `curl --resolve`.
5. Resolver state on this host: `/etc/resolver`, `scutil --dns`.

Left for a person with root: install, reboot, the post-reboot verification
script, and the three-browser check. The exact commands are in Findings and
the files in Artifacts.

# Findings

## Measured here

### 1. Baseline: the interim state on a stock macOS 26 host

```
$ sw_vers
ProductName:		macOS
ProductVersion:		26.6.2
BuildVersion:		25G83

$ ifconfig lo0
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
	nd6 options=201<PERFORMNUD,DAD>
```

`lo0` carries exactly one IPv4 address. The bind probe (Artifacts,
`bind-probe.py`) confirms the range is absent and shows what NET-123's probe
costs:

```
$ python3 bind-probe.py
127.0.0.1      OK                                               port=52538      15.9 us
::1            OK                                               port=52539       5.8 us
127.0.64.1     EADDRNOTAVAIL (49) Can't assign requested address                  7.0 us
127.0.64.2     EADDRNOTAVAIL (49) Can't assign requested address                  3.0 us
127.0.64.100   EADDRNOTAVAIL (49) Can't assign requested address                  2.3 us
127.0.64.254   EADDRNOTAVAIL (49) Can't assign requested address                  2.0 us
total 6 probes in 0.11 ms
```

The probe is microseconds per address and never blocks, so probing the whole
range at session start (254 binds, under 2 ms extrapolated) is affordable and
NET-123 can probe every address, not only the answerer's `.1`.

The route table already sends all of `127/8` to `lo0`; what is missing is the
address, not the route. That matters for the failure mode: a connect to an
absent range address does not fail fast, it times out.

```
$ route -n get 127.0.64.1
   route to: 127.0.64.1
destination: 127.0.0.0
       mask: 255.0.0.0
  interface: lo0
      flags: <UP,DONE,CLONING,STATIC>

$ time curl -s -m 3 -o /dev/null -w "%{http_code} %{errormsg}\n" http://127.0.64.1:18080/
000 Connection timed out after 3005 milliseconds
```

So a name that resolves to a range address on a host without the aliases gives
a browser a hang, not a refusal. That is the concrete reason NET-123's interim
must publish at `127.0.0.1` and the answerer must not hand out range addresses
until the probe passes.

### 2. The boot mechanism: only a root LaunchDaemon remains

Adding an alias is a privileged ioctl, and there is no unprivileged route:

```
$ ifconfig lo0 alias 127.0.64.1 255.255.255.255
ifconfig: ioctl (SIOCAIFADDR): permission denied
exit=1

$ networksetup -help 2>&1 | grep -i "lo0\|alias\|loopback"
(no output: networksetup has no loopback or alias verb)
```

The legacy boot hooks are gone on this macOS; `/etc/rc.common` survives as a
library file only:

```
$ ls -la /etc/rc.local /etc/hostconfig /etc/rc.common /etc/rc /etc/launchd.conf
ls: /etc/hostconfig: No such file or directory
ls: /etc/launchd.conf: No such file or directory
ls: /etc/rc: No such file or directory
ls: /etc/rc.local: No such file or directory
-rw-r--r--  1 root  wheel  1560 Aug 12 19:51 /etc/rc.common
```

`launchd.plist(5)` documents `RunAtLoad` as the once-at-load trigger (with a
generic caution about speculative launches that does not apply to a job that
must run at boot by definition), and `LaunchOnlyOnce` for jobs that need a
reboot to re-run:

```
$ man launchd.plist | col -b | grep -n -A4 "^     RunAtLoad"
248:     RunAtLoad <boolean>
249-     This optional key is used to control whether your job is launched once at
250-     the time the job is loaded. The default is false. This key should be
251-     avoided, as speculative job launches have an adverse effect on system-
252-     boot and user-login scenarios.
524:     LaunchOnlyOnce <boolean>
525-     This optional key specifies whether the job can only be run once and only
526-     once.  In other words, if the job cannot be safely respawned without a
527-     full machine reboot, then set this key to be true.
```

`launchctl(1)` names `bootstrap`/`bootout` as the recommended replacements for
`load`/`unload`, so the install sequence uses `launchctl bootstrap system`.

`ifconfig(8)` has no bulk form for aliases. `alias` adds one address; the CIDR
spelling parses (it reaches the ioctl unprivileged) but `alias 127.0.64.0/24`
would add the single address `127.0.64.0` with a /24 mask, not 254 addresses.
One call per address is the only shape:

```
$ man ifconfig | col -b | grep -n -A6 "^     alias"
70:     alias   Establish an additional network address for this interface.  This
71-	     is sometimes useful when changing network numbers, and one wishes
72-	     to accept packets addressed to the old interface.	If the address
73-	     is on the same subnet as the first network address for this
74-	     interface, a non-conflicting netmask must be given.  Usually
75-	     0xffffffff is most appropriate.

$ ifconfig lo0 alias 127.0.64.0/24
ifconfig: ioctl (SIOCAIFADDR): permission denied
```

The netmask note is why the script passes `255.255.255.255`: every range
address is on the same subnet as `127.0.0.1/8`.

Cost of 254 sequential calls, using the read-only form as a proxy (the alias
form is the same process spawn plus one ioctl):

```
$ time (for i in $(seq 1 254); do ifconfig lo0 >/dev/null; done)
0.01s user 0.03s system 10% cpu 0.378 total
$ time (for i in $(seq 1 254); do ifconfig lo0 inet >/dev/null; done)
0.01s user 0.03s system 12% cpu 0.315 total
$ time ifconfig lo0 >/dev/null
0.00s user 0.00s system 57% cpu 0.002 total
```

About 1.3 to 1.5 ms per invocation, 0.3 to 0.4 s for the range on an idle
host. The under-a-second part of the hypothesis is plausible; a cold boot with
a loaded disk is what the root run has to measure.

Prior art, what each does and whether it survives reboot:

- Published loopback-alias LaunchDaemons (a gist at
  `gist.github.com/brandt/c2f9e8277c90a1c284770c7ca7966226`, a 2017 blog post
  at `felipealfaro.wordpress.com`, a Medium post, the Devilbox docs): a plist
  in `/Library/LaunchDaemons` whose `ProgramArguments` is literally
  `/sbin/ifconfig lo0 alias 127.0.0.2` with `RunAtLoad true`, loaded with
  `sudo launchctl load`. One plist per address; the blog post says so
  explicitly. They survive reboot; that is their whole purpose. One 2017
  comment reports the alias not appearing on some versions until an
  `unload -w`/`load -w` cycle, which is the pre-`bootstrap` era `Disabled`
  override state, not a RunAtLoad failure.
- Docker Desktop: ships `com.docker.vmnetd` as a root LaunchDaemon
  (`/Library/LaunchDaemons/com.docker.vmnetd.plist`, `RunAtLoad true`,
  `Program /Library/PrivilegedHelperTools/com.docker.vmnetd`) but does not
  alias `lo0` at boot. Its own docs tell the user to run
  `sudo ifconfig lo0 alias 10.200.10.1/24` by hand, which does not survive
  reboot. That is the "runtime aliases, gone at reboot" state design 7.1
  rejects.
- OrbStack: `dev.orbstack.OrbStack.privhelper.plist` is a Mach-service
  privileged helper (no `RunAtLoad`), started on demand by the app; it does
  not alias `lo0`.
- Lima and colima: no loopback alias mechanism found; port forwards bind
  `127.0.0.1`.

The plists read on this host:

```
$ plutil -p /Library/LaunchDaemons/com.docker.vmnetd.plist
{
  "Label" => "com.docker.vmnetd"
  "Program" => "/Library/PrivilegedHelperTools/com.docker.vmnetd"
  "ProgramArguments" => [ 0 => "/Library/PrivilegedHelperTools/com.docker.vmnetd" ]
  "RunAtLoad" => true
  "Sockets" => { "Listener" => { "SockPathMode" => 438, "SockPathName" => "/var/run/com.docker.vmnetd.sock" } }
  "Version" => "77"
}
$ plutil -p /Library/LaunchDaemons/dev.orbstack.OrbStack.privhelper.plist
{
  "AssociatedBundleIdentifiers" => [ 0 => "dev.kdrag0n.MacVirt" ]
  "Label" => "dev.orbstack.OrbStack.privhelper"
  "MachServices" => { "dev.orbstack.OrbStack.privhelper" => true }
  "Program" => "/Library/PrivilegedHelperTools/dev.orbstack.OrbStack.privhelper"
  "ProgramArguments" => [ 0 => "/Library/PrivilegedHelperTools/dev.orbstack.OrbStack.privhelper" ]
}
```

Two design points follow. First, prior art proves the one-address form of the
mechanism has worked across macOS versions for years; what is unproved is 254
addresses from one job and the timing, which is the root run. Second, the
prior-art plists run `/sbin/ifconfig` with literal arguments, which is design
7.1's "the plist invokes the system tool with literal arguments" option. 254
literal invocations do not fit one `ProgramArguments`, so the draft uses the
other option the design allows: a root-owned script at a non-user-writable
path, installed by the same privileged step, reading no configuration. Docker
Desktop's `/Library/PrivilegedHelperTools` is the conventional home for it.

### 3. Draft artifacts, linted and dry-run

The files are in Artifacts. `plutil -lint` passes on the plist; `sh -n` and
`shellcheck -s sh` pass on both scripts. The alias script dry-runs unprivileged
to prove the idempotency scan and the exit code, with every alias refused:

```
$ sh dev.minimal.loopback.sh 2>/dev/null; echo "exit=$?"
dev.minimal.loopback: 2026-09-18T07:21:17Z since_boot=143020s added=0 present=0/254 on lo0
exit=1
```

The `since_boot` field is the timing instrument for the root run: the unified
log is not readable enough without admin rights to time launchd jobs (the
`log show` predicates in the verify script returned headers only here, and
`ifconfig` does not log), so the daemon stamps its own seconds-since-boot from
`kern.boottime` into `/var/log/dev.minimal.loopback.log`.

### 4. Same-port publishing on two loopback addresses (stand-in)

This is a stand-in. Without root no address in the range binds, so the shape
is shown on the two loopback addresses that do exist, `127.0.0.1` and `::1`.
The resolver is out of the picture (`--resolve` pins the name); what it shows
is that one port at two distinct loopback addresses is two independent
listeners reached by two names.

```
$ (cd a && python3 -m http.server 18080 --bind 127.0.0.1 &) ; (cd b && python3 -m http.server 18080 --bind ::1 &)
$ lsof -nP -iTCP:18080 -sTCP:LISTEN | awk '{print $1, $2, $9}'
COMMAND PID NAME
Python 45300 127.0.0.1:18080
Python 45301 [::1]:18080

$ curl -s --resolve a.min.internal:18080:127.0.0.1 -w " [%{remote_ip} %{time_total}s]\n" http://a.min.internal:18080/
box a
 [127.0.0.1 0.002009s]
$ curl -s --resolve "b.min.internal:18080:[::1]" -w " [%{remote_ip} %{time_total}s]\n" http://b.min.internal:18080/
box b
 [::1 0.001372s]

$ python3 -c "import socket; socket.socket().bind(('127.0.64.2',18080))"
OSError: [Errno 49] Can't assign requested address   (EADDRNOTAVAIL)
```

The third bind is the interim collision NET-010's comment describes: on this
host a second IPv4 box on port 18080 has nowhere to go but `127.0.0.1`, where
the port is taken.

### 5. Resolver state on this host

The earlier spike's resolver file has been removed; only the directory it
created remains, and no `min.internal` scoped resolver is registered:

```
$ ls -la /etc/resolver
drwxr-xr-x@  2 root  wheel    64 Sep 10 18:57 .
$ scutil --dns | grep -n -A6 "min.internal"
(no output)
$ launchctl print system/dev.minimal.loopback
Could not find service "dev.minimal.loopback" in domain for system
```

No answerer is expected on `15353` in that state, and the earlier spike
already proved the file works on this OS for all three browsers, with the
60 s per-lookup hang when the answerer is down. The resolver file in Artifacts
reuses that shape (`nameserver 127.0.0.1`, `port 15353`, the arch working
value). It is written by the same privileged step so that both halves of the
advisory command land in one prompt, as design 7.1 requires.

## Root run

### 6. Install and immediate check (done, before reboot)

Run from a terminal on 2026-09-18, one password prompt. `install.sh` as first
committed checked too early: `launchctl print` showed `state = xpcproxy` while
the 254 `ifconfig` calls were still running, the alias count read 0 and the
probe 1. Two seconds later:

```
$ launchctl print system/dev.minimal.loopback
Could not find service "dev.minimal.loopback" in domain for system
$ ifconfig lo0 | grep -c 127.0.64
254
$ cat /var/log/dev.minimal.loopback.log
dev.minimal.loopback: 2026-09-18T07:36:43Z since_boot=143946s added=254 present=254/254 on lo0
$ python3 bind-probe.py $(seq -f "127.0.64.%g" 1 254) | grep -c " OK "
254
$ scutil --dns | grep -A4 min.internal
  domain   : min.internal
  nameserver[0] : 127.0.0.1
  port     : 15353
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
```

The "applied immediately" half of design 7.1 holds: one `launchctl bootstrap`
puts the whole range on `lo0`, every address binds, and the scoped resolver is
registered with its port. The `launchctl print` miss is the plist's
`LaunchOnlyOnce`: launchd drops the job after it exits, so the daemon's log
line, not launchd state, is the evidence that it ran; the scripts now say so.
`since_boot` on this run is the host's uptime and means nothing until the
reboot.

### 7. Reboot and after (done)

`sudo reboot` at 00:43 local, login, then `verify-after-reboot.sh` from the
repository root:

```
## boot time
{ sec = 1789717410, usec = 313873 } Fri Sep 18 00:43:30 2026
## launchd state (LaunchOnlyOnce: 'Could not find service' means it ran and exited)
Could not find service "dev.minimal.loopback" in domain for system
## alias count
254
## daemon log
dev.minimal.loopback: 2026-09-18T07:36:43Z since_boot=143946s added=254 present=254/254 on lo0
dev.minimal.loopback: 2026-09-18T07:43:54Z since_boot=24s added=254 present=254/254 on lo0
## bind probe, every address in the range (expect 254 OK, plus 127.0.0.1 and ::1)
127.0.64.254   OK                                               port=51106       5.7 us
total 256 probes in 2.53 ms
254
## alias timing relative to boot (unified log, first 3 minutes after boot)
2026-09-18 00:43:54.251 Df launchd[1:12bd] [system:] service inactive: dev.minimal.loopback
2026-09-18 00:43:54.251 Df launchd[1:12bd] [system:] removing service: dev.minimal.loopback
## resolver
  domain   : min.internal
  nameserver[0] : 127.0.0.1
  port     : 15353
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
```

The job ran and finished 24 s after the kernel started, before the login
window, and all 254 addresses were on `lo0` and bindable at first login. The
hypothesis' "within a second of boot" was about the script's own run time
(under 0.4 s, section 2); the 24 s is launchd reaching the system daemons on a
cold boot and is earlier than any session could start. `kern.boottime` and
`since_boot` are measured from the same clock, so the daemon log is the
timing record; the unified log only shows launchd dropping the launch-once
job.

### 8. Two boxes on one port, three browsers (done)

Stand-in answerer (`answerer.py`, beside this document) on `127.0.0.1:15353`
answering `a.min.internal` with `127.0.64.10` and `b.min.internal` with
`127.0.64.11`; two `python3 -m http.server 18080` bound to those addresses,
serving `box-a` and `box-b`.

```
$ dscacheutil -q host -a name a.min.internal
name: a.min.internal
ip_address: 127.0.64.10
$ dscacheutil -q host -a name b.min.internal
name: b.min.internal
ip_address: 127.0.64.11
$ curl -s -w " [%{remote_ip} %{time_total}s]\n" http://a.min.internal:18080/
box-a
 [127.0.64.10 0.605859s]
$ curl -s -w " [%{remote_ip} %{time_total}s]\n" http://b.min.internal:18080/
box-b
 [127.0.64.11 0.650319s]
$ cat answerer.log
63533 a.min.internal. type=28 -> rcode=0
63768 _dns.resolver.arpa. type=64 -> rcode=3
51980 a.min.internal. type=1 -> 127.0.64.10
56672 b.min.internal. type=28 -> rcode=0
65206 b.min.internal. type=1 -> 127.0.64.11
```

Same port, two names, two addresses, the right body from each. The 0.6 s on
the first `curl` is resolution, not the fetch: the scoped resolver asks AAAA
first, then a DDR probe (`_dns.resolver.arpa` SVCB), then A; a repeat by name
is served from the system cache with no answerer traffic. The real answerer
should answer AAAA with an empty NOERROR as the stand-in does, or the resolver
waits for it.

| browser | a.min.internal | b.min.internal | load |
|---|---|---|---|
| Chrome (default profile, via the browser extension) | `box-a` from 127.0.64.10 | `box-b` from 127.0.64.11 | instant; server log shows `GET /` and the favicon request |
| Safari (default profile) | `box-a` from 127.0.64.10 | `box-b` from 127.0.64.11 | instant once the answerer sent SOA-bearing negatives (section 9); the first attempt, before that fix, never painted |
| Firefox (fresh install, DoH at default) | `box-a` from 127.0.64.10 | `box-b` from 127.0.64.11 | instant; no DoH change needed |

Box logs for the Safari and Firefox rounds, one `GET /` per page load, each from
its own address:

```
127.0.64.10 - - [18/Sep/2026 01:08:52] "GET / HTTP/1.1" 200 -
127.0.64.10 - - [18/Sep/2026 01:09:41] "GET / HTTP/1.1" 200 -
127.0.64.11 - - [18/Sep/2026 01:09:00] "GET / HTTP/1.1" 200 -
127.0.64.11 - - [18/Sep/2026 01:09:48] "GET / HTTP/1.1" 200 -
```

Query types the resolver sent the answerer across the browser rounds: A, AAAA
and HTTPS (type 65), plus one DDR probe (`_dns.resolver.arpa` SVCB) earlier.

### 9. The stand-in answerer took the whole resolver down

Safari's first load of `a.min.internal` resolved through the answerer (an A
and an AAAA query logged at 00:52) and the box served `GET /` with 200, but
Safari never painted the page. Minutes later two Chrome tabs opened by hand
spun with no query reaching the answerer and no request reaching either box,
`curl` by name timed out at 5 s, and a download from `mozilla.org` failed:
every lookup on the host, scoped or not, had stopped. The answerer process
was alive and idle in `recvfrom`. Killing the answerer and the two servers and
running `dscacheutil -flushcache` restored general resolution at once
(`mozilla.org` in 0.7 s).

A second answerer with raw packet logging and a watchdog (kill it when a
general lookup stalls) answered every query it received in 0 ms, and `dig`
against it directly shows well-formed replies (`qr aa rd ra`, one A record,
empty NOERROR for AAAA, NXDOMAIN for an unknown name), yet the system took
6.6 s and 32.9 s to return `a.min.internal`, and 31 s to return nothing for
`b.min.internal` although the answerer had sent its A record instantly. The
resolver also asked for HTTPS (type 65) records first. The unified log for
`mDNSResponder` is empty to an unprivileged reader, so the resolver's own
account is not available here; the state was cleared with a root
`killall -HUP mDNSResponder`.

After the root `killall -HUP mDNSResponder` the stall came straight back: each
scoped lookup hung 60 s and the watchdog killed the stand-ins when general
lookups stalled too. The cause was the answerer's negative replies. They
carried no SOA record in the authority section, so the resolver had nothing
to cache for "no AAAA record" and kept the query open, and while that query
was open every other lookup on the host waited behind it. With an SOA in the
authority section of every NODATA and NXDOMAIN reply (RFC 2308) the first
lookups took 5.1 s and 3.7 s, cached ones under 1.2 s, fetches by name under
a second, general resolution was untouched, and all three browsers painted
both boxes.

What this says for the real answerer: the earlier native-DNS spike recorded a
60 s hang when the answerer is down; this run shows that a reachable answerer
whose negatives are not cacheable stalls every lookup on the host, scoped or
not. The answerer must send an SOA with every negative reply, answer AAAA
and HTTPS with an empty NOERROR rather than NXDOMAIN, and be tested against
`mDNSResponder` with the query types it actually sends (A, AAAA, HTTPS, and
the DDR probe `_dns.resolver.arpa` SVCB). The advisory that installs the
resolver file must not run before the answerer is listening.

## The root procedure, as run

Run from the repository root (Artifacts lists every file). The
password prompt happens once at the first `sudo`; nothing afterwards prompts.

Install and immediate check (before reboot):

```
cd docs/spikes/2026-09-22-macos-loopback-alias
sudo install -o root -g wheel -m 755 -d /Library/PrivilegedHelperTools /etc/resolver
sudo install -o root -g wheel -m 755 dev.minimal.loopback.sh /Library/PrivilegedHelperTools/dev.minimal.loopback.sh
sudo install -o root -g wheel -m 644 dev.minimal.loopback.plist /Library/LaunchDaemons/dev.minimal.loopback.plist
sudo install -o root -g wheel -m 644 min.internal /etc/resolver/min.internal
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.minimal.loopback.plist
sleep 2   # the job is LaunchOnlyOnce; once it exits launchd drops it and `launchctl print` says "Could not find service"
ifconfig lo0 | grep -c 127.0.64          # expect 254
cat /var/log/dev.minimal.loopback.log    # expect present=254/254; this run's since_boot is meaningless
python3 bind-probe.py $(seq -f "127.0.64.%g" 1 254) | grep -c " OK "   # expect 254
```

Record: the alias count, the daemon log line, and the probe count. This is the
"applied immediately" half of design 7.1.

Reboot, then verify (no root):

```
sudo reboot
# after login:
sh docs/spikes/2026-09-22-macos-loopback-alias/verify-after-reboot.sh
```

Record from its output: `kern.boottime`; `launchctl print` (expect "Could not
find service", the launch-once job has run and been dropped); `ifconfig lo0 | grep -c 127.0.64` (expect 254); the daemon
log's `since_boot=Ns` (the hypothesis says N is small, seconds not minutes;
record the number); the probe count (expect 254 OK); and whether `scutil --dns`
lists a `min.internal` resolver with port 15353. The files live beside
this document and are reproduced under Artifacts.

Two boxes on one port, then three browsers. Start the answerer from the earlier
spike's rig (`spike/dns.py`, answering `a.min.internal` with `127.0.64.10` and
`b.min.internal` with `127.0.64.11` on port 15353) or any equivalent, then:

```
mkdir -p /tmp/sp1/a /tmp/sp1/b; echo box-a > /tmp/sp1/a/index.html; echo box-b > /tmp/sp1/b/index.html
cd /tmp/sp1/a && python3 -m http.server 18080 --bind 127.0.64.10 &
cd /tmp/sp1/b && python3 -m http.server 18080 --bind 127.0.64.11 &
dscacheutil -q host -a name a.min.internal      # expect 127.0.64.10
dscacheutil -q host -a name b.min.internal      # expect 127.0.64.11
curl -s -w " [%{remote_ip} %{time_total}s]\n" http://a.min.internal:18080/
curl -s -w " [%{remote_ip} %{time_total}s]\n" http://b.min.internal:18080/
```

Then load `http://a.min.internal:18080/` and `http://b.min.internal:18080/` in
Safari, Chrome and Firefox, each in a default profile with no proxy or PAC
configured, Firefox with DoH at its default. Record per browser: the page body
(`box a` / `box b`), the time to first paint by eye (instant versus a
multi-second stall, which would indicate the resolver hook was skipped and the
lookup fell through to the 60 s path), and for Firefox whether DoH had to be
turned off. Six loads, six rows.

Uninstall when done:

```
sudo launchctl bootout system/dev.minimal.loopback
sudo rm /Library/LaunchDaemons/dev.minimal.loopback.plist /Library/PrivilegedHelperTools/dev.minimal.loopback.sh /etc/resolver/min.internal
for n in $(seq 1 254); do sudo ifconfig lo0 -alias 127.0.64.$n; done
```

# Conclusion

**Status: proved.** A root LaunchDaemon installed by the advisory command
re-applies the reserved range on `lo0` at boot: after a reboot all 254
addresses were present and bindable 24 s after the kernel started, before the
login window, and two boxes published on the same port at two range addresses
loaded by name in Safari, Chrome and Firefox. The `127.0.0.1` interim is a
temporary per-host state, as the spec assumes, and T10 and T11 keep their
macOS half. The open question closes on this run; design 12 item 13 flips to
measured.

One finding beside the question: a scoped answerer whose negative replies
carry no SOA stalls every DNS lookup on the Mac (section 9). That is a
requirement on the answerer, not on the alias step.

What was established without root:

1. On a stock macOS 26 host `lo0` carries `127.0.0.1` only; every range address
   fails `bind` with `EADDRNOTAVAIL` in microseconds, so NET-123's probe is
   cheap enough to cover the full range, and a connect to an absent range
   address hangs to timeout rather than refusing, which is why the interim
   must keep boxes on `127.0.0.1` until the probe passes.
2. Adding an alias is a root-only ioctl (`SIOCAIFADDR: permission denied`),
   `networksetup` has no loopback verb, and the pre-launchd boot hooks are gone.
   A root LaunchDaemon with `RunAtLoad` is the only boot re-apply route, and it
   is what every published loopback-alias recipe uses; Docker Desktop and
   OrbStack install root LaunchDaemons the same way but neither aliases `lo0`
   at boot.
3. `ifconfig` has no bulk alias form; 254 calls cost about 0.3 to 0.4 s on an
   idle host, consistent with the under-a-second hypothesis.
4. Same-port publishing at distinct loopback addresses works as a plain
   two-listener shape (stand-in on `127.0.0.1` and `::1`).
5. The artifacts (plist, idempotent script with a since-boot stamp, resolver
   file) lint clean and are ready to install.

What the root run decided: the `RunAtLoad` job completed 24 s after the kernel
started and long before a session could start, and the three browsers resolved
range addresses through the scoped resolver and loaded the right box from each.
The interim is a temporary per-host state and the open question closes.

# Action items

1. In the NET spec's HIGH open question, replace "pending the loopback-alias
   measurement" with a pointer to this spike and the root-run steps that remain.
2. In NET-123's comment, add that the probe covers the whole range at under
   2 ms, that a connect to an absent range address times out rather than
   refusing, and that the interim exists to keep the answerer from handing out
   range addresses before the probe passes.
3. In T10 (issue #1470), make the advisory command install three files in one
   privileged step: the plist, the alias script at
   `/Library/PrivilegedHelperTools`, and `/etc/resolver/min.internal`, and
   apply the range immediately with `launchctl bootstrap system`.
4. In T10, make the bind probe iterate every address in `127.0.64.1` to
   `127.0.64.254` and treat any `EADDRNOTAVAIL` as "range absent", since a
   partial alias set would otherwise let the allocator hand out an address
   that hangs.
5. In T11 (issue #1471), keep the macOS half unchanged (per-box addresses from
   the range) unless the root run shows the daemon not running at boot; do not
   narrow it to the interim on the evidence so far.
6. In the design 7.1 mechanism bullet, record that the plist runs a root-owned
   script (not literal `ifconfig` arguments) because 254 addresses do not fit
   one `ProgramArguments`, and that the script's only inputs are literals.
7. Flip design 12 item 13 to measured, pointing at this document.
8. In the answerer task (T9, issue #1460), send an SOA in the authority section
   of every NODATA and NXDOMAIN reply, answer AAAA and HTTPS with an empty
   NOERROR, and add a test that drives `mDNSResponder` through the scoped
   resolver with A, AAAA, HTTPS and the DDR probe and asserts that an
   unrelated name still resolves in under a second meanwhile.
9. In T10, order the advisory's install so the resolver file is written only
   after the answerer is listening, since a scoped resolver with no answerer
   or a bad one takes every lookup on the host with it.
10. In T10, do not ship `LaunchOnlyOnce`. The spike used it and paid for it
    twice: launchd drops the job the moment it exits, so `launchctl print`
    could not confirm the run (section 6), and because the script exits
    nonzero when fewer than 254 aliases are present, launchd will not retry a
    partial apply until the next boot — a single failed `ifconfig` would
    leave the range short for the whole session, which is exactly the state
    NET-123's probe reads as "range absent". The shipped job wants a
    throttled retry on nonzero exit (`KeepAlive` with `SuccessfulExit`
    false), which the script's idempotence already tolerates: a re-run adds
    only the missing aliases.
11. In T10, make the post-install check poll for the 254 aliases with a
    bounded timeout instead of a fixed wait. `launchctl bootstrap` returns
    before the helper finishes, and the first install run read 0 aliases for
    that reason (section 6); the spike's by-hand recipe settled for
    `sleep 2`, but an advisory that reports success or failure to a person
    must wait on the count, not on the clock.

# Artifacts

Seven files live in
`docs/spikes/2026-09-22-macos-loopback-alias/`
on this host. Five are reproduced here in full: the three the privileged step
installs, and the two verification scripts. The other two are not embedded
twice — `install.sh` is the command list already reproduced under "The root
procedure, as run", and `answerer.py` is described below rather than shown,
being a stand-in for T9's answerer and no part of the mechanism under test.

## `dev.minimal.loopback.plist` (install to `/Library/LaunchDaemons/`, root:wheel 0644)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.minimal.loopback</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>/Library/PrivilegedHelperTools/dev.minimal.loopback.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LaunchOnlyOnce</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/dev.minimal.loopback.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/dev.minimal.loopback.log</string>
</dict>
</plist>
```

## `dev.minimal.loopback.sh` (install to `/Library/PrivilegedHelperTools/`, root:wheel 0755)

One correction since the run: the skip guard builds `present` with `printf
"%s "` rather than `print`, so the addresses are space-separated. `awk`'s
`print` emitted one per line, and `case " $present " in *" $addr "*` only
matches an address bounded by spaces, so the guard never fired and a re-run
re-issued all 254 `ifconfig` calls. It is inert for everything measured here —
both recorded runs started with no range alias on `lo0`, so every address took
the alias branch either way, and `added=254 present=254/254` is what the
unguarded loop and the fixed one both produce — but the header's idempotence
claim and action item 10's retry both rest on the guard working, so it is
fixed here rather than left as a trap for whoever installs this.

```sh
#!/bin/sh
# dev.minimal.loopback: re-apply the reserved local range 127.0.64.0/24 on lo0.
# Run by launchd at boot (RunAtLoad) and once at install. Idempotent: an alias
# that is already present is skipped, so a re-run adds nothing and removes
# nothing. The range and the interface are literal on purpose: the daemon reads
# no configuration (arch design 7.1, post-install custody).
set -u
PATH=/sbin:/usr/sbin:/bin:/usr/bin
IFACE=lo0
PREFIX=127.0.64
present=$(ifconfig "$IFACE" inet 2>/dev/null | awk '$1 == "inet" { printf "%s ", $2 }')
added=0
n=1
while [ "$n" -le 254 ]; do
    addr="$PREFIX.$n"
    case " $present " in
        *" $addr "*) ;;
        *)
            if ifconfig "$IFACE" alias "$addr" 255.255.255.255; then
                added=$((added + 1))
            else
                echo "dev.minimal.loopback: alias $addr failed" >&2
            fi
            ;;
    esac
    n=$((n + 1))
done
count=$(ifconfig "$IFACE" inet 2>/dev/null | awk -v p="$PREFIX." 'index($2, p) == 1 { c++ } END { print c + 0 }')
boot=$(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+), usec.*/\1/')
now=$(date +%s)
echo "dev.minimal.loopback: $(date -u +%Y-%m-%dT%H:%M:%SZ) since_boot=$((now - boot))s added=$added present=$count/254 on $IFACE"
[ "$count" -eq 254 ]
```

## `min.internal` (install to `/etc/resolver/`, root:wheel 0644)

```
nameserver 127.0.0.1
port 15353
```

## `bind-probe.py` (no install; the NET-123 probe in script form)

```python
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
```

## `answerer.py` (no install; the stand-in answerer for the browser check)

Beside this document. A UDP DNS server on `127.0.0.1:15353` with a fixed
table, SOA-bearing negatives, raw packet logging. Not the real answerer.

## `verify-after-reboot.sh` (no install; run after the reboot, no root)

```sh
#!/bin/sh
# Run after `sudo reboot` and a fresh login. No root needed.
SP=docs/spikes/2026-09-22-macos-loopback-alias
echo "## boot time";        sysctl -n kern.boottime
echo "## launchd state (LaunchOnlyOnce: 'Could not find service' means it ran and exited)"
launchctl print system/dev.minimal.loopback 2>&1 | grep -E "state|last exit|runs|Could not find"
echo "## alias count";      ifconfig lo0 | grep -c 127.0.64
echo "## daemon log";       cat /var/log/dev.minimal.loopback.log
echo "## bind probe, every address in the range (expect 254 OK, plus 127.0.0.1 and ::1)"
python3 "$SP/bind-probe.py" 127.0.0.1 ::1 $(seq -f "127.0.64.%g" 1 254) | tail -8
python3 "$SP/bind-probe.py" $(seq -f "127.0.64.%g" 1 254) | grep -c " OK "
echo "## alias timing relative to boot (unified log, first 3 minutes after boot)"
BOOT=$(date -r "$(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+), usec.*/\1/')" "+%Y-%m-%d %H:%M:%S")
END=$(date -r "$(( $(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+), usec.*/\1/') + 180 ))" "+%Y-%m-%d %H:%M:%S")
/usr/bin/log show --start "$BOOT" --end "$END" --style compact \
  --predicate '(process == "launchd" && eventMessage CONTAINS "dev.minimal.loopback") || process == "ifconfig"' | head -20
echo "## resolver"
scutil --dns | grep -A6 "min.internal"
```

The `log show` block is best effort: unprivileged it returned only headers on
this host, which is why the daemon's own `since_boot` line is the timing of
record.

## Code touched by the eventual change, as it stands today

- `crates/minimald/src/net/policy.rs:expose_request` hard-codes the published
  forward's host side as `127.0.0.1:<external_port>`; T11 replaces that literal
  with the box's allocated address.
- `crates/minimald/src/net/dns.rs` (`LOOPBACK` const, `register_host_net`,
  `register_own_ip`) registers every hostname to `127.0.0.1`; T11 registers
  the allocated address instead.
- `crates/minimald/src/net/proxy.rs:bind_listener` is the only bind-and-report
  helper in the net module today; it binds the proxy's own listener and is not
  a range probe. No probe of `127.0.64.0/24` exists yet; T10 adds it.
