---
id: 1454
title: "Can a cgroup per host-address box carry its egress identity on a co-resident Linux host?"
status: proved
date: 2026-09-18
budget_hours: 16
actual_hours: 1.5
related:
  - "issue #1454 (this spike, SP2 of the box-networking plan)"
  - "issue #1437 (epic: box networking plan)"
  - "issue #1482 (T38: classify the host-address cohort apart from node-plane traffic and enforce its deny-all)"
  - "docs/specs/18-spec-box-networking/18-spec-box-networking.md (NET-078, NET-079, NET-080; open question on the cgroup layout)"
  - "gominimal/arch specs/networking/deployment-and-egress-gateway.md (design §4.1 cgroup classifier, §7.4 SharedLinux)"
tags:
  - cgroup
  - nftables
  - host-address
  - networking
  - sp2
---

# Question

Does matching each host-address box's cgroup in the host packet filter give
the box its own egress verdict while the daemon's own package fetch stays
node-plane traffic?

The spec's open question has two halves: (a) what cgroup layout gives each
host-address box its own identity inside the box host (NET-079), and (b) are
host-address boxes on a co-resident Linux host in scope of NET-078 to NET-080
at all. The design ([§4.1][design]) names "one netfilter cgroup-match rule"
over "the boxes cgroup subtree" and says nothing about the tree or about who
installs the rule.

# Hypothesis

Yes. A per-box cgroup under the daemon's slice, matched by the packet filter,
classifies both the box and the daemon without a network namespace. The
assumption under test: host-address boxes on a co-resident Linux host are in
scope; if the mechanism cannot do it, T38 narrows to the VM-backed host and the
classifier is the guest daemon's.

# Method

1. Read the spec (NET-078 to NET-080, the open question) and design §4.1 and
   §7.4.
2. Read what the tree does today: `crates/sandbox2` for cgroup placement,
   `crates/minimald` for how a host-address box is launched, the pinned
   `hakoniwa` checkout for its cgroup and namespace ordering,
   `crates/minimal/src/autospawn.rs` for the daemon's own placement.
3. On a Linux host (lima VM, Ubuntu 25.10, kernel 6.17, cgroup v2, nftables
   1.1.5) build a slice-like tree `/sys/fs/cgroup/minimald.slice/{box-a,box-b,daemon}`,
   load an `inet` output chain matching `socket cgroupv2`, and fetch from each
   leaf: HTTPS by name, HTTP to a raw address, and DNS over UDP straight to
   `1.1.1.1`. Read the counters.
4. Probe the failure modes that matter for the assumption: fork/exec
   inheritance; an established connection whose owner moves cgroup after
   connect; a user namespace and a cgroup namespace inside the leaf (the
   sandbox2 shape); whether an unprivileged box process can leave its leaf,
   with the tree root-owned and with it delegated to the daemon's uid; `reject`
   versus `drop`; the no-internal-process rule for the daemon's own placement;
   a three-level tree with cohort and per-box matches; and what an
   unprivileged daemon can and cannot do (create cgroups, load rules).
5. Delete the tables and the tree.

# Findings

## Environment

```
$ uname -r
6.17.0-41-generic
$ nft --version
nftables v1.1.5 (Commodore Bullmoose #6)
$ iptables --version
iptables v1.8.11 (nf_tables)
$ curl --version | head -1
curl 8.14.1 (aarch64-unknown-linux-gnu) libcurl/8.14.1 OpenSSL/3.5.3 ...
$ cat /sys/fs/cgroup/cgroup.controllers
cpuset cpu io memory hugetlb pids rdma misc dmem
$ cat /sys/fs/cgroup/cgroup.subtree_control
cpuset cpu io memory pids
$ cat /proc/self/cgroup
0::/user.slice/user-502.slice/session-4.scope
$ curl -sS -m 8 -o /dev/null -w 'egress-https=%{http_code}\n' https://example.com
egress-https=200
```

The `socket cgroupv2` match worked first time on this kernel and nft; the
cgroup v1 `meta cgroup` form was not needed and was not tried.

## What the tree does today

- **No box or session sandbox is in a cgroup of its own.** `sandbox2` only
  asks hakoniwa for cgroup resources when `Config::cpu_weight` is set and
  the host booted with
  systemd (`crates/sandbox2/src/lib.rs:701`, `booted_with_systemd` at
  `lib.rs:1121`); hakoniwa then creates a **systemd transient scope** named
  `hakoniwa.slice:hakoniwa:<pid>` through libcgroups
  (`hakoniwa/src/cgroups/manager.rs:15`), keyed by pid, not by box. Nothing in
  `crates/minimald`, `crates/sessions` or `crates/mip` calls
  `with_cpu_weight`, so a box or session sandbox stays in the daemon's own
  cgroup today. Builds are the exception: `crates/orchestrator` sets
  `cpu_weight` on every local build
  (`crates/orchestrator/src/local_backend.rs:221`, applied at
  `crates/op/src/specs.rs:329`), so on a systemd host each build sandbox does
  get a scope of its own — a pid-keyed one, which is why Conclusion (a) says
  that path is not this tree.
- **Every sandbox unshares a cgroup namespace** unconditionally
  (`crates/sandbox2/src/lib.rs:506`, `.unshare(hakoniwa::Namespace::Cgroup)`
  with `Runctl::IgnoreCgroupSetupFailed`).
- **Ordering hazard in hakoniwa.** The child unshares every requested
  namespace in one `unshare()` call, cgroup namespace included
  (`hakoniwa/src/runc.rs:124` calling `runc/unshare.rs:30`), and only then
  asks the parent to do the cgroup placement (`runc.rs:127`,
  `runc/notify.rs:20`, served at `command.rs:466`). So under hakoniwa's own
  hook the child's cgroup-namespace root is the cgroup it was in *before* the
  move, that is the daemon's, and a cgroup2 mount inside the sandbox would
  root there and list sibling leaves. Finding D below shows why that matters.
- **A host-address box is the default network mode.** `NetworkMode::HostNet`
  (`crates/sessions/src/lib.rs:32`) maps to `sandbox2::HostNet`
  (`crates/minimald/src/net/provider.rs:30`), whose plan is `NetPlan::host()`
  with the host resolver (`crates/sandbox2/src/network.rs:266`): no network
  namespace, no wiring. A HostNet box still cannot carry an `egress` section:
  `PTask::validate_policy` returns `PolicyError::EgressRequiresOwnIp`
  (`crates/sessions/src/lib.rs:486`, asserted over the session RPC at
  `crates/minimald/src/rpc.rs:2959`), the rule NET-120 supersedes.
- **The native daemon is unprivileged.** On Linux `min` runs
  `minimald run --detach --instance-num 0` as the invoking user
  (`crates/minimal/src/autospawn.rs:400`); the daemon daemonizes itself with
  `setsid`. It therefore lives wherever the user's session put it (here
  `user.slice/user-502.slice/session-4.scope`), owns no cgroup, and holds no
  `CAP_NET_ADMIN`. The one root-installed piece today is the AppArmor profile
  (`scripts/install-apparmor-profile.sh`).

## Phase 1: the tree, the ruleset, the verdicts

Harness: every fetch ran as `sudo sh -c 'echo $$ > <leaf>/cgroup.procs; exec
setpriv --reuid=502 --regid=1000 --init-groups <cmd>'`, so the socket is
created by an unprivileged process already inside its leaf.

```
$ sudo mkdir -p /sys/fs/cgroup/minimald.slice/{box-a,box-b,daemon}
$ cat /sys/fs/cgroup/minimald.slice/cgroup.subtree_control
                                   # empty: socket matching needs no controller
$ sudo nft -f - <<'NFT'
table inet spike {
  chain out {
    type filter hook output priority filter; policy accept;
    socket cgroupv2 level 2 "minimald.slice/box-a" counter drop comment "box-a deny-all"
    socket cgroupv2 level 2 "minimald.slice/box-b" counter accept comment "box-b allow"
    socket cgroupv2 level 2 "minimald.slice/daemon" counter accept comment "daemon node-plane"
  }
}
NFT
```

Fetches, with the process's own view of its cgroup first:

```
-- box-a: 0::/minimald.slice/box-a   uid 502
   https://example.com      curl: (6) Could not resolve host: example.com   rc=6
   http://1.1.1.1/          curl: (28) Connection timed out after 5002 ms   rc=28
   DNS/UDP to 1.1.1.1:53    sendto: PermissionError: [Errno 1] Operation not permitted
-- box-b: 0::/minimald.slice/box-b   uid 502
   https://example.com      http_code=200
   http://1.1.1.1/          http_code=301
   DNS/UDP to 1.1.1.1:53    dns answer bytes=61 ancount=2
-- daemon: 0::/minimald.slice/daemon uid 502
   https://example.com      http_code=200
   http://1.1.1.1/          http_code=301
   DNS/UDP to 1.1.1.1:53    dns answer bytes=61 ancount=2
```

Counters after phase 1:

```
table inet spike {
	chain out {
		type filter hook output priority filter; policy accept;
		socket cgroupv2 level 2 "minimald.slice/box-a" counter packets 10 bytes 665 drop comment "box-a deny-all"
		socket cgroupv2 level 2 "minimald.slice/box-b" counter packets 21 bytes 3093 accept comment "box-b allow"
		socket cgroupv2 level 2 "minimald.slice/daemon" counter packets 20 bytes 3041 accept comment "daemon node-plane"
	}
}
```

Reading: box-a's 10 dropped packets are its DNS queries to the loopback stub
resolver (`127.0.0.53`; loopback output traverses the output hook, hence
"Could not resolve host" rather than a connect failure), its SYN retries to
`1.1.1.1:80`, and the one UDP datagram that `sendto` refused with `EPERM`.
box-b and daemon carry the same fetch set and land within a few packets of
each other. Nothing outside the tree touched any rule.

## Phase 2: failure modes

**A. fork/exec inheritance.** A subshell and an exec'd `curl` in box-a report
`0::/minimald.slice/box-a` and the fetch times out. Children inherit the leaf.

**B. an established socket keeps the cgroup it was created in.**

```
connected in 0::/minimald.slice/box-b
moved to    0::/minimald.slice/box-a
old socket after move: b'HTTP/1.1 301 Moved Permanently'
NEW socket after move: TimeoutError('timed out')
```

The match reads the socket's cgroup pointer, set at socket creation, not the
process's current cgroup. Measured consequence: **moving a process between
leaves does not change the verdict of its open flows**, so a policy encoded
purely by placement cannot reach a flow that is already up.

The other half — that rewriting the rule for the leaf *does* reach the open
flow, because nftables re-evaluates every packet against the current ruleset
— **was not measured here**. Test E rewrote the ruleset but only fetched
afterwards, so it exercised new connections, not established ones. What a
rewrite does to a live flow is also not one outcome: a `drop` blackholes it
until the peer's retransmit timeout rather than tearing it down, and a
`reject` is refused per packet, so a declaration change may need the box's
sockets killed as well. Action item 6 assumes the rewrite reaches the flow
and requires termination anyway; T38 should measure both before relying on
either (rewrite the leaf's rule under a live transfer, record whether it is
dropped or rejected and whether the socket survives).

**C. user namespace and cgroup namespace inside the leaf.** The host blocks
unprivileged user namespaces with `kernel.apparmor_restrict_unprivileged_userns=1`
(the same policy `scripts/install.sh` remediates for minimald); it was set to
`0` for this test and restored to `1` afterwards.

```
-- box-b, unshare -Ur:   cgroup=0::/minimald.slice/box-b uid=0   http_code=301
-- box-a, unshare -Ur:   cgroup=0::/minimald.slice/box-a uid=0   curl: (7) ... rc=7
-- box-a, unshare -UrC:  cgroup=0::/ uid=0                       curl: (7) ... rc=7
```

A user namespace changes nothing; a cgroup namespace hides the path from the
process (`0::/`) and changes nothing for the filter, which matches the kernel
path. (The `rc=7` immediate failures are because phase 2's `reject` rule from
test E was already in place for box-a; see E.)

**D. can a box process leave its leaf?**

```
-- D1 root-owned tree, uid 502 in box-a writes box-b/cgroup.procs:
   cannot create /sys/fs/cgroup/minimald.slice/box-b/cgroup.procs: Permission denied
   0::/minimald.slice/box-a
-- D2 tree chowned to uid 502 (a non-root daemon owning its delegated subtree), no cgroupns:
   rc=0
   0::/minimald.slice/box-b
   http_code=301                      <- escaped the deny-all leaf
-- D3 same delegated tree, unshare -UrmC (userns + mountns + cgroupns, sandbox2's shape):
   cgroup2 mounted inside the cgroupns; its root lists: cgroup.controllers ... cgroup.procs ... memory.pressure
   sibling via the host mount: blocked -> 0::/
   sibling via the new mount: ls: cannot access '/mnt/../box-b': No such file or directory
   moved into own child; view inside: 0::/child
   curl: (7) Failed to connect ... rc=7   <- still refused
   outside view of the child: /sys/fs/cgroup/minimald.slice/box-a/child
```

With the tree owned by the same uid the boxes run as (which is what a
delegated subtree of an unprivileged daemon looks like: sandbox2 maps the
sandbox user to the daemon's uid), a box **without** a cgroup namespace walks
into its sibling's leaf and takes its verdict. With a cgroup namespace whose
root is the box's own leaf, the sibling is unreachable through both the host
mount and a fresh cgroup2 mount, and the only move available is into a child
of its own leaf, which a `level N` prefix match still covers. The cgroup
namespace is therefore load-bearing, and its root must be the leaf, which is
exactly what hakoniwa's ordering does not give (see above).

**E. `reject` instead of `drop`.**

```
$ sudo nft insert rule inet spike out socket cgroupv2 level 2 "minimald.slice/box-a" counter reject with icmpx admin-prohibited
-- box-a: curl: (7) Failed to connect to 1.1.1.1 port 80 after 0 ms: Could not connect to server
   0.00user 0.00system 0:00.00elapsed
```

`drop` costs the box a 5 s connect timeout per attempt; `reject with icmpx
admin-prohibited` refuses in 0 ms. NET-079 says "refuse".

## Phase 3: layout constraints

**F. the no-internal-process rule, step by step (bash, explicit rc; the slice
starts empty).**

```
   state: slice.subtree_control=[] slice.type=domain daemon.type=domain slice.procs=[] daemon.procs=[]
ok   : echo <pid> > cgroup.procs                 # a process in the slice root
ok   : echo +cpu > cgroup.subtree_control        # accepted, but:
   state: slice.subtree_control=[cpu] slice.type=domain threaded daemon.type=domain invalid ...
ok   : echo +pids > cgroup.subtree_control
FAIL : echo <pid> > daemon/cgroup.procs          # write error: Operation not supported
ok   : echo -cpu -pids > cgroup.subtree_control
   state: slice.subtree_control=[] slice.type=domain daemon.type=domain ...
ok   : echo <pid> > daemon/cgroup.procs          # works again once the root is a plain domain
```

On 6.17 enabling a controller on a non-root cgroup that still holds a process
is **not refused**: the cgroup silently becomes `domain threaded` and every
child becomes `domain invalid`, and no child can hold a process until the
controllers are disabled again. If the daemon sits in the slice root and
anything ever enables `cpu` (the existing `cpu_weight` path) or `pids` there,
every box leaf becomes unusable. With no controller enabled, a process in the
root and processes in the leaves coexist and the socket match works either
way. The daemon must be a **sibling leaf**, placed before any controller is
enabled.

**G. a three-level tree with cohort and per-box matches.**

```
$ sudo mkdir -p /sys/fs/cgroup/minimald.slice/boxes/{b1,b2}
$ sudo nft -f - <<'NFT'
table inet spike3 {
  chain out {
    type filter hook output priority filter + 1; policy accept;
    socket cgroupv2 level 3 "minimald.slice/boxes/b1" counter drop comment "b1 deny-all"
    socket cgroupv2 level 2 "minimald.slice/boxes" counter accept comment "cohort (any box) accept"
    socket cgroupv2 level 1 "minimald.slice" counter accept comment "everything under the slice incl. daemon"
  }
}
NFT
b1 http_code=000 (timed out)   b2 http_code=301   daemon http_code=301

		socket cgroupv2 level 3 "minimald.slice/boxes/b1" counter packets 3 bytes 180 drop
		socket cgroupv2 level 2 "minimald.slice/boxes" counter packets 5 bytes 339 accept
		socket cgroupv2 level 1 "minimald.slice" counter packets 5 bytes 339 accept
```

`level N` is a prefix match on the first N path components, so one rule names
a box, one names the cohort, one names everything under the daemon's root;
the more specific rule must come first. The level is the depth of the
absolute kernel path, so the daemon renders its own root path into the rules.

**H. what an unprivileged process can do.**

```
$ mkdir /sys/fs/cgroup/unpriv.slice                                        -> Permission denied
$ ls -ld /sys/fs/cgroup/user.slice/user-502.slice/user@502.service
drwxr-xr-x+ 4 <uid> <gid> 0 ... user@502.service                            (delegated by the user manager)
$ mkdir /sys/fs/cgroup/user.slice/user-502.slice/user@502.service/minimald.slice   -> rc=0
$ nft add table inet unpriv
Error: Could not process rule: Operation not permitted
```

An unprivileged daemon on a systemd host can build its tree under the
`user@<uid>.service` subtree the user manager delegates to it, and can move
its own children between leaves there. It **cannot** install or change an
nftables rule: that needs `CAP_NET_ADMIN`, once.

## Cleanup

```
$ sudo nft delete table inet spike; sudo nft delete table inet spike3
$ sudo rmdir /sys/fs/cgroup/minimald.slice/{boxes/b1,boxes/b2,boxes,box-a,box-b,daemon} /sys/fs/cgroup/minimald.slice
$ sudo nft list tables            -> table ip nat        (lima's own)
$ ls /sys/fs/cgroup | grep -c minimald   -> 0
$ sysctl -n kernel.apparmor_restrict_unprivileged_userns   -> 1
```

# Conclusion

**Status: proved.** A per-box cgroup matched by `socket cgroupv2` in the
host's output chain gives each host-address box its own egress verdict while a
sibling leaf carries the daemon's own fetch as node-plane traffic, with no
network namespace involved, and the counters attribute every packet to the
leaf whose process opened the socket. The hypothesis holds with three
conditions the experiment surfaced: the daemon is a sibling leaf and not the
root of its tree; each box is placed in its leaf before it unshares its cgroup
namespace; and the rules are installed by a privileged step the unprivileged
native daemon does not have.

**(a) The layout.** One tree per daemon, rooted at a cgroup the daemon owns:
natively `user.slice/user-<uid>.slice/user@<uid>.service/minimald.slice/`, the
path finding H created under the subtree the user manager delegates; in the
VM the guest daemon is pid 1 and roots at `/sys/fs/cgroup/minimald.slice/`,
the name phase 1 used. The `.slice` suffix is the experiment's name, not a requirement —
nothing here depends on it — but `L`, the depth `<root>` renders into every
`socket cgroupv2` match, does depend on the final path, so T38 fixes the name
once and derives `L` from it. A host with no user manager has no delegated
subtree to build under, so its root has to be created and chowned by
something privileged. **That path is unverified here**: D2 ran in a tree
`sudo` chowned by hand and says only that the shape behaves (and that the
box escapes its leaf without a cgroup namespace); nothing in this run
establishes who creates that root, who delegates it, or that it survives a
reboot. T38 must settle it, or scope the native classifier to hosts with a
user manager.

```
<root>/                 the daemon's tree; no controller is ever enabled here while it has a process
  daemon/               the daemon and every helper it spawns for itself; a leaf, entered at startup
  boxes/                the host-address cohort; the daemon never places itself under here
    <box-id>/           one leaf per host-address box, created before spawn, removed after reap;
                        the box process enters it before its cgroup-namespace unshare, so the
                        namespace root is this leaf and siblings are unreachable
```

Rules, with `L` the depth of `<root>`: `socket cgroupv2 level L+2
"<root>/boxes/<box-id>"` per box for its own verdict (NET-079, `reject with
icmpx admin-prohibited` for an immediate refusal); `level L+1 "<root>/boxes"`
as the cohort identity (NET-078); `level L+1 "<root>/daemon"` as the
node-plane identity (NET-078, NET-080). Per-box rules go first, then cohort,
then daemon. A change of a box's declaration is a rule rewrite for its leaf,
not a move of its processes: moving them is measured not to touch their open
flows (finding B), while what the rewrite does to an open flow is untested
and T38 must measure it. `sandbox2`'s own cgroup path (`cpu_weight` via a
systemd scope keyed by pid) is not this tree and should not be reused for it.

**(b) Scope.** Host-address boxes on a co-resident Linux host **are in scope**
for NET-078 to NET-080 as far as the mechanism goes: the classifier is one
cgroup-match ruleset and it decides inside the box host on the box's own
leaf. Two facts bound the scope. First, the identities are cgroup paths and
counters, not source addresses: un-enrolled there is nothing to SNAT toward,
and NET-078's "distinct source identities" is met by the two match identities
and their counters, not by two addresses. Second, the ruleset needs
`CAP_NET_ADMIN`, which the native daemon lacks, so the co-resident host needs
a one-time privileged install step in the shape of the existing AppArmor
profile install: a root-owned table whose rules the daemon can express by
placement (a deny-all box under a `boxes/deny/` subtree matched by one static
rule) or, for per-box allow lists inside the box host, a small privileged rule
writer. Placement-only encoding cannot cut a box's established flows when its
declaration tightens, so a re-declaration must also kill the box's sockets.
Given these, T38 keeps both hosts; the VM-backed host is the easy case (the
guest daemon is pid 1 and root, so it owns the tree and the ruleset).

# Action items

1. Resolve the spec's open question on the cgroup layout with the tree in
   Conclusion (a) and note that the daemon is a sibling leaf under its root,
   never the root itself.
2. Keep co-resident Linux host-address boxes in scope of NET-078 to NET-080
   and add a WHERE-scoped requirement, or a note on NET-079, that on a native
   host the classifier ruleset is installed by a privileged install step and
   the daemon selects verdicts by placement or through that step.
3. Amend NET-079's verify note to name `reject with icmpx admin-prohibited`
   as the refusal so a deny-all box fails in 0 ms rather than at a connect
   timeout.
4. Reconcile NET-079 with NET-003's "resolves the name and reaches nothing":
   a plain deny-all leaf also drops the box's loopback DNS to the stub
   resolver, so the deny rule needs a carve-out for the local resolver path if
   resolution is to succeed inside a deny-all host-address box.
5. In T38, place the box process in its leaf before hakoniwa's single
   `unshare()` at `runc.rs:124` (a pre-unshare self-placement or a barrier),
   because hakoniwa's own cgroup hook runs after the cgroup-namespace unshare
   and would root the box's namespace at the daemon's cgroup.
6. In T38, treat a change of a box's declaration as a rule rewrite plus
   flow termination, since an established socket keeps the cgroup it was
   created in. Measure the rewrite half first, which this run did not:
   rewrite a leaf's rule under a live transfer and record whether the flow
   is dropped or rejected and whether the socket has to be killed for the
   new verdict to hold.
7. In T38, settle the root of the tree on a host with no user manager, which
   this run did not cover: name who creates and chowns it and how it comes
   back after a reboot, or scope the native classifier to hosts whose user
   manager delegates a subtree (finding H) and leave the rest to the VM.
8. In T38, enter the `daemon/` leaf at startup before any box exists and
   never enable a controller on `<root>` while it holds a process; the
   existing `cpu_weight` path must not be pointed at this tree.
9. Correct the plan's SP2 assumption line: the task that narrows to the
   VM-backed host is T38 (#1482) alone; T40 (#1492) is dynamic ingress and
   unrelated, and #1494 is T22.

# Artifacts

- This document: the ruleset, every command and its output are in the fenced
  blocks above.
- Run scripts (not checked in; copied into the lima VM as `/tmp/sp2-phase1.sh`
  through `/tmp/sp2-phase4.sh` for the run and reproducible from the blocks
  above).
- No code or spec change was made; the lima host was returned to its starting
  state (no `spike` tables, no `minimald.slice`, userns restriction restored).

[design]: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
