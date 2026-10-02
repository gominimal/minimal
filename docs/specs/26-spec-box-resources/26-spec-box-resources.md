---
id: BRES
title: Box resources — a host-sized guest, one enforced memory limit per box, admission that says why, and a signal when the kernel kills
owner: mitodrummer
epic: gominimal/inbox#698
arch: https://github.com/gominimal/arch/blob/main/architecture.md#box-resources
arch_sha: 5c1201517ba07347344fb9725efb06ee39d5c03e
updated: 2026-10-02
---

# BRES — Box resources — a host-sized guest, one enforced memory limit per box, admission that says why, and a signal when the kernel kills

## Context

The architecture's [Box Resources](https://github.com/gominimal/arch/blob/main/architecture.md#box-resources)
chapter is the one statement of the memory rules: `[machine] ram` is both what a box needs
from its host and its limit, `ram_reserved` is the part it is guaranteed, `[execution] on_oom`
says what an out-of-memory kill takes, the boxes sit in one subtree capped at the host's
allocatable, swap is unreadable once the boot ends, and every host reports its figures and
whether it enforces them (`enforced` or `advisory`). Nothing enforces any of it today. The host
VM daemon boots a constant guest (2048 MiB on x86_64, 4096 MiB on aarch64) on a 16 GiB laptop
and a 128 GiB workstation alike, with no swap; the session sandbox sets no memory limit; the Box
Host daemon admits every box without checking memory; and on `local0` boxes run unbounded. The
incident in gominimal/inbox#596 is the result: a 16 GiB guest, eight sessions, seven OOM kills in
one boot, every shell frozen together, and nothing logged.

After this ships, on `local0` and `local-minvmd0`, the guest is sized from its host; every box
runs under one limit inside a subtree the daemon stays outside; a box the host cannot hold is
refused with the host's figures and the remedy instead of starting smaller; swap slows a build
before the kernel kills inside that box alone; and every kill is reported in the daemon log, on
the box's event stream, in the attached shell, and in `min box show`, `min host show` and
`min ls`. A host that cannot enforce says `advisory` instead of pretending.

**Success:** on either local host, one box allocating without bound beside another ends with the
kernel killing inside that box alone, the other box's shell answering a keystroke within one
second, and the kill readable as a `WARN` naming the box, an `oom_killed` event and a kill count
in `min box show`; and an entry writing more `ram` than the host can hold exits 8 with the host's
allocatable and allocated rather than starting at a smaller size.

**First slice:** S1's host-derived guest RAM, S3b's expansion checks (IEC units only, and no
`ram_reserved` above a written `ram`, each exit 3), and admission on `local0` refusing a box that
does not fit with exit 8 and the `insufficient_resources` figures: an entry asking for more
memory than the host has is refused end to end, with the numbers, before any limit is written.

## Users and stories

**Roles:** developer on a large host, developer whose build outgrows its box, developer running several boxes on one VM, developer who drives builds through `min session exec` and `min task run`, developer running boxes on a Linux host without a VM, project author, developer running several boxes on one host, developer or a parent box following my boxes, developer whose linker just vanished, developer about to start a large build, developer deciding where a box fits and why it was refused or killed, developer placing a box on a host, operator reading the daemon log

- AS A developer on a large host, I WANT a fresh VM to boot with RAM derived from host memory when I set nothing, SO THAT the machine I paid for is the machine my boxes get.
  <!-- Acceptance criteria, for the EARS step:
       - The `default` arm of RAM resolution becomes host-derived with the same shape as the vcpu ceiling `max_vm_vcpus` (`crates/minvmd/src/cmd/mod.rs`): a fixed fraction of host memory (Open decisions: written to one half), floored at today's `DEFAULT_VM_RAM_MIB` so small hosts keep current behaviour, capped so the machine outside the VM keeps a reserve, and on x86_64 rounded to a hole-safe value (≤ 3072 or ≥ 6144 MiB, the rule `config.rs` already validates against): a derived value inside 3073–6143 MiB rounds down to 3072 MiB.
       - Resolution precedence stays `env ?? config ?? default`; only the `default` arm changes. `MINVMD_VM_RAM_MIB` and `minvmd config set --ram-mib` win unchanged.
       - `minvmd config show` and `config show --json` report the derived value with source `derived` (a fourth value beside `env`, `config`, `default`). A running VM reports the source it booted with: `State` gains `booted_ram_mib_source` beside `booted_ram_mib` (`crates/minvmd/src/state.rs`) and `minvmd status --json` carries it, so "16 GiB by default" and "16 GiB pinned by config" are different facts at runtime. Recording it in the `min bug` bundle is #597 item 5.
       - On a host whose total is at or below the floor's fraction, the source reads `default` and the value is today's constant — no host smaller than today's default boots a bigger guest.
       - Unit tests cover, per arch: a 128 GiB host, a 16 GiB host, a floor host (at or below 4 GiB on x86_64, 8 GiB on aarch64 — the source reads `default`), and on x86_64 an 8 GiB host, whose half (4096 MiB) falls inside the hole range `config.rs` warns on and must round down to 3072 MiB.
       - Note, not a gate: a large guest SHOULD return memory it no longer uses to the machine outside it (architecture Box Resources › Guest memory); this story is complete without it.
  -->
- AS A developer whose build outgrows its box, I WANT the guest to have swap that nothing can read after the boot ends, SO THAT memory pressure makes my shell slow before it makes it dead, without box memory reaching a disk.
  <!-- Acceptance criteria, for the EARS step:
       - After `enter_rootfs` (`crates/minimald/src/guest.rs`), `minimald` sizes a zram device from guest RAM (Open decisions: written to one half of RAM, capped), runs `mkswap` on it, and `swapon`s it. No swap file or partition exists on the state volume, on the rootfs, or on any volume that persists or is snapshotted.
       - The guest kernel carries zram; if the shipped guest kernel config lacks it, enabling it is part of this story.
       - `cat /proc/swaps` inside the guest lists the zram device with non-zero size; `/proc/meminfo` `SwapTotal` is non-zero. Both are asserted by a guest-side integration test on the KVM lane.
       - The host's own processes are never swapped: the cgroup holding `minimald`, the pty pumps and the relay carries `memory.swap.max` = 0, readable on the KVM lane. A box's own swap allowance is S3a-1's.
       - Order: after S3a-1 (it mounts cgroup2 and creates the daemon's cgroup this story limits). Seeing swap without a shell is S6's `swap_total_bytes` check.
  -->
- AS A developer running several boxes on one VM, I WANT each box to run under its own cgroup memory limit inside a subtree the daemon stays outside, SO THAT the kernel kills inside the box that overcommitted and my other shells and the daemon keep answering.
  <!-- Acceptance criteria, for the EARS step:
       - `enter_rootfs` (`crates/minimald/src/guest.rs`) mounts cgroup2 at `/sys/fs/cgroup` beside `proc` and `sysfs`; nothing mounts it today, and the guest has no systemd, so hakoniwa's cgroup manager (which hardcodes a systemd slice and fails without a booted systemd) is not the mechanism.
       - `minimald` creates one boxes subtree — the subtree the networking design's egress classifier matches (deployment-and-egress-gateway.md §4.1) — with `memory.max` = the host's allocatable, which is guest RAM minus the daemon's reserve (Open decisions). `minimald` and the pty pumps sit outside it, so a shortage among boxes is resolved among boxes and a kill never takes the relay that reports it.
       - Each box gets a leaf in that subtree, written by `minimald` in sandbox2's container setup (`crates/sandbox2/src/lib.rs`): `memory.max` = the box's resolved `ram` (S3b; until S3b lands, the host's default box size), `memory.swap.max` = the same value (a box may swap at most its `ram`), and `memory.min` = the box's reservation (S3c; until S3c lands, the host's overcommit floor). The attach shell's pid is written to the leaf's `cgroup.procs` before it enters any of the box's namespaces, so the whole shell tree inherits the leaf.
       - The leaf is the root of the box's cgroup namespace and its limit files are not writable from inside: `cat /sys/fs/cgroup/memory.max` inside the box equals the limit, and a write to it from root inside the box fails.
       - A leaf that cannot be created or written fails the box start with the error; sandbox2's `IgnoreCgroupSetupFailed` is not used for this leaf. Nothing runs unbounded silently on a host that reports `enforced`.
       - The leaf is created for every box the guest daemon starts; today that is the session box, and a box type gominimal/inbox#731 adds takes the same leaf with no change to this story.
       - The proof is the KVM-lane scenario for use case 2, carried by a `crates/minvmd/tests/<name>_integration.rs` harness (the shape of `minimald_session_integration.rs`; the KVM lane auto-discovers `_integration` binaries, not `_root_integration`) or by `scripts/session-e2e.sh`: with two session boxes live, a process in box A allocates without bound; **while A is under pressure and after A's process is killed**, B's attached pty answers a keystroke within one second; A's `memory.events` records the kill; B's stays at zero.
  -->
- AS A developer who drives builds through `min session exec` and `min task run`, I WANT every process the daemon starts on a box's behalf to run inside that box's memory leaf, SO THAT the limit means the same thing however work enters the box.
  <!-- Acceptance criteria, for the EARS step:
       - A `min session exec` process (the exec `min box exec` names) is injected into the sandbox by `setns` (`crates/minimald/src/nsenter.rs`); the shim writes its own pid to the box leaf's `cgroup.procs` before it joins the box's namespaces, so it runs under the same limit and `timeout` ceilings as the entrypoint. Inside the box `/proc/self/cgroup` reads `0::/` (the leaf is the namespace root), and from the daemon side the exec's pid is listed in the leaf's `cgroup.procs`.
       - `min session run` and `min task run` build their own container (`crates/minimald/src/exec.rs`); that container is created inside the box's leaf, not beside it, so a task's linker counts against the box that ran it.
       - Lifecycle hooks the daemon runs for a box, and every PTY attach, join the same leaf.
       - The S3a-1 scenario is repeated with A's allocation driven through `min session exec` and through `min task run`; A's `memory.events` records the kill in both, B's pty answers within one second in both.
       - Order: after S3a-1.
  -->
- AS A developer running boxes on a Linux host without a VM, I WANT the native daemon to put my boxes under the same subtree and per-box limits when it holds a delegated memory controller, SO THAT a runaway box on `local0` meets its own limit and never squeezes the daemon or my desktop.
  <!-- Acceptance criteria, for the EARS step:
       - When the native `minimald` finds a delegated cgroup2 subtree with the memory controller enabled, it creates the boxes subtree inside it and a leaf per box with the limits, the join order and the not-writable-from-inside rule S3a-1 states; the subtree's `memory.max` is `local0`'s allocatable — capacity minus the Box Host's reserve on `local0`, which stands for the rest of the desktop (Open decisions).
       - Without such a subtree it applies no memory limit and starts the box; what it reports then is S8's.
       - A root integration test on the native lane with a delegated subtree runs the S3a-1 scenario on `local0`: A's process is killed, A's `memory.events` records it, B's pty answers within one second.
       - Order: after S3a-1.
  -->
- AS A project author, I WANT the `[machine] ram` my entry writes to be exactly the limit the kernel enforces, and an omitted one to take the host's default box size, SO THAT the number in `minimal.toml` is the number that holds or a refusal that says why, never a quietly smaller one.
  <!-- Acceptance criteria, for the EARS step:
       - At expansion, `min` accepts `ram` and `ram_reserved` flat on an entry, in IEC binary units only (`KiB`, `MiB`, `GiB`, `TiB`); `"8G"`, `"8GB"` or `"8Gi"` fails with exit 3 and a did-you-mean hint naming `"8GiB"`. A `ram_reserved` above a written `ram` fails with exit 3.
       - Omitted or `"auto"`, `ram` resolves at admission to the host's default box size, which the host reports; on a host that overcommits it is a fraction of allocatable (Open decisions), never all of it. The source reads `default`.
       - A written `ram` is applied exactly as S3a-1's `memory.max`, and its source reads `entry`. Nothing clamps, rounds, or shrinks it.
       - Admission refuses a box whose `cpu_arch` does not match the host's exactly, or whose resolved `ram` — or whose `cpus` or `disk`, fit only (open gap 18) — does not fit the host's allocatable, with exit 8 and the machine form `{"schema":"min/v1/error","code":"insufficient_resources",…}` carrying the dimension, the requested size and the layer it came from, the host's allocatable and allocated (never other boxes' names or owners), and the remedy: omit `ram`, or give the host more memory.
       - The daemon logs the limit and its source at box creation as a structured `INFO`; the box record stores both, which S9 renders.
       - Tests: a written `ram` above allocatable on `local0` and on `local-minvmd0` exits 8 with the figures; an omitted `ram` starts with `memory.max` equal to the host's default box size; `"8G"` exits 3 with the hint.
       - Sequence: complete once gominimal/inbox#731's BOX spec lands the `[machine]` expansion and the box record; slices: S3a-1, then this.
  -->
- AS A developer running several boxes on one host, I WANT each box to hold a reservation that admission never overcommits and reclaim never takes, SO THAT the memory a box needs to keep working stays its own while its neighbours compete for the rest.
  <!-- Acceptance criteria, for the EARS step:
       - `ram_reserved` is optional and at most the box's resolved `ram`. Omitted, the reservation is the host's overcommit policy: all of `ram` on a host that does not overcommit, or a small floor on LocalVM and SharedLinux (Open decisions), capped at the box's resolved `ram`.
       - A written `ram_reserved` above what an omitted or `"auto"` `ram` resolves to is refused at admission with exit 8, `code = "insufficient_resources"`, naming `ram` as the remedy.
       - Admission sums the reservations of the host's boxes, the new one's included, and refuses with exit 8 and the S3b figures when the sum exceeds allocatable; the sum is the host's allocated.
       - On an `enforced` host the box's leaf carries `memory.min` = its reservation, readable from `min box show` (S9) and from the leaf on the KVM and native lanes.
       - The boxes subtree's `memory.min` equals the host's allocated (the sum of its boxes' reservations), updated at each admission and each box exit, so a leaf's reservation is protected from reclaim; readable from the subtree on the KVM and native lanes.
       - Tests: two boxes whose written reservations sum above allocatable — the second exits 8; an omitted reservation on `local-minvmd0` equals the floor; a written `ram_reserved = "2GiB"` with `ram = "auto"` resolving to less exits 8.
       - Sequence: complete once gominimal/inbox#731's BOX spec lands the `[machine]` expansion and the box record; slices: S3a-1, S3b, then this.
  -->
- AS A project author, I WANT `[execution] on_oom` to say whether a box goes on after an OOM kill or ends, SO THAT a shell outlives a linker it started while a task with one process silently missing reports failure instead of success.
  <!-- Acceptance criteria, for the EARS step:
       - `on_oom` is `"kill_process"` or `"end_box"`, written flat on an entry. The Box Type supplies the default: `kill_process` for `session` and `agent`; `end_box` for `task`, `service`, `build` and `container-build`.
       - Under `kill_process`, the process the kernel chose dies and the box goes on, unless that process was the entrypoint, which ends the box.
       - Under `end_box`, the kernel kills every process in the box together (`memory.oom.group` on the leaf) and the box ends; a service then follows its `restart` policy.
       - A box an OOM kill ends records `exited` with reason `oom`, and `min run` and `min box wait` return 137 (128 + SIGKILL).
       - Tests on the KVM lane: in a session box, a child that allocates past `ram` dies and the shell answers; a `task` box whose process is OOM-killed exits with 137 and reason `oom`; a session whose shell itself is OOM-killed ends as `exited` with reason `oom`.
       - Sequence: complete once gominimal/inbox#731's BOX spec lands the `[execution]` expansion, the box record's `exited` reason and `min box wait`; slices: S3a-1, then this.
  -->
- AS AN operator reading the daemon log, I WANT a `WARN` for sustained memory pressure and for every OOM kill, with the box named, SO THAT "the box ran out of memory" is a line in the log, not an inference from a ring buffer.
  <!-- Acceptance criteria, for the EARS step:
       - A sampler task in `minimald` (its own short-period timer; the maintenance actor's 6-hour tick is not the home) reads `/proc/pressure/memory` and each box leaf's `memory.events` (S3a-1) on a cadence (Open decisions: written to 5 s).
       - On any increment of a leaf's `oom_kill`, one `WARN` is emitted naming the box (id and name), the kill count this boot, and the kernel's task name when `kmsg` still carries it — never the command line. Kills that land within one tick are one `WARN` with their count.
       - On `some avg10` above a threshold for a sustained window (Open decisions: written to 25% for 30 s), one `WARN` names the pressure and the top consumer among box leaves by `memory.current`; it repeats no more often than once per window while pressure persists, and logs one `INFO` when pressure clears.
       - The counters the sampler reads are cumulative (`memory.events`, `/proc/vmstat oom_kill`), so kills that scrolled out of `kmsg` are still counted; the `WARN` for a kill that happened while the daemon was not sampling is emitted at the next tick.
       - The events are `tracing` events with structured fields (`box_id`, `box_name`, `oom_kills`, `task`, `psi_some_avg10`), so `min bug` (#597) can select them without parsing prose.
       - Order: after S3a-1 (per-box attribution reads the leaf).
  -->
- AS A developer or a parent box following my boxes, I WANT each OOM kill to be an event in the box's control-plane stream, SO THAT I see a child's OOM from `min box events` without reading a host log.
  <!-- Acceptance criteria, for the EARS step:
       - Each kill S4a observes, or each burst coalesced with its count, is written as one `oom_killed` event in the box record beside the daemon log line, carrying the kernel's task name, never the command line, and the count.
       - `min box events <box>` replays it, and `min box events --parent self` from inside a parent box shows a child's `oom_killed` event.
       - Test: the S3a-1 scenario leaves exactly one `oom_killed` event per coalesced burst on A's stream and none on B's.
       - Sequence: complete once gominimal/inbox#731 lands the box record's event stream and `min box events`, and, for the `--parent self` clause, once gominimal/inbox#568 lands nesting (a child created from inside a box); slices: S4a, then this.
  -->
- AS A developer whose linker just vanished, I WANT a notice in my attached shell saying the kernel killed it for memory and what the box's limit is, SO THAT a build that died from SIGKILL does not look like a mysterious linker failure.
  <!-- Acceptance criteria, for the EARS step:
       - Within one sampler tick of S4a's kill event, every PTY attached to the affected box receives one notice line written by `minimald` (the `wall` shape: a newline, the message, a newline; never written into the shell's input), naming the kernel's task name when known and the box's limit.
       - A box with no attached PTY at the time queues the notice and prints it on the next attach, before the shell paints; the queue holds the latest event only.
       - A stderr line at shell start does not satisfy this; the notice is asserted by the KVM-lane scenario from S3a-1 driving A's PTY through `scripts/e2e-attach-pty.py` and matching the notice text.
       - The notice is suppressed for non-interactive `min session exec`, `min session run`, and `min task run`; those get the exit status the kernel already gives them, and because S3a-2 put them in the leaf, S4a's `WARN` still names the box.
       - Order: after S4a (consumes its kill event).
  -->
- AS A developer about to start a large build, I WANT `min ls` to show the guest's memory headroom and swap, SO THAT "check before you build" is a command I already run.
  <!-- Acceptance criteria, for the EARS step:
       - `ListSessionsResponse.resource_pool` (`crates/minimald-rpc/src/lib.rs`), which `minimald` already fills from in-guest sysinfo (`crates/minimald/src/rpc.rs`) with `memory_bytes`, gains `memory_available_bytes`, `swap_total_bytes`, `swap_free_bytes`, `oom_kills_this_boot`, and `psi_some_avg10`. This is the in-guest measurement spec 09 deferred; no new RPC (Open decisions).
       - `min ls` extends the `RESOURCE POOL:` line it already prints above the session table (`crates/minimal/src/cmd/list.rs`) to `… memory <available> of <total> free · swap <free> of <total> · <n> OOM kills this boot`; `min ls --json` carries the new fields under the existing `resource_pool` key, unchanged shape otherwise. The line is the developer's glance; `min host show` (S9) is the source of record for the host's figures.
       - `minvmd status --json` gains a `memory` object with the same fields, read from the guest over the existing oneshot RPC client (`crates/minvmd/src/rpc_client.rs`), `null` when the VM is stopped; it does not collide with spec 09's `metrics` object, which carries no memory or swap keys.
       - The numbers are the guest's `/proc/meminfo`, `/proc/vmstat`, and `/proc/pressure/memory`, not the host VMM's RSS (spec 09 records why the RSS proxy is unmeasurable).
       - Asserted on the native lane (`min ls --json` against a live daemon: `resource_pool.memory_available_bytes` > 0) and on the KVM lane (`swap_total_bytes` > 0 after S2).
  -->
- AS A developer deciding where a box fits and why it was refused or killed, I WANT `min host show` to carry the host's memory figures and `min box show` to carry the box's, SO THAT the numbers admission and the kernel used are readable without a shell.
  <!-- Acceptance criteria, for the EARS step:
       - `min host list` and `min host show` carry, for `local0` and `local-minvmd0` alike, the Box Provider API Host model's figures: capacity, allocatable, allocated, the default box size, the overcommit policy, and memory enforcement (`enforced` or `advisory`); `-o json` carries them as fields.
       - `min box show <box>` carries the limit and its source (`entry` or `default`), the reservation, current use (`memory.current`), the OOM kill count, and, on an `advisory` host, marks the limit and reservation advisory. `min box show self` from inside a box carries the same.
       - Test: on `local-minvmd0`, `min host show -o json` reports allocatable = capacity − the daemon's reserve and allocated = the sum of running boxes' reservations; `min box show` after the S3a-1 scenario reports A's kill count as 1.
       - Sequence: complete once gominimal/inbox#731's box CLI lands `min host list|show` and `min box show`, and, for the `min box show self` clause, once gominimal/inbox#568 puts `min` inside a box; slices: S3b, S3c, then this.
  -->
- AS A developer placing a box on a host, I WANT the host to say whether it actually enforces memory limits, from what it can do rather than from a setting, SO THAT a box on a host that cannot protect its memory is admitted with a warning instead of a false promise.
  <!-- Acceptance criteria, for the EARS step:
       - A host's memory enforcement is `enforced` when it holds a delegated memory controller that delivers all three guarantees — each box's limit, hard reservations, and the cap on the boxes subtree — and `advisory` otherwise. No configuration key sets it. The guest daemon on `local-minvmd` reports `enforced` after S3a-1; the native `local0` reports `enforced` with S3a-3's delegated subtree and `advisory` without it.
       - Every host reports it, including `local0` and `local-minvmd0`, through S9's surfaces.
       - An `advisory` host still does admission's accounting — fit and reservations — and applies no limit: it admits a box that fits, written size or not, warns at creation that the box's memory is not protected, and `min box show` marks the box's limit and reservation advisory.
       - Tests on the native lane: `local0` without a delegated subtree reports `advisory`, a box start prints the warning, `min box show` marks it advisory, and a box whose `ram` exceeds allocatable is still refused with exit 8; with a delegated subtree the same host reports `enforced` and prints no warning.
       - Sequence: complete once gominimal/inbox#731's box CLI lands `min host show` and `min box show`; slices: S3a-3, S9, then this.
  -->

## Requirements

- **BRES-001** WHEN `minvmd` boots the guest and neither `MINVMD_VM_RAM_MIB` nor the persisted config sets guest RAM THE SYSTEM SHALL size the guest at the larger of the per-architecture constant (2048 MiB on x86_64, 4096 MiB on aarch64) and the smaller of one half of host memory and host memory minus a 4 GiB reserve.
  tier:     T1
  verify:   cargo nextest run -p minvmd prop_derived_guest_ram_never_below_arch_constant
  property: For every host memory size above twice the constant and each architecture, the derived guest RAM equals the larger of that architecture's constant and the smaller of one half of host memory and host memory minus 4 GiB, after BRES-002's rounding on x86_64; for every host size it is at least the constant.

- **BRES-002** WHEN `minvmd` derives guest RAM on x86_64 and the derived value is from 3073 MiB to 6143 MiB inclusive THE SYSTEM SHALL round it down to 3072 MiB.
  tier:     T1
  verify:   cargo nextest run -p minvmd prop_derived_guest_ram_x86_64_avoids_3073_to_6143
  property: For every host memory size, the guest RAM derived on x86_64 is never from 3073 MiB to 6143 MiB inclusive.

- **BRES-003** THE SYSTEM SHALL resolve guest RAM from `MINVMD_VM_RAM_MIB` first, from `minvmd config set --ram-mib` second, and from the derived default only when neither is set.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_ram_precedence_env_then_config_then_derived

- **BRES-004** WHEN guest RAM resolves from the derived default THE SYSTEM SHALL report the value in `minvmd config show` and `minvmd config show --json` with the source `derived`, beside the sources `env`, `config` and `default`.
  tier:     T0
  verify:   cargo nextest run -p minvmd config_show_reports_derived_source

- **BRES-005** WHEN `minvmd` boots a VM THE SYSTEM SHALL record the RAM source the VM booted with beside its booted RAM and report both in `minvmd status --json`.
  tier:     T0
  verify:   cargo nextest run -p minvmd status_json_reports_booted_ram_and_source

- **BRES-006** WHEN `minvmd` resolves guest RAM from its default on a host whose total memory is at or below twice the per-architecture constant (4 GiB on x86_64, 8 GiB on aarch64) THE SYSTEM SHALL size the guest at that constant and report the source `default`.
  tier:     T1
  verify:   cargo nextest run -p minvmd prop_small_host_keeps_arch_constant_with_default_source
  property: For every host memory size and architecture, the default resolves to that architecture's constant with source `default` exactly when host memory is at or below twice the constant, and with source `derived` otherwise.

- **BRES-007** WHEN `minimald` enters the root filesystem at guest boot THE SYSTEM SHALL create a zram device sized at one half of guest RAM capped at 8 GiB, with its `mem_limit` set to one half of that size (the 2:1 compression this spec assumes, held as a bound even for incompressible pages), format it as swap and enable it, enforced by `minimald` at guest boot and the guest kernel, on the guest side of TB3.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_zram_swap_sized_half_ram_capped_8gib_integration

- **BRES-008** THE SYSTEM SHALL keep no swap file or swap partition on the state volume, on the rootfs, or on any volume that persists or is snapshotted, enforced by `minimald` at guest boot and the guest kernel, on the guest side of TB3.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_no_swap_on_persistent_volume_integration

- **BRES-009** WHILE the guest is running THE SYSTEM SHALL list the zram device in the guest's `/proc/swaps` with a non-zero size and report a non-zero `SwapTotal` in the guest's `/proc/meminfo`.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_proc_swaps_lists_zram_integration

- **BRES-010** THE SYSTEM SHALL set `memory.swap.max` to 0 on the cgroup holding `minimald`, the pty pumps and the relay, so that the host's own processes are never swapped, enforced by `minimald` inside the guest, outside the boxes subtree (the guest side of TB3).
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_daemon_cgroup_never_swaps_integration

- **BRES-011** WHEN the guest boots THE SYSTEM SHALL mount cgroup2 at `/sys/fs/cgroup` beside `proc` and `sysfs`.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_mounts_cgroup2_at_boot_integration

- **BRES-012** THE SYSTEM SHALL cap the guest's boxes subtree, the one subtree the egress classifier matches, at `memory.max` equal to the host's allocatable (guest RAM minus the daemon's 512 MiB reserve and minus the zram device's worst-case footprint, its `mem_limit` of BRES-007), enforced by `minimald` and the kernel outside the box, on the host side of TB2 inside the guest (the guest side of TB3), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_boxes_subtree_capped_at_allocatable_integration

- **BRES-013** THE SYSTEM SHALL keep `minimald` and the pty pumps outside the guest's boxes subtree, enforced by `minimald` and the kernel outside the box, on the host side of TB2 inside the guest (the guest side of TB3), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_daemon_and_pumps_outside_boxes_subtree_integration

- **BRES-014** WHEN `minimald` starts a box on either local host (`local0` with a delegated subtree, `local-minvmd0`) THE SYSTEM SHALL create a leaf for it in the boxes subtree with `memory.max` equal to the box's resolved `ram`, `memory.swap.max` equal to the same value on `local-minvmd0` and on `local0` where BRES-075 allows swap (0 otherwise), and `memory.min` equal to the box's reservation, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`; on the developer's machine on `local0`, inside a subtree the host's cgroup manager delegates), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_box_leaf_limits_integration && cargo nextest run -p minimald local0_box_leaf_limits_root_integration

- **BRES-015** WHEN a PTY attach starts a shell in a box on either local host (`local0` with a delegated subtree, `local-minvmd0`) THE SYSTEM SHALL write the shell's pid into the box's leaf before the shell enters any of the box's namespaces, so that the whole shell tree inherits the leaf, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`; on the developer's machine on `local0`, inside a subtree the host's cgroup manager delegates), against every process in the box including root inside it, with the write made before `setns` or `unshare`.
  tier:     T0
  verify:   cargo nextest run -p minvmd attach_shell_joins_leaf_before_namespaces_integration && cargo nextest run -p minimald local0_join_leaf_before_namespaces_root_integration

- **BRES-016** WHEN `minimald` starts a box on either local host (`local0` with a delegated subtree, `local-minvmd0`) THE SYSTEM SHALL make the box's leaf the root of the box's cgroup namespace, on a cgroup2 mount with `nsdelegate` (mounted so by `minimald` in the guest, by the host's cgroup manager on `local0`), so that `/sys/fs/cgroup/memory.max` read inside the box returns the box's limit and the kernel refuses writes from inside to the leaf's own limit files, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`; on the developer's machine on `local0`, inside a subtree the host's cgroup manager delegates), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p sandbox2 box_cgroup_namespace_root_is_leaf && cargo nextest run -p minimald local0_box_cgroup_namespace_root_is_leaf_root_integration

- **BRES-017** IF root inside a box on either local host (`local0` with a delegated subtree, `local-minvmd0`) writes to the box's `/sys/fs/cgroup/memory.max` THEN THE SYSTEM SHALL fail the write, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`; on the developer's machine on `local0`, inside a subtree the host's cgroup manager delegates), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd box_root_cannot_write_own_memory_max_integration && cargo nextest run -p minimald local0_box_root_cannot_write_memory_max_root_integration

- **BRES-018** IF `minimald` cannot create or write a box's leaf THEN THE SYSTEM SHALL fail the box start with that error, so that no box runs without its leaf on a host that reports `enforced`, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minimald leaf_write_failure_fails_box_start

- **BRES-019** WHEN the guest daemon starts a box of any type THE SYSTEM SHALL give that box a leaf.
  tier:     T0
  verify:   cargo nextest run -p minimald every_box_type_gets_a_leaf

- **BRES-020** WHILE two session boxes are live, WHEN a process in box A allocates without bound and the kernel kills it THE SYSTEM SHALL keep box B's attached PTY answering a keystroke within one second, record the kill in A's `memory.events`, and leave the kill count in B's `memory.events` at zero.
  tier:     T0
  verify:   cargo nextest run -p minvmd box_oom_isolation_integration

- **BRES-021** WHEN `min session exec` starts a process in a box THE SYSTEM SHALL write that process's pid into the box's leaf before it joins the box's namespaces, so that inside the box `/proc/self/cgroup` reads `0::/` and from the daemon side the pid is listed in the leaf, enforced by the exec shim `minimald` launches, on the host side of TB2 before `setns`, and otherwise by `minimald` and the kernel outside the box against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd exec_joins_leaf_before_namespaces_integration

- **BRES-022** WHEN `min session run` or `min task run` builds its container in a box THE SYSTEM SHALL create the container inside the box's leaf, not beside it, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd run_and_task_container_inside_leaf_integration

- **BRES-023** WHEN the daemon runs a lifecycle hook for a box THE SYSTEM SHALL place the hook's process in the box's leaf, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd lifecycle_hook_joins_leaf_integration

- **BRES-024** WHILE two session boxes are live, WHEN a process started in box A through `min session exec` allocates without bound and the kernel kills it THE SYSTEM SHALL record the kill in A's `memory.events` and keep box B's attached PTY answering a keystroke within one second.
  tier:     T0
  verify:   cargo nextest run -p minvmd box_oom_isolation_via_exec_integration

- **BRES-025** WHILE two session boxes are live, WHEN a process started in box A through `min task run` allocates without bound and the kernel kills it THE SYSTEM SHALL record the kill in A's `memory.events` and keep box B's attached PTY answering a keystroke within one second.
  tier:     T0
  verify:   cargo nextest run -p minvmd box_oom_isolation_via_task_run_integration

- **BRES-026** WHERE the host delegates a cgroup2 subtree with the memory controller enabled to the native `minimald` THE SYSTEM SHALL create the boxes subtree inside it with `memory.max` equal to `local0`'s allocatable (capacity minus the larger of 4 GiB and one quarter of host memory), enforced by the native `minimald` and the kernel outside the box, on the host side of TB2 on the developer's machine (no TB3), inside a subtree the host's cgroup manager delegates, against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_boxes_subtree_capped_at_allocatable_root_integration

- **BRES-027** IF the native `minimald` finds no delegated cgroup2 subtree with the memory controller enabled THEN THE SYSTEM SHALL start the box with no memory limit applied.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_without_delegation_starts_box_unlimited

- **BRES-028** WHERE the host delegates a cgroup2 subtree with the memory controller enabled to the native `minimald`, WHEN a process in box A, one of two live session boxes, allocates without bound THE SYSTEM SHALL have the kernel kill that process, record the kill in A's `memory.events`, and keep box B's attached PTY answering a keystroke within one second.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_box_oom_isolation_root_integration

- **BRES-029** IF a `ram` or `ram_reserved` value written flat on an entry uses any unit other than the IEC binary units `KiB`, `MiB`, `GiB` and `TiB` THEN THE SYSTEM SHALL fail expansion in `min` with exit 3 and a did-you-mean hint that names the same number with the IEC unit of the same magnitude letter (`"8GiB"` for `"8G"`, `"8GB"` or `"8Gi"`) and says that the decimal unit is not the binary one (`8GB` is not `8GiB`).
  tier:     T1
  verify:   cargo nextest run -p minimal prop_machine_ram_non_iec_unit_exits_3_with_hint
  property: Every `ram` or `ram_reserved` value not in IEC binary units fails expansion with exit 3, and its hint names the same number with the IEC unit of the same magnitude letter; every IEC value parses to exactly its byte count.

- **BRES-030** IF a `ram_reserved` is above a written `ram` on the same entry THEN THE SYSTEM SHALL fail expansion in `min` with exit 3.
  tier:     T1
  verify:   cargo nextest run -p minimal prop_ram_reserved_above_written_ram_exits_3
  property: For every entry writing both `ram` and `ram_reserved`, expansion fails with exit 3 exactly when `ram_reserved` is above `ram`.

- **BRES-031** WHEN admission resolves a box whose `ram` is omitted or `"auto"` THE SYSTEM SHALL resolve it to the host's default box size, one half of allocatable on `local0` and `local-minvmd0`, and record its source as `default`.
  tier:     T2
  verify:   cargo nextest run -p minimald auto_ram_resolves_to_half_allocatable
  property: For every allocatable, the default box size equals one half of it rounded down, so above zero it is less than all of it; no box whose `ram` is omitted or `"auto"` is admitted at a default box size below 256 MiB (BRES-078).
  harness:  `crates/sessions/src/core/admission.rs` `kani_default_box_size_below_allocatable`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`

- **BRES-032** WHEN a box's `ram` is written THE SYSTEM SHALL write exactly that value to the leaf's `memory.max`, without clamping or shrinking it, so that the leaf's `memory.max` reads back equal to the written `ram` rounded down to the host page size, and record its source as `entry`, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minimald written_ram_applied_exactly_as_memory_max

- **BRES-033** IF a box's `cpu_arch` does not match the host's exactly THEN THE SYSTEM SHALL refuse the box at admission with exit 8, enforced by the Box Host daemon at admission, on the host side of TB2; the refusal's machine-form `code` and its remedy are an architecture gap (Open questions: arch's checks table has no `cpu_arch` row).
  tier:     T0
  verify:   cargo nextest run -p minimald admission_refuses_cpu_arch_mismatch_exit_8

- **BRES-034** IF a box's resolved `ram`, `cpus` or `disk` does not fit the host's allocatable THEN THE SYSTEM SHALL refuse the box at admission with exit 8, checking `cpus` and `disk` for fit only, enforced by the Box Host daemon at admission, on the host side of TB2.
  tier:     T2
  verify:   cargo nextest run -p minimald admission_refuses_box_that_does_not_fit_exit_8
  property: For every host allocatable and every box's resolved `ram`, `cpus` and `disk`, admission refuses with exit 8 exactly when some dimension exceeds the host's allocatable for it.
  harness:  `crates/sessions/src/core/admission.rs` `kani_admission_fit_refuses_iff_over_allocatable`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`
  - IF `local0`'s capacity is at or below its reserve THEN THE SYSTEM SHALL take `local0`'s allocatable as 0, refuse every box at admission with exit 8, and report that allocatable in `min host show`, enforced by the Box Host daemon at admission, on the host side of TB2.
    tier:   T0
    verify: cargo nextest run -p minimald local0_capacity_at_or_below_reserve_refuses_every_box

- **BRES-035** WHEN admission refuses a box with exit 8 because it does not fit (BRES-034) or its reservation cannot be met (BRES-038, BRES-039) THE SYSTEM SHALL carry the machine form `{"schema":"min/v1/error","code":"insufficient_resources",…}` with the dimension, the requested size and the layer it came from, the host's allocatable and allocated, and the remedy for the refusal (for a `ram` fit refusal: omit `ram`, or give the host more memory; for `cpus` or `disk`: write a smaller value, or give the host more of it; for a reservation refusal, the remedy BRES-038 or BRES-039 states), enforced by the Box Host daemon at admission, on the host side of TB2.
  tier:     T2
  verify:   cargo nextest run -p minimald exit_8_refusal_carries_insufficient_resources_figures
  property: Every fit or reservation refusal carries the `min/v1/error` machine form with the requested size, its layer, and the host's allocatable and allocated as admission computed them.
  harness:  `crates/sessions/src/core/admission.rs` `kani_refusal_carries_its_own_figures`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`
  - THE SYSTEM SHALL omit every other box's name and owner from every exit-8 refusal, enforced by the Box Host daemon at admission, on the host side of TB2.
    tier:   T0
    verify: cargo nextest run -p minimald exit_8_refusal_never_names_another_box
    property: No exit-8 refusal names another box or its owner.

- **BRES-036** WHEN `minimald` creates a box THE SYSTEM SHALL log the box's memory limit and its source as a structured `INFO` event.
  tier:     T0
  verify:   cargo nextest run -p minimald box_create_logs_limit_and_source_info
  - WHEN `minimald` creates a box THE SYSTEM SHALL store the box's memory limit and its source in the box record.
    tier:   T0
    verify: cargo nextest run -p minimald box_record_stores_limit_and_source

- **BRES-037** WHEN admission resolves a box whose `ram_reserved` is omitted THE SYSTEM SHALL set its reservation to the host's 256 MiB overcommit floor on `local-minvmd0` and `local0`, capped at the box's resolved `ram`.
  tier:     T2
  verify:   cargo nextest run -p minimald omitted_ram_reserved_defaults_to_256mib_floor
  property: For every resolved `ram`, an omitted `ram_reserved` resolves to the smaller of 256 MiB and that `ram`, so no reservation exceeds its box's resolved `ram`.
  harness:  `crates/sessions/src/core/admission.rs` `kani_omitted_reservation_is_capped_floor`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`

- **BRES-038** IF a written `ram_reserved` is above the box's resolved `ram`, whether that `ram` is written, omitted or `"auto"`, THEN THE SYSTEM SHALL refuse the box at admission with exit 8 and `code = "insufficient_resources"`, with the remedy naming `ram` (write a `ram` at least `ram_reserved`, or lower `ram_reserved`), whatever client sent the request and whether or not `min`'s expansion check (BRES-030) ran, enforced by the Box Host daemon at admission, on the host side of TB2.
  tier:     T2
  verify:   cargo nextest run -p minimald ram_reserved_above_auto_ram_refused_exit_8
  property: For every admitted box, its reservation is at most its resolved `ram`; every request whose written `ram_reserved` is above its resolved `ram`, written, omitted or `"auto"`, is refused with exit 8 naming `ram`.
  harness:  `crates/sessions/src/core/admission.rs` `kani_reservation_never_exceeds_resolved_ram`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`

- **BRES-039** IF the sum of the reservations of the host's running boxes, the new box's included, exceeds the host's allocatable THEN THE SYSTEM SHALL refuse the new box at admission with exit 8, the figures of BRES-035 and the remedy: lower or omit `ram_reserved`, or stop other boxes, taking that sum as the host's allocated, enforced by the Box Host daemon at admission, on the host side of TB2.
  tier:     T2
  verify:   cargo nextest run -p minimald admission_refuses_when_reservations_exceed_allocatable
  property: For every set of at most 8 boxes, admission admits the new box only when the sum of the counted boxes' reservations, the new one's included, is at most the host's allocatable, computes that sum without overflow, and reports it as allocated, with the reservation remedy, in any refusal.
  harness:  `crates/sessions/src/core/admission.rs` `kani_reservations_sum_within_allocatable`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`

- **BRES-040** WHILE a host reports `enforced` THE SYSTEM SHALL set each box leaf's `memory.min` to the box's reservation, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd enforced_host_leaf_memory_min_is_reservation_integration

- **BRES-041** WHEN admission admits a box or a box exits THE SYSTEM SHALL set the boxes subtree's `memory.min` to the host's allocated, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T2
  verify:   cargo nextest run -p minvmd boxes_subtree_memory_min_tracks_allocated_integration
  property: For every sequence of admits and exits, the boxes subtree's `memory.min` after each step equals the sum of the reservations of the boxes then counted, and never exceeds the host's allocatable.
  harness:  `crates/sessions/src/core/admission.rs` `kani_allocated_tracks_admit_and_exit`, sequences of at most 8 admit and exit steps over at most 8 boxes, `#[kani::unwind(9)]`

- **BRES-042** THE SYSTEM SHALL accept `on_oom` written flat on an entry with the value `"kill_process"` or `"end_box"`.
  tier:     T0
  verify:   cargo nextest run -p mfile on_oom_accepts_kill_process_and_end_box

- **BRES-043** WHEN `on_oom` is omitted THE SYSTEM SHALL take its value from the box's Box Type: `kill_process` for `session` and `agent`, `end_box` for `task`, `service`, `build` and `container-build`.
  tier:     T0
  verify:   cargo nextest run -p minimal on_oom_defaults_from_box_type

- **BRES-044** WHILE a box's `on_oom` is `kill_process`, WHEN the kernel kills a process in the box other than its entrypoint for memory THE SYSTEM SHALL keep the box running.
  tier:     T0
  verify:   cargo nextest run -p minvmd kill_process_non_entrypoint_box_continues_integration

- **BRES-045** WHILE a box's `on_oom` is `kill_process`, WHEN the kernel kills the box's entrypoint for memory THE SYSTEM SHALL end the box as any entrypoint exit ends it.
  tier:     T0
  verify:   cargo nextest run -p minvmd kill_process_entrypoint_ends_box_integration

- **BRES-046** WHILE a box's `on_oom` is `end_box`, WHEN the kernel kills a process in the box for memory THE SYSTEM SHALL have every process in the box killed together through `memory.oom.group` on its leaf, and end the box, enforced by `minimald` and the kernel outside the box, on the host side of TB2 (inside the guest on `local-minvmd0`, on the developer's machine on `local0`), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minvmd end_box_oom_group_kills_whole_box_integration

- **BRES-047** WHILE a service box's `on_oom` is `end_box`, WHEN an OOM kill ends the box THE SYSTEM SHALL apply the service's `restart` policy.
  tier:     T0
  verify:   cargo nextest run -p minvmd end_box_service_follows_restart_policy_integration

- **BRES-048** WHEN an OOM kill ends a box THE SYSTEM SHALL record the box as `exited` with reason `oom`.
  tier:     T0
  verify:   cargo nextest run -p minimald oom_ended_box_records_exited_reason_oom
  - WHEN an OOM kill ends a box THE SYSTEM SHALL return 137 from `min run` and from `min box wait` for that box.
    tier:   T0
    verify: ./scripts/session-e2e.sh oom_ended_box_run_and_wait_return_137

- **BRES-049** WHILE `minimald` is running THE SYSTEM SHALL read `/proc/pressure/memory` and each box leaf's `memory.events` every 5 seconds, reading the machine-wide `/proc/pressure/memory` on `local0` as well as in the guest.
  tier:     T0
  verify:   cargo nextest run -p minimald sampler_reads_psi_and_leaf_events_every_5s

- **BRES-050** WHEN a box leaf's `oom_kill` count increases THE SYSTEM SHALL emit one `WARN` naming the box's id and name, its kill count this boot, and the kernel's task name when `kmsg` still carries it, emitting one `WARN` with their count for kills within one sampler tick, from `minimald` outside the box.
  tier:     T1
  verify:   cargo nextest run -p minimald prop_oom_kill_increase_emits_one_warn_per_tick
  property: Any increase of any leaf's `oom_kill` count produces exactly one `WARN` for that tick, and a leaf whose count did not rise produces none.
  - THE SYSTEM SHALL omit the killed process's command line from every OOM-kill `WARN`, enforced by `minimald` outside the box.
    tier:   T0
    verify: cargo nextest run -p minimald oom_kill_warn_never_carries_command_line
    property: No OOM-kill `WARN` ever carries a command line.

- **BRES-051** WHEN memory pressure `some avg10` has stayed at or above 25% across samples whose timestamps span at least 30 seconds THE SYSTEM SHALL emit one `WARN` naming the pressure and the box leaf with the highest `memory.current`.
  tier:     T1
  verify:   cargo nextest run -p minimald prop_sustained_pressure_emits_warn_naming_top_box
  property: For every sequence of timestamped samples, the first pressure `WARN` of an episode is emitted exactly when `some avg10` has been at or above 25% across samples whose timestamps span at least 30 seconds, and names the leaf with the highest `memory.current` in that sample.

- **BRES-052** WHILE memory pressure `some avg10` stays at or above 25% THE SYSTEM SHALL repeat the pressure `WARN` at most once per 30 seconds.
  tier:     T1
  verify:   cargo nextest run -p minimald prop_pressure_warn_repeats_at_most_every_30s
  property: For every sequence of timestamped samples, no two pressure `WARN`s are less than 30 seconds apart.

- **BRES-053** WHEN `minimald` takes the first sample with memory pressure `some avg10` below 25% after a pressure `WARN` THE SYSTEM SHALL log one `INFO`.
  tier:     T1
  verify:   cargo nextest run -p minimald prop_pressure_clear_logs_one_info
  property: For every sequence of timestamped samples, exactly one `INFO` follows each episode that raised a `WARN`, at the first sample below 25%, and none follows an episode that raised none.

- **BRES-054** IF an OOM kill happened while `minimald` was not sampling, or has scrolled out of `kmsg`, THEN THE SYSTEM SHALL count it from the cumulative `memory.events` counters and emit its `WARN` at the next tick, keying each leaf's previous snapshot on the leaf's identity, a generation `minimald` assigns each time it creates the leaf, so that a leaf created again (on resume) is counted from zero whatever its counter reads.
  tier:     T1
  verify:   cargo nextest run -p minimald prop_missed_oom_kills_counted_at_next_tick
  property: For every sequence of cumulative `oom_kill` snapshots keyed by leaf generation, however many ticks lie between them, and including a box's leaf removed and created again under a new generation with a counter below, equal to or above the old one, the next tick reports for each generation exactly its count minus that generation's previous snapshot, or its whole count for a generation with no previous snapshot, so no kill is lost or counted twice.
  - WHEN `minimald` removes a box's leaf THE SYSTEM SHALL read the leaf's `memory.events` once more first, account any `oom_kill` increase since the last sample, and then drop that generation's snapshot, so a kill between the last tick and the box's end is not lost and no later leaf is compared against it.
    tier:   T0
    verify: cargo nextest run -p minimald leaf_removal_accounts_final_oom_kills

- **BRES-055** THE SYSTEM SHALL emit the pressure and OOM-kill log lines as `tracing` events with the structured fields `box_id`, `box_name`, `oom_kills`, `task` and `psi_some_avg10`.
  tier:     T0
  verify:   cargo nextest run -p minimald memory_log_events_carry_structured_fields

- **BRES-056** WHEN `minimald` observes an OOM kill, or a coalesced burst of them, THE SYSTEM SHALL write one `oom_killed` event into the box record beside the log line, carrying the kernel's task name when known and the count, written by `minimald` into the record outside the box filesystem (BOX-040), where nothing in the box can append.
  tier:     T1
  verify:   cargo nextest run -p minimald prop_oom_kill_writes_one_oom_killed_event_per_burst
  property: For every tick, exactly one `oom_killed` event is produced for each leaf whose `oom_kill` count rose, carrying the rise as its count, and none for any other leaf.
  - THE SYSTEM SHALL omit the killed process's command line from every `oom_killed` event, enforced by `minimald` outside the box.
    tier:   T0
    verify: cargo nextest run -p minimald oom_killed_event_never_carries_command_line
    property: No `oom_killed` event ever carries a command line.

- **BRES-057** WHEN `min box events <box>` runs THE SYSTEM SHALL replay the box's `oom_killed` events.
  tier:     T0
  verify:   ./scripts/session-e2e.sh box_events_replays_oom_killed

- **BRES-058** WHERE `min` runs inside a box (#568), WHEN `min box events --parent self` runs in a parent box THE SYSTEM SHALL show a child box's `oom_killed` event.
  tier:     T0
  verify:   ./scripts/session-e2e.sh box_events_parent_self_shows_child_oom_killed

- **BRES-059** WHILE two session boxes are live, WHEN a process in box A allocates without bound and the kernel kills it THE SYSTEM SHALL leave exactly one `oom_killed` event per coalesced burst on A's stream and none on B's.
  tier:     T0
  verify:   cargo nextest run -p minvmd box_oom_isolation_event_stream_integration

- **BRES-060** WHEN a box's `oom_killed` event is written THE SYSTEM SHALL deliver, within one sampler tick, one notice line (a newline, the message, a newline) naming the kernel's task name when known and the box's limit to every PTY attached to the box, from `minimald`'s pty pump outside the box.
  tier:     T0
  verify:   ./scripts/session-e2e.sh oom_notice_on_every_attached_pty
  - THE SYSTEM SHALL deliver the OOM notice on the PTY's output and never write it into the shell's input, from `minimald`'s pty pump outside the box.
    tier:   T0
    verify: ./scripts/session-e2e.sh oom_notice_never_written_to_shell_input
    property: No OOM notice is ever written into a shell's input.

- **BRES-061** WHILE no PTY is attached to a box, WHEN its `oom_killed` event is written THE SYSTEM SHALL keep only the latest notice and print it on the next attach before the shell paints.
  tier:     T0
  verify:   ./scripts/session-e2e.sh oom_notice_held_for_next_attach

- **BRES-062** WHEN the kernel kills a process started by a non-interactive `min session exec`, `min session run` or `min task run` THE SYSTEM SHALL deliver no OOM notice to that caller.
  tier:     T0
  verify:   ./scripts/session-e2e.sh non_interactive_oom_gets_no_notice
  - WHEN the kernel kills a process started by a non-interactive `min session exec`, `min session run` or `min task run` THE SYSTEM SHALL return the kernel's exit status for that process to the caller.
    tier:   T0
    verify: ./scripts/session-e2e.sh non_interactive_oom_returns_kernel_exit_status

- **BRES-063** THE SYSTEM SHALL extend the `resource_pool` in the session-list response, filled by `minimald`, with `memory_available_bytes`, `swap_total_bytes`, `swap_free_bytes`, `oom_kills_this_boot` and `psi_some_avg10`, adding no new RPC.
  tier:     T0
  verify:   cargo nextest run -p minimald-rpc resource_pool_carries_memory_fields

- **BRES-064** WHEN `min ls` runs THE SYSTEM SHALL extend its `RESOURCE POOL:` line to `… memory <available> of <total> free · swap <free> of <total> · <n> OOM kills this boot`.
  tier:     T0
  verify:   cargo nextest run -p minimal ls_resource_pool_line_shows_memory_swap_oom
  - WHEN `min ls --json` runs THE SYSTEM SHALL carry the new memory fields under `resource_pool` and leave the rest of its shape unchanged.
    tier:   T0
    verify: cargo nextest run -p minimal ls_json_resource_pool_adds_memory_fields_only

- **BRES-065** WHILE the VM is running THE SYSTEM SHALL include in `minvmd status --json` a `memory` object with the fields of BRES-063, read from the guest over the existing oneshot RPC and separate from spec 09's `metrics` object.
  tier:     T0
  verify:   cargo nextest run -p minvmd status_json_memory_object_from_guest_integration
  - WHILE the VM is stopped THE SYSTEM SHALL report `memory` as `null` in `minvmd status --json`.
    tier:   T0
    verify: cargo nextest run -p minvmd status_json_memory_null_when_stopped

- **BRES-066** THE SYSTEM SHALL compute the memory figures of BRES-063 and BRES-065 from `/proc/meminfo`, `/proc/vmstat` and `/proc/pressure/memory` as `minimald` sees them, not from the VMM's RSS, so that on `local0` they cover the whole machine.
  tier:     T0
  verify:   cargo nextest run -p minimald memory_figures_read_from_proc_not_vmm_rss

- **BRES-067** WHEN `min host list` or `min host show` renders `local0` or `local-minvmd0` THE SYSTEM SHALL carry its memory capacity, allocatable, allocated, default box size, overcommit policy and memory enforcement (`enforced` or `advisory`), and carry them as fields under `-o json`.
  tier:     T0
  verify:   cargo nextest run -p minimal host_show_carries_memory_figures

- **BRES-068** WHEN `min box show <box>` runs THE SYSTEM SHALL carry the box's memory limit and its source (`entry` or `default`), its reservation, its current use (`memory.current`) and its OOM kill count.
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_carries_memory_fields
  - WHILE a box's host reports `advisory` THE SYSTEM SHALL mark the box's limit and reservation advisory in `min box show`, including under `-o json`, or only its reservation where BRES-077 applies.
    tier:   T0
    verify: cargo nextest run -p minimal box_show_marks_advisory_limit_and_reservation

- **BRES-069** WHERE `min` runs inside a box (#568) THE SYSTEM SHALL carry in `min box show self` the memory fields of BRES-068, including its advisory mark.
  tier:     T0
  verify:   ./scripts/session-e2e.sh box_show_self_carries_memory_fields

- **BRES-070** THE SYSTEM SHALL report a host's memory enforcement as `enforced` only when the host holds a delegated memory controller delivering each box's limit and the cap on the boxes subtree and the effective protection along the boxes subtree's ancestor chain can deliver its reservations (BRES-076), and as `advisory` otherwise, so that `local0` reports `enforced` with a delegated subtree whose ancestors protect its allocatable, and `advisory` without a delegated subtree or without that protection, decided by the Box Host daemon from what it detects, on the host side of TB2.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_memory_enforcement_follows_delegation_root_integration

- **BRES-071** THE SYSTEM SHALL offer no configuration key that sets a host's memory enforcement.
  tier:     T0
  verify:   cargo nextest run -p minimald no_config_key_sets_memory_enforcement

- **BRES-072** THE SYSTEM SHALL report `local-minvmd0`'s memory enforcement as `enforced`.
  tier:     T0
  verify:   cargo nextest run -p minvmd local_minvmd0_reports_enforced_integration

- **BRES-073** WHILE a host reports `advisory` THE SYSTEM SHALL admit a box by the same fit and reservation accounting as an enforced host, whether or not its `ram` is written, and apply no memory limit to it, except on `local0` as BRES-077 states.
  tier:     T0
  verify:   cargo nextest run -p minimald advisory_host_admits_by_accounting_without_limit

- **BRES-074** WHILE a host reports `advisory`, WHEN a box is created on it THE SYSTEM SHALL print a warning on stderr that the box's memory is not protected, or, where BRES-077 applies, that its reservation is not protected.
  tier:     T0
  verify:   cargo nextest run -p minimal advisory_host_create_warns_on_stderr

- **BRES-075** WHERE the host delegates a cgroup2 subtree with the memory controller enabled to the native `minimald`, WHEN `minimald` creates a box's leaf on `local0` THE SYSTEM SHALL set the leaf's `memory.swap.max` to 0 unless every swap device enabled on the host is a zram device or a dm-crypt device keyed fresh at each boot (a `/dev/urandom` key in `/etc/crypttab`, so the key never outlives the boot), so that box memory never reaches a plaintext swap partition or swap file on the developer's disk, enforced by the native `minimald` and the kernel outside the box, on the host side of TB2 on the developer's machine (no TB3), inside a subtree the host's cgroup manager delegates, against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_leaf_swap_max_zero_unless_host_swap_zram_or_encrypted_root_integration

- **BRES-076** WHERE the host delegates a cgroup2 subtree with the memory controller enabled to the native `minimald` THE SYSTEM SHALL count `local0`'s reservations as deliverable only when the kernel's effective protection for the boxes subtree can reach `local0`'s allocatable: every ancestor above the delegated subtree, up to but not including the cgroup root, carries a `memory.min` of at least that allocatable (a `MemoryMin=` on the delegating unit and on each slice above it), at each of those levels the `memory.min` claimed by the chain's cgroup and its siblings together is at most their parent's, so no sibling dilutes the protection the kernel distributes, and every cgroup between the delegated subtree's root and the boxes subtree carries one too or cgroup2 is mounted with `memory_recursiveprot`, decided by the Box Host daemon from what it reads, on the host side of TB2.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_reservations_advisory_without_ancestor_protection_root_integration

- **BRES-077** WHILE `local0` holds a delegated memory controller but reports `advisory` because its reservations cannot be delivered (BRES-076) THE SYSTEM SHALL still write each box's leaf `memory.max` and the boxes subtree's `memory.max`, and mark only the box's reservation advisory, enforced by the native `minimald` and the kernel outside the box, on the host side of TB2 on the developer's machine (no TB3), against every process in the box including root inside it.
  tier:     T0
  verify:   cargo nextest run -p minimald local0_reservation_advisory_keeps_limits_root_integration

- **BRES-078** IF the host's default box size, one half of its allocatable, is below 256 MiB THEN THE SYSTEM SHALL refuse a box whose `ram` is omitted or `"auto"` at admission with exit 8 and the figures of BRES-035, with the remedy: write a `ram` that fits, or give the host more memory, enforced by the Box Host daemon at admission, on the host side of TB2.
  tier:     T2
  verify:   cargo nextest run -p minimald default_box_size_below_256mib_refused_exit_8
  property: For every allocatable, a box whose `ram` is omitted or `"auto"` is admitted only when one half of that allocatable, rounded down, is at least 256 MiB, so no box is admitted at a default size below 256 MiB.
  harness:  `crates/sessions/src/core/admission.rs` `kani_default_box_size_floor_refuses_below_256mib`, 8 boxes in all (7 counted plus the new one), symbolic `u64` byte sizes, `#[kani::unwind(9)]`

## Non-goals

- **Live VM resize and vcpu hot-add:** never done; guest RAM is resolved at boot (spec 01 and
  spec 09 non-goals, reaffirmed by the architecture's Box Resources › Guest memory).
- **A large guest returning memory it no longer uses:** a SHOULD in the architecture's Box
  Resources › Guest memory; S1 is complete without it and it lives there until a spec takes it.
- **Workstation paging of the VM's memory:** the guest's swap requirements cover the guest; whether the
  physical host pages guest memory, zram pages included, is an architecture gap (Open
  questions).
- **Remote hosts:** the architecture expects them to inherit these rules and report the same
  fields; nothing here tests one (Open questions, and a later spec when a remote Box Host
  ships).
- **The provider's `ram` quota, exit 5:** Box Provider API §5 and gominimal/arch#45.
- **A memory budget carried down a nesting chain, and the nested-box reservation cap, exit 5:**
  architecture open gap 20; nesting itself is gominimal/inbox#568.
- **Policy that requires `enforced` hosts:** architecture open gap 21.
- **`cpus` and `disk` enforcement beyond fit:** architecture open gap 18 (gominimal/arch#96 Q2).
- **How a Box Type may bound these quantities:** architecture open gap 19.
- **The kernel's OOM policy inside a box (`oom_score_adj`):** the kernel's; untouched.
- **zram in the guest kernel:** an upstream prerequisite in the guest kernel's own build, not a
  behaviour of this spec (Open questions); BRES-007 and BRES-009 observe it.
- **A `min status` verb:** `min ls` carries the headroom line instead (BRES-064).
- **Host-side pressure thresholds from the VMM's RSS:** spec 09 removed them as unmeasurable.
- **The box record, its event stream, the `[machine]` and `[execution]` expansion path, and the
  `min box` and `min host` grammar:** the BOX and BCLI specs for gominimal/inbox#731; this spec
  gives those surfaces their memory meaning.
- **The `min bug` bundle's memory diagnostics:** gominimal/inbox#597, which collects the
  `derived` source (BRES-004) and the structured events (BRES-055).
- **Sandbox hardening:** gominimal/inbox#503; the per-box leaf is compatible with it and does not
  depend on it.

## Design reasoning

**One document, with the guest kernel as a prerequisite.** Every behaviour here lands in the
CLI, the host VM daemon or the Box Host daemon, so the epic is one spec. The one change outside
them is zram in the guest kernel. BRES-007 and BRES-009 stay at T0 on the KVM lane and fail there
until the guest kernel ships zram, which Open questions names as an upstream prerequisite. Tier
`none` for the swap requirements was rejected because nothing would then ever test swap, and a
sibling spec for open gap 21 was rejected as widening the epic's scope.

**Running boxes count toward allocated.** Admission sums the reservations of the host's running
boxes (BRES-039, BRES-041). Keeping a stopped, resumable box's reservation until it exits or is
removed was rejected because idle stopped sessions would hold memory nobody is using.
Re-admitting a box on resume was rejected because resume could then fail with exit 8, the outcome
the box volume spec rejected for its write hold. Which way a stopped box goes is Open questions
(HIGH). The admission core leaves the choice of which boxes count to its caller, so the answer
changes the caller and not the proofs.

**The controls sit outside the box and hold against its root.** The limit, the rule that a box
cannot raise it, the subtree cap and the join before namespaces are enforced by the Box Host
daemon and the kernel, outside the box: on the host side of TB2, which is inside the guest on
`local-minvmd0` and on the developer's machine on `local0`. They hold against root inside the
box. Nothing is claimed after a box escapes into its Box Host; Security considerations records
that as a residual beside AT26. Counting the VM's fixed size as a bound that survives escape was
rejected as new scope, and limiting only a box's ordinary processes was rejected, as it was for
the BOX spec.

**Swap is a guest-only claim.** BRES-007, BRES-008 and BRES-010 say what the guest does with
swap. Whether the workstation pages the VM's memory, zram pages included, to its own swap is
outside the guest, and it goes to the architecture as an Open question. Having the host VM
daemon pin guest memory was rejected because it conflicts with a guest returning memory it no
longer uses. Declaring workstation paging out of scope was rejected as a decision nobody would
revisit.

**On a small x86_64 host the constant wins and the source reads `derived`.** Just above 4 GiB,
the cap that keeps 4 GiB for the machine outside falls below today's constant. The constant wins
(BRES-001), and the source reads `derived` (BRES-006) because the derivation ran. Reading
`default` whenever the result equals the constant was rejected because it widens the epic's
condition. Letting the reserve win was rejected because it breaks "small hosts keep current
behaviour".

**The same counters on both hosts.** The sampler and the `min ls` figures read the files the
epic names on both hosts (BRES-049, BRES-066), so on `local0` they cover the whole machine (Open
questions). Reading the boxes subtree's own counters on `local0` was rejected: it is a second
code path, and an `advisory` `local0` would still read the whole machine. Keeping machine-wide
figures on `min ls` and subtree figures for the `WARN` was rejected because it gives one host two
meanings of pressure.

**A script learns that a host is `advisory` from `show`.** Creation on an `advisory` host warns
on stderr (BRES-074), and a script reads the advisory mark from `min box show -o json` or
`min host show -o json` (BRES-067, BRES-068). gominimal/arch#96 Q4 stays open. An `advisory`
field on creation's machine output was rejected because it adds a field to a verb the BOX spec
owns. An event on the box's stream was rejected because it is not in BOX-040's event list.

**One requirement per behaviour, with its halves nested.** A "never" clause and the second
surface of a two-surface behaviour are sub-bullets under their parent, as in the BOX spec. One id
per half was rejected: a failing test already names the half, and the split cost ten more ids.
The per-box leaf rules are written once, "on either local host", with a test on each lane
(BRES-014, BRES-015, BRES-016, BRES-017), and `local0` keeps only its own subtree cap (BRES-026). A second
set of the same rules for the native lane was rejected because one host's proof would then stand
alone.

**The `cpu_arch` refusal states exit 8 and nothing more.** BRES-033 does not reuse
`insufficient_resources` and its "omit `ram`" remedy, which would mislead for an architecture
mismatch. The architecture's checks table has no `cpu_arch` row, so the code and the remedy are
an architecture gap (Open questions).

**Pressure clears at the first sample below 25%.** BRES-053 logs its `INFO` there. Requiring
30 seconds below was rejected because it adds timer state for no reader.

**Mechanisms the requirements leave out.** The guest has no systemd, so the Box Host daemon
mounts cgroup2 itself (BRES-011) and does not use the sandbox library's cgroup manager, which
hardcodes a systemd slice. The sampler (BRES-049) is its own 5-second task beside the maintenance
actor rather than inside it, because the actor's 6-hour interval and 5-minute startup delay are
wrong for a pressure signal. Smaller translation calls, each the first reading offered: the hole
range is 3073–6143 MiB inclusive (BRES-002); a leaf's `memory.min` is stated at leaf creation
(BRES-014) and once more for enforced hosts (BRES-040); `min` owns the exit-3 checks and the
manifest parser accepts the `on_oom` values (BRES-029, BRES-030, BRES-042); a killed
non-interactive process's exit status passes through unchanged (BRES-062); nested or other-valued
`[machine]` keys stay with the BOX spec's acceptance.

**Verification tiers, and the constraint each one places on code not yet written.** T3 is refused
throughout: there is no Lean project, and most of these requirements reach the kernel.

- The guest RAM derivation (BRES-001, BRES-002, BRES-006) is T1, a property test over host size
  and architecture: the derivation must be a pure function of host memory and architecture that
  returns the size and its source, with the configuration and the memory read in its caller. Edge
  tables at T0 were rejected because they miss any edge nobody listed; Kani at T2 was rejected
  because the function would have to move onto the Kani lane.
- The expansion checks (BRES-029, BRES-030) are T1, as decided for the BOX spec: the size parser
  must be a pure function whose error carries the hint and whose multiplication is checked, with
  the exit-code mapping outside it.
- The admission core (BRES-031, BRES-034, BRES-035, BRES-037, BRES-038, BRES-039, BRES-078) is
  T2, Kani harnesses beside the existing session-core proofs, which takes that lane's expected
  harness count from 8 to 16: admission must be a pure decision over owned values with no enforcement
  input, summing with checked addition so an overflow refuses, while its caller chooses which
  boxes count. The same shape makes BRES-073's "same accounting on an `advisory` host" and
  BRES-035's "never names another box" hold by construction. BRES-033 stays T0, one equality.
- The Kani bound is `#[kani::unwind(9)]` claiming 8 boxes in all, following the repository's
  convention of one extra unwind per loop. Unwind 8 claiming 7 boxes was rejected.
- The subtree's `memory.min` (BRES-041) is T2 over at most 8 admit and exit steps, cut to 4 if
  CI time objects: the write must take `allocated` from the admission core, and every exit path,
  a failed start's rollback included, must call the core's release. T0 was rejected because a
  forgotten release path would be caught only by an integration run.
- OOM-kill accounting (BRES-050, BRES-054, BRES-056) is T1: it must be a pure function from the
  previous and current counter snapshots, keyed by leaf generation, to bursts, and a burst has no
  command-line field. Scripted
  T0 sequences were rejected.
- The pressure tracker (BRES-051, BRES-052, BRES-053) is T1: it must be a pure state machine fed
  timestamped samples of `some avg10` and the top leaf, with no clock inside it. Scripted T0
  sequences were rejected.
- BRES-071 is T0: the enforcement decision's signature must take detection results only, so no
  configuration can reach it.
- BRES-020, BRES-024, BRES-025, BRES-028 and BRES-059 stay T0 because each is one scenario, two
  boxes and one kill, with nothing to quantify over. The universal behind them is the hard
  constraint in Security considerations, and the kernel enforces it.

Seven requirements state a universal that stays at T0, and it is written here rather than as a
`property:` line because it is not what the named test samples:

- BRES-008: no volume that persists or is snapshotted ever holds swap. The volumes a guest mounts
  cannot be generated, and the named test checks that every entry of the guest's `/proc/swaps` is
  a zram device, which is the whole list at run time.
- BRES-010: no process in the daemon's cgroup is ever swapped. That is the kernel's claim given
  `memory.swap.max` = 0, and the test reads the value.
- BRES-018: on an `enforced` host no box ever runs without its leaf. The ordering is an effect
  sequence against cgroupfs, and a generator over kernel write failures would test a fake.
- BRES-019: every box the guest daemon starts has a leaf, whatever its type. The named test
  iterates all six Box Types, which is exhaustive.
- BRES-032: for every written `ram`, the leaf's `memory.max` reads back as that value rounded down
  to the host page size. The decision is the identity, so a harness proves nothing; the risk is in
  the write path and the kernel.
- BRES-060: every PTY attached when the event is written receives exactly one notice. Delivery is
  the pty pump's concurrent fan-out, which is not a pure decision; the end-to-end case attaches two
  PTYs.
- BRES-071: no configuration value changes a host's reported enforcement. It holds by the
  signature constraint above, and a property test over arbitrary configuration would test the
  signature.

Six findings from the tier pass were settled as assumptions. BRES-032 is worded at page
granularity, because the kernel keeps `memory.max` in pages. A `local0` whose capacity is at or
below its reserve has allocatable 0 and refuses every box with exit 8, reported by `min host show`
(BRES-034's sub-bullet); reporting it `advisory` instead is an Open question. The unit hint names
the same number with the IEC unit and says `8GB` is not `8GiB` (BRES-029). A leaf created again
on resume carries a new generation and is counted from zero (BRES-054).
"30 seconds" means samples whose timestamps span at least 30 seconds (BRES-051). The single-scenario
requirements stay T0.

**Generality:** only `local0` (with or without a delegated memory controller) and
`local-minvmd0`, the two hosts the lanes can run. Claiming any Box Host on the strength of these
two was rejected as wider than the tests, and claiming every host shape including advisory-only
ones was rejected as untestable here; a remote host is expected to inherit the rules unchanged,
and that is an Open question until one exists to test.

## Security considerations

The four controls below are the ones the architecture's "A box cannot loosen its own limit"
names. All four are enforced by the Box Host daemon and the kernel, outside the box, on the host
side of TB2: inside the guest on `local-minvmd0` (the guest side of TB3), and on the developer's
machine inside a subtree the host's cgroup manager delegates on `local0` (no TB3). They hold
against root inside the box.

- **Invariant:** THE SYSTEM SHALL hold every process in a box, root inside it included, to that
  box's memory limit.
  enforced by: the per-box leaf's `memory.max`, written by the Box Host daemon at box start and
  enforced by the kernel; a leaf that cannot be written fails the start
  covered by: BRES-014, BRES-018, BRES-019, BRES-032
- **Invariant:** THE SYSTEM SHALL never let a process inside a box raise or remove its own
  limit.
  enforced by: the leaf is the root of the box's cgroup namespace, and its limit files are not
  writable from inside
  covered by: BRES-016, BRES-017
- **Invariant:** THE SYSTEM SHALL keep the boxes together within the host's allocatable, with the
  daemon and the pty pumps outside that bound.
  enforced by: the boxes subtree's `memory.max` at allocatable and its `memory.min` at allocated,
  written by the Box Host daemon, which stays outside the subtree
  covered by: BRES-012, BRES-013, BRES-026, BRES-041
- **Invariant:** THE SYSTEM SHALL place every process the daemon starts on a box's behalf in that
  box's leaf before it enters any of the box's namespaces.
  enforced by: the pid is written to the leaf's `cgroup.procs` before `setns` or `unshare`, by
  the attach path, the exec shim, the run and task container setup, and the hook runner
  covered by: BRES-015, BRES-021, BRES-022, BRES-023

The epic's hard constraint follows from those four:

- **Invariant:** THE SYSTEM SHALL, on a host that reports `enforced`, confine every out-of-memory
  kill caused by a box reaching its own `memory.max` to that box, and every kill caused by the
  boxes subtree reaching allocatable to the boxes subtree, never the daemon.
  enforced by: the kernel's OOM killer, which acts within the cgroup whose limit was reached;
  Minimal itself never kills for memory, clamps or shrinks a size
  covered by: BRES-012, BRES-020, BRES-024, BRES-025, BRES-028, BRES-032, BRES-044, BRES-045,
  BRES-046

The other invariants:

- **Invariant:** THE SYSTEM SHALL keep a box's swapped memory unreadable once the boot that
  wrote it ends. In the guest that is zram; on `local0` a box's leaf may swap only where every
  host swap device is zram or encrypted under a per-boot key. Whether the physical host pages the VM's memory is an
  Open question.
  enforced by: zram created by the Box Host daemon at guest boot; no swap on any volume that
  persists or is snapshotted; the daemon's own cgroup never swaps; on `local0`, a leaf
  `memory.swap.max` of 0 over any other host swap
  covered by: BRES-007, BRES-008, BRES-010, BRES-075
- **Invariant:** THE SYSTEM SHALL never reveal another box's name or owner in a refusal, nor a
  killed process's command line in a log line or event.
  enforced by: the admission core takes other boxes' reservations as bare numbers, and an OOM
  burst carries no command-line field
  covered by: BRES-035, BRES-050, BRES-056 (their sub-bullets)
- **Invariant:** THE SYSTEM SHALL report a host `enforced` only when it can deliver the per-box
  limit, hard reservations and the subtree cap.
  enforced by: detection in the Box Host daemon, including the effective protection along the
  boxes subtree's ancestor chain on `local0`, with no configuration key that sets it
  covered by: BRES-070, BRES-071, BRES-072, BRES-076

**Residual, beside AT26.** The architecture presumes a box can escape into its Box Host (Box
Isolation Model). All four controls sit on the host side of TB2, so a box that crosses TB2 is
outside every one of them, and this spec claims nothing about memory after that escape. AT26's
own residuals (overcommit, swap contention, and an `advisory` host enforcing none of this) stand
unchanged. Two follow from the hard constraint's scope: when overcommitted boxes together reach
allocatable, the kernel may kill in a box other than the one that grew, protected only by each
box's `memory.min`; and on `local0` a machine-wide OOM caused by processes outside the boxes
subtree is outside every claim here, since the reserve is a figure admission subtracts, not a
limit on the rest of the desktop.

## Open questions

- [NEEDS CLARIFICATION (HIGH): Does a stopped, resumable box keep its reservation in the host's
  allocated? Admission counts running boxes today (BRES-039). Keeping it until exit or removal
  holds memory for idle sessions; re-admitting on resume lets resume fail with exit 8.]
- [NEEDS CLARIFICATION (MEDIUM): Remote hosts. The architecture expects them to inherit these
  rules and report the same fields, but nothing here tests one, and the Generality line claims
  only `local0` and `local-minvmd0`.]
- [NEEDS CLARIFICATION (MEDIUM): Architecture gap — the physical host paging the VM's memory,
  zram pages included, to its own swap. The architecture's Swap rules are silent on the host side
  of TB3, and this spec's swap claim is guest-only.]
- [NEEDS CLARIFICATION (MEDIUM): Architecture gap — the `cpu_arch` refusal's machine-form code
  and remedy. The checks table has no `cpu_arch` row; BRES-033 states exit 8 only.]
- [NEEDS CLARIFICATION (MEDIUM): Upstream prerequisite — the guest kernel does not carry zram
  today. BRES-007 and BRES-009 fail on the KVM lane until the guest kernel's build enables it.]
- [NEEDS CLARIFICATION (LOW): gominimal/arch#96 Q1 — how exit 8 maps to a remote provider's
  `RESOURCE_EXHAUSTED`. On the two local hosts the Box Host daemon refuses and `min` prints
  `min/v1/error` with exit 8 (BRES-035).]
- [NEEDS CLARIFICATION (LOW): gominimal/arch#96 Q4 — whether a scripted caller should learn in
  the creating call that an `advisory` host waived its written `ram`. Today it reads the mark from
  `min box show` or `min host show` (BRES-067, BRES-068).]
- [NEEDS CLARIFICATION (LOW): On `local0` the pressure `WARN`, `min ls`'s memory, swap and
  OOM-kill figures read machine-wide counters (BRES-049, BRES-066), so a desktop process's
  pressure or OOM kill counts. Whether `local0` should read the boxes subtree's own counters is
  open.]
- [NEEDS CLARIFICATION (LOW): A `local0` whose capacity is at or below its reserve takes
  allocatable 0 and refuses every box (BRES-034). The alternative is to report it `advisory`.]
- [NEEDS CLARIFICATION (MEDIUM): Architecture gap — the Swap rule is written for the guest. It
  says swap is unreadable once the boot ends and the host's own processes never swap, but not
  what a box on `local0` may swap to when the desktop's swap is a plaintext partition or file.
  Proposed for the architecture: on `local0` a box swaps only where the host's swap is zram or
  encrypted under a per-boot key, and otherwise its swap allowance is 0 (BRES-075).]
- [NEEDS CLARIFICATION (MEDIUM): Architecture gap — allocatable is capacity minus the Box Host's
  reserve, and swap held in memory is not counted. zram's compressed pages are charged to no
  memory cgroup, so boxes that swap can push the guest past its reserve into a global OOM.
  Proposed for the architecture: a host whose swap lives in memory subtracts its worst-case
  footprint from allocatable as well, as BRES-012 does with the zram `mem_limit` of BRES-007.]
- [NEEDS CLARIFICATION (MEDIUM): Architecture gap — memory enforcement is one value covering all
  three guarantees. A `local0` that delivers each box's limit and the subtree cap but not its
  reservations reports `advisory` and still applies the limits (BRES-077), which BRES-073 and the
  architecture's "an `advisory` host enforces none of the three" do not otherwise allow. Proposed
  for the architecture: let an `advisory` host apply the guarantees it can deliver and mark the
  rest, or report enforcement per guarantee.]
