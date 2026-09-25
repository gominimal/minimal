---
id: BRES
title: Box resources — declared per box, admitted by the host, enforced where the host can
owner: mitodrummer
epic: gominimal/inbox#731
arch: https://github.com/gominimal/arch/blob/main/architecture.md#box-resources
updated: 2026-09-25
---

# BRES — Box resources — declared per box, admitted by the host, enforced where the host can

## Context

The architecture of record now says what a box needs from its host: `[machine]` carries `cpu_arch`, `cpus`, `ram`, `ram_reserved` and `disk`, `ram` is also the box's memory limit, and the host refuses a box it cannot hold (Box Resources, proposed in gominimal/arch#92). Nothing of it ships today. `minimal.toml` has no `[machine]` keys, the daemon admits every box without checking the host's memory, and a box on a native host runs with no per-box limit, so one runaway build can squeeze the daemon and the developer's desktop. The VM path's cgroup work (the cgroup2 mount, a leaf per session, the daemon's own reservation) belongs to the guest-memory epic, gominimal/inbox#698, whose S3b waits on the admission this spec adds.

After this ships, every box declares its size or takes the host's default, the host admits it only when the size and the summed reservations fit, a refusal says which dimension missed and by how much, and on a host that can enforce memory each box meets its own ceiling. A host that cannot enforce says so rather than pretending.

**Success:** on `local0` and `local-minvmd0`, a box whose `ram` the host cannot hold is refused with exit 8 and the host's figures; a box that allocates past its `ram` on an `enforced` host is killed inside its own cgroup with an `oom_killed` event, while the daemon and other boxes keep answering; and `min host show` reports `enforced` or `advisory` from what the host can do.

**First slice:** the `[machine]` keys are accepted and validated at expansion (BRES-001 to BRES-003), and the daemon on `local0` admits or refuses with exit 8 against its allocatable memory (BRES-004, BRES-005), with no cgroup change.

## Users and stories

**Roles:** developer running several boxes on one laptop

- AS A developer running several boxes on one laptop, I WANT each box's `ram` to be a real memory limit and the host to refuse a box it cannot hold, SO THAT one runaway box hits its own ceiling and never squeezes the daemon or my desktop.

## Requirements

- **BRES-001** THE SYSTEM SHALL accept `[machine] cpu_arch`, `cpus`, `ram`, `ram_reserved` and `disk`, and `[execution] on_oom` (`kill_process` or `end_box`), flat on an entry, with sizes in IEC units only.
  tier:     T0
  verify:   cargo nextest run -p mfile machine_keys_flat_iec_units

- **BRES-002** IF a size is written in a non-IEC unit THEN THE SYSTEM SHALL fail with exit 3 and a did-you-mean hint.
  tier:     T0
  verify:   cargo nextest run -p mfile non_iec_size_exit3_with_hint

- **BRES-003** IF `ram_reserved` exceeds a written `ram` THEN THE SYSTEM SHALL fail with exit 3.
  tier:     T2
  verify:   cargo nextest run -p mfile ram_reserved_over_ram_exit3
  property: For every ram and ram_reserved pair of u64 bytes, validation accepts iff ram_reserved <= ram, with no overflow.
  harness:  mfile `ram_reserved_le_ram_no_overflow` over `kani::any::<(u64,u64)>()`, unwind 1

- **BRES-004** WHEN a box is admitted THE SYSTEM SHALL check `cpu_arch` exactly and `cpus`, resolved `ram` and `disk` against the host's allocatable, and the summed reservations against allocatable, counting an omitted reservation as at most the box's resolved `ram`, without clamping or rounding.
  tier:     T2
  verify:   cargo nextest run -p minimald admission_checks_fit_and_reservations
  property: For every host allocatable and every set of boxes' reservations, admission admits a new box iff each dimension fits and the summed reservations, each omitted one capped at its box's resolved ram, do not exceed allocatable, computed without overflow.
  harness:  minimald/src/admission.rs `admit_iff_fit_and_reservations` over a host and at most 8 boxes of `kani::any::<u64>()` sizes, unwind 8

- **BRES-005** IF admission finds a dimension the host cannot hold THEN THE SYSTEM SHALL fail with exit 8 and `code = "insufficient_resources"`, carrying the dimension, the requested size and its layer, the host's allocatable and allocated, and the remedy.
  tier:     T2
  verify:   cargo nextest run -p minimald admission_miss_exit8_with_figures
  property: For every rejected admission, the error carries the first failing dimension, the requested size, and the host's allocatable and allocated figures.
  harness:  minimald/src/admission.rs `rejection_names_first_failing_dimension`, same bounds

- **BRES-006** WHEN `ram` is `"auto"` THE SYSTEM SHALL resolve it to the host's default box size and report in `min box show` the resolved limit and whether it came from the spec or the host.
  tier:     T0
  verify:   cargo nextest run -p minimald ram_auto_resolves_to_host_default

- **BRES-007** WHERE the host's memory enforcement is `enforced` THE SYSTEM SHALL place every box's memory cgroup in one boxes subtree capped at allocatable, with the daemon outside it, setting `memory.max` to the box's `ram` and `memory.min` to its reservation.
  - WHERE the enforced host is a VM THE SYSTEM SHALL apply the same subtree and limits inside the guest.
    tier:   T0
    verify: cargo nextest run -p minimald vm_boxes_subtree_memory_max_and_min
    <!-- runs on the VM lane (NET-107): the behaviour exists only with the VM host daemon in the loop -->
  tier:     T0
  verify:   cargo nextest run -p minimald boxes_subtree_memory_max_and_min
  <!-- a root integration test on a native `local0` with a delegated memory controller -->

- **BRES-008** WHERE the host's memory enforcement is `enforced` THE SYSTEM SHALL reject any write to a box's memory limit that originates from a process inside the box's namespaces, including one running as root inside the box.
  tier:     T0
  verify:   cargo nextest run -p minimald in_box_root_cannot_raise_memory_limit

- **BRES-009** THE SYSTEM SHALL run exec commands and lifecycle hooks in the box's own cgroup.
  tier:     T0
  verify:   cargo nextest run -p minimald exec_and_hooks_share_box_cgroup

- **BRES-010** IF the kernel kills a process in a box for memory THEN THE SYSTEM SHALL apply `on_oom` (`kill_process` or `end_box`, defaulted by type), record an `oom_killed` event naming the task name, and write a one-line notice to any attached PTY.
  tier:     T0
  verify:   cargo nextest run -p minimald oom_applies_on_oom_and_records_event

- **BRES-011** IF an OOM kill ends a box THEN THE SYSTEM SHALL record `exited.reason = "oom"` and return 137 from `min run` and `min box wait`.
  tier:     T0
  verify:   cargo nextest run -p minimald oom_ending_box_exits_137

- **BRES-012** THE SYSTEM SHALL decide `enforced` or `advisory` memory enforcement from the host's capabilities, never from configuration, and report it in `min host show` and `min box show`.
  tier:     T0
  verify:   cargo nextest run -p minimald memory_policy_from_capabilities_not_config

- **BRES-013** WHILE a native host has no delegated memory controller THE SYSTEM SHALL report `advisory`, apply no memory cgroup limit to its boxes, and still perform admission accounting.
  tier:     T0
  verify:   cargo nextest run -p minimald native_without_controller_is_advisory

- **BRES-014** THE SYSTEM SHALL render, in `min host list` and `min host show`, each host's capacity, allocatable, allocated, default box size and whether its memory enforcement is `enforced` or `advisory`.
  tier:     T0
  verify:   cargo nextest run -p minimal host_list_and_show_render_resource_figures

- **BRES-015** IF a written `ram_reserved` exceeds the `ram` that `"auto"` resolved to THEN THE SYSTEM SHALL fail admission with exit 8 and `code = "insufficient_resources"`, naming `ram` as the remedy.
  tier:     T0
  verify:   cargo nextest run -p minimald reserved_over_resolved_auto_ram_exit8

## Non-goals

- The guest VM's own size on `local-minvmd`: gominimal/inbox#698 S1.
- Swap in the guest: gominimal/inbox#698 S2; swap as host policy is the architecture's (Box Resources › Swap).
- The daemon's own memory reservation and the cgroup2 mount in the guest: gominimal/inbox#698 S3a-1.
- The provider's `ram` quota and the quota's other dimensions (exit 5): Box Provider API §5, gominimal/arch#45.
- Cedar decisions on `[machine]`: none; the architecture leaves `[machine]` out of the Gatehouse Box Spec projection (Policy layers and precedence), so resources are bounded without Cedar.
- The nested-box reservation cap (exit 5): nesting lands with gominimal/inbox#568.
- `cpus` and `disk` enforcement beyond fit: architecture open gap 18.

## Design reasoning

**Admission arithmetic is proved, not sampled.** BRES-003 is a T2 Kani harness over one `(ram, ram_reserved)` pair at unwind 1; BRES-004 and BRES-005 are T2 harnesses at unwind 8 over at most eight boxes, with no u64 overflow in the sums; the author chose this over a property test in `minimald` and over named cases at the boundaries. The cost is a constraint on code not yet written: the admission decision is a pure function over the request, the host's allocatable figures and the existing reservations, separate from the cgroup writes that follow it, and the Kani lane gains that `minimald` module and `mfile`.

**`enforced` or `advisory` comes from the host, never from configuration.** The architecture states this honesty rule (Box Resources › The host's side); this spec does not restate its rationale. BRES-012 makes it observable and BRES-013 keeps admission accounting on a host that cannot enforce, so a native `local0` without a delegated memory controller still refuses a box that does not fit.

**The escape claim covers in-box root.** BRES-008 is written for every process in the box's namespaces including one running as root inside, and is testable as such. Limiting it to ordinary processes was rejected as a weaker claim than the mechanism provides.

**The boxes subtree is tested on both enforced host kinds.** The subtree (BRES-007) exists on any `enforced` host: a native `local0` with a delegated memory controller, and the guest of a VM host. The native case is a root integration test in `minimald`; the VM case exists only with the VM host daemon in the loop, so its test names the VM lane (NET-107) rather than taking `tier: none`, which would have left the VM path unverified.

**Generality:** every requirement is written for any host a daemon runs on and exercised on `local0` and `local-minvmd0`; a remote host inherits them unchanged, and the architecture has every host report the same fields. What varies by host is only whether it can enforce, and that is reported rather than assumed (BRES-012), so a host with no memory controller fits as `advisory`.

## Security considerations

- **Invariant:** WHILE a host's memory enforcement is `enforced` THE SYSTEM SHALL keep every process in a box's namespaces, including in-box root, from raising that box's memory limit.
  enforced by: the box's memory cgroup is the root of its cgroup namespace, a process joins it before entering any of the box's namespaces, and its limits are not writable from inside (architecture Box Resources › One limit per box)
  covered by: BRES-008

## Open questions

- [NEEDS CLARIFICATION (HIGH): `cpus` and `disk` are fit-only here (BRES-004), checked one box at a time against allocatable, pending architecture open gap 18; gominimal/arch#96 question 2 notes that Box Provider API §5 instead makes them reservations summed in `allocated`, which would add a reservation-sum check for both.]
- [NEEDS CLARIFICATION (HIGH): where the exit 8 refusal lives, the daemon's `min/v1/error` surface or the provider API's `RESOURCE_EXHAUSTED` mapping (gominimal/arch#96 question 1). BRES-005 is written to the daemon's error surface.]
- [NEEDS CLARIFICATION (MEDIUM): gominimal/arch#96 questions 4 and 6 touch this spec: how a scripted caller learns that an `advisory` host waived a written `ram` (BRES-012, BRES-013), and whether `allocated` sums implied reservations or only written `ram_reserved` (BRES-004).]
- [NEEDS CLARIFICATION (HIGH): which side applies `memory.max`. gominimal/inbox#698 S3b has the guest daemon apply `[machine] ram` as its session leaf's bound and clamps a non-declared default to guest RAM minus the daemon reserve, while BRES-004 admits without clamping and BRES-007 sets `memory.max` in the boxes subtree. One of the two needs to cede the write and the clamp rule before either lands.]
- [NEEDS CLARIFICATION (HIGH): gominimal/inbox#698 S3a-2 has every exec process and every daemon-run lifecycle hook join the session leaf, which is BRES-009, and S3a-1 bind-mounts the leaf read-only, which overlaps BRES-008. Question for the owner: does BRES keep BRES-008 and BRES-009 with #698 reusing them, or do they become non-goals pointing at #698 S3a-1 and S3a-2?]
