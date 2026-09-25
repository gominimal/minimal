---
id: BVOL
title: Box Volumes — named, persistent, single-writer, locally backed
owner: mitodrummer
epic: gominimal/inbox#731
arch: https://github.com/gominimal/arch/blob/main/architecture.md
updated: 2026-09-25
---

# BVOL — Box Volumes — named, persistent, single-writer, locally backed

## Context

Every box starts from an empty filesystem, so package downloads and build caches are redone each time a box is created. The architecture of record defines the Box Volume for this: a named volume reused across box executions, with at most one writer and many readers of a point-in-time value, backed by object storage (Glossary › Box Volume; `volumes` on an entry in `box.toml`; `min volume list|show|rm|prune` in the command tree). Nothing of it ships today. The epic carried volumes as a stretch story, S19; the author promoted it to its own spec on 2026-09-25.

This spec is the first backing: a volume lives on the host that runs the box, in a directory under the host's state directory. The interface a developer sees, the `volumes` key and the `min volume` verbs, is the one the object-storage backing will serve, and does not change when it arrives.

**Success:** two boxes created one after the other from an entry declaring `volumes = ["cache"]` see the same files; a second writer is refused with exit 5 naming the holder; `min volume list` shows the volume's size, last use and users; and removing every box leaves the volume in place.

**First slice:** a declared volume is created on first use, mounted, and reattached by name in the next box (BVOL-001 to BVOL-003), listed by `min volume list` (BVOL-006), with no single-writer check yet.

## Users and stories

**Roles:** developer whose builds benefit from cached state across boxes

- AS A developer whose builds benefit from cached state across boxes, I WANT to declare a named volume on an entry that is created on first use, reattached by name, single-writer, and listable and removable on its own, SO THAT package downloads and build caches are not redone every time a box is created.

## Requirements

- **BVOL-001** WHERE an entry declares `volumes = ["<name>", …]` THE SYSTEM SHALL mount each named volume into every box created from that entry.
  tier:     T0
  verify:   cargo nextest run -p minimald declared_volume_is_mounted

- **BVOL-002** WHEN a box is created with a volume name the host does not hold THE SYSTEM SHALL create that volume on the host.
  tier:     T0
  verify:   cargo nextest run -p minimald first_use_creates_volume

- **BVOL-003** WHEN a box is created with a volume name the host already holds THE SYSTEM SHALL mount that existing volume with its contents.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_reattached_by_name_keeps_contents

- **BVOL-004** IF a box asks to write a volume that another box holds for writing THEN THE SYSTEM SHALL refuse the box with exit 5, naming the holding box.
  tier:     T0
  verify:   cargo nextest run -p minimald second_writer_refused_exit5_names_holder

- **BVOL-005** WHILE a box holds a volume for writing THE SYSTEM SHALL mount the volume in any number of other boxes that ask only to read it.
  tier:     T0
  verify:   cargo nextest run -p minimald readers_unlimited_while_writer_holds

- **BVOL-006** THE SYSTEM SHALL provide `min volume list`, `show`, `rm` and `prune [--unused-for <d>]`, rendering each volume's size, last use and the boxes that used it.
  tier:     T0
  verify:   cargo nextest run -p minimal volume_verbs_render_size_last_use_boxes

- **BVOL-007** IF `min volume rm` targets a volume a running box holds without `--force` THEN THE SYSTEM SHALL refuse and name `--force`.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_rm_held_needs_force

- **BVOL-008** WHEN `min box rm` or `min box prune` reaps a box that used a volume THE SYSTEM SHALL leave the volume and its contents in place.
  tier:     T0
  verify:   cargo nextest run -p minimald box_rm_keeps_volume

## Non-goals

- Object-storage backing and point-in-time readers: the architecture's Box Volume (Glossary › Box Volume); a second backing behind this interface.
- Sharing a volume across hosts: a local volume exists only on the host that created it; cross-host reuse arrives with the object-storage backing.

## Design reasoning

**A local directory first, the interface fixed.** The epic and the author's promotion of the story name the host's state directory as the first backing and require that the interface not change when object storage arrives. The requirements therefore speak of volumes the host holds, mounts and refuses, never of a directory or a path, so the second backing is a change beneath them rather than a rewrite of them.

**Generality:** a second backing fits because the requirements name the interface (the `volumes` key, the single-writer rule, the `min volume` verbs, survival past `min box rm`), not the directory.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never let two boxes hold one volume for writing at the same time.
  enforced by: the host daemon's writer hold on each volume, checked when a box is created
  covered by: BVOL-004

## Open questions

- [NEEDS CLARIFICATION (HIGH): the state directory path on each host kind and who owns the volume directories (the daemon's user, the box's user, or root); the epic's own note on S19 asks for this before sizing.]
- [NEEDS CLARIFICATION (HIGH): how an entry asks for read-only access to a volume; `volumes = ["<name>"]` carries no mode, and BVOL-004 and BVOL-005 need one to tell a writer from a reader.]
- [NEEDS CLARIFICATION (LOW): whether `min box rm` of the last box that wrote a volume should warn that the volume remains (BVOL-008).]
