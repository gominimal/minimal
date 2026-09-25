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

**Success:** in one project, a box created from an entry declaring `volumes = ["cache"]` after the previous such box is removed sees that box's files; a box of another project with the same declaration sees none of them; a second writer is refused with exit 5 naming the holder; `min volume list` shows the volume's size, last use and users; and removing every box leaves the volume in place.

**First slice:** a declared volume is created on first use, mounted, and reattached by project and name in the next box (BVOL-001 to BVOL-003), listed by `min volume list` (BVOL-006), with no single-writer check yet.

## Users and stories

**Roles:** developer whose builds benefit from cached state across boxes

- AS A developer whose builds benefit from cached state across boxes, I WANT to declare a named volume on an entry that is created on first use, reattached by name, single-writer, and listable and removable on its own, SO THAT package downloads and build caches are not redone every time a box is created.

## Requirements

- **BVOL-001** WHERE an entry declares `volumes = ["<name>", …]` THE SYSTEM SHALL mount each named volume at `/volumes/<name>` in every box created from that entry.
  tier:     T0
  verify:   cargo nextest run -p minimald declared_volume_is_mounted

- **BVOL-002** WHEN a box is created with a volume name its project does not yet hold on the host THE SYSTEM SHALL create that volume for the project on the host.
  tier:     T0
  verify:   cargo nextest run -p minimald first_use_creates_project_volume

- **BVOL-003** WHEN a box is created with a volume name its project already holds on the host THE SYSTEM SHALL mount that project's existing volume with its contents.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_reattached_by_project_and_name_keeps_contents

- **BVOL-004** IF a box declares `rw` access to a volume that another box holds for writing THEN THE SYSTEM SHALL refuse the box with exit 5, naming the holding box.
  tier:     T0
  verify:   cargo nextest run -p minimald second_writer_refused_exit5_names_holder

- **BVOL-005** WHILE a box holds a volume for writing THE SYSTEM SHALL mount the volume in any number of other boxes that declare it `ro`.
  tier:     T0
  verify:   cargo nextest run -p minimald readers_unlimited_while_writer_holds

- **BVOL-006** THE SYSTEM SHALL provide `min volume list`, `show`, `rm` and `prune [--unused-for <d>]`, rendering each volume's project, size, last use and the boxes that used it.
  tier:     T0
  verify:   cargo nextest run -p minimal volume_verbs_render_size_last_use_boxes

- **BVOL-007** IF `min volume rm` targets a volume that a box holds for writing without `--force` THEN THE SYSTEM SHALL refuse and name `--force`.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_rm_held_needs_force

- **BVOL-008** WHEN `min box rm` or `min box prune` reaps a box that used a volume THE SYSTEM SHALL leave the volume and its contents in place.
  tier:     T0
  verify:   cargo nextest run -p minimald box_rm_keeps_volume

- **BVOL-009** THE SYSTEM SHALL key every volume on its project and name, and never mount a volume created for one project into a box of another project.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_never_mounted_across_projects

- **BVOL-010** THE SYSTEM SHALL keep a box's write hold on a volume for as long as the box's record exists, across stop, exit and resume, and release it when `min box rm` or `min box prune` reaps the box.
  tier:     T0
  verify:   cargo nextest run -p minimald write_hold_persists_until_box_reaped

- **BVOL-012** WHEN `min volume prune` runs THE SYSTEM SHALL skip every volume that a box holds for writing, whatever its last use.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_prune_skips_held_volumes

- **BVOL-011** THE SYSTEM SHALL accept each `volumes` item as a bare name, meaning `mode = "rw"`, or as `{ name = "<name>", mode = "rw" | "ro" }`, holding an `rw` volume for writing and mounting an `ro` volume read-only.
  tier:     T0
  verify:   cargo nextest run -p minimald volume_mode_bare_is_rw_and_ro_mounts_read_only

## Non-goals

- Object-storage backing and point-in-time readers: the architecture's Box Volume (Glossary › Box Volume); a second backing behind this interface.
- Sharing a volume across hosts: a local volume exists only on the host that created it; cross-host reuse arrives with the object-storage backing.

## Design reasoning

**A local directory first, the interface fixed.** The epic and the author's promotion of the story name the host's state directory as the first backing and require that the interface not change when object storage arrives. The requirements therefore speak of volumes the host holds, mounts and refuses, never of a host directory or host path, so the second backing is a change beneath them rather than a rewrite of them.

**Volumes are keyed by project and name.** The architecture scopes volume names to the project (AT21), so two projects on one host that both declare `cache` get two volumes (BVOL-009). A host-wide name would have let one project's compromised run poison another's cache.

**A write hold lasts as long as the box record.** The owner decided on 2026-09-25 that the hold persists across stop, exit and resume and is released when the box is reaped (BVOL-010), so a stopped session always resumes with its volume and resume needs no second check. `min volume prune` skips a held volume for the same reason (BVOL-012). The alternative, releasing the hold on stop and re-checking it on resume, was rejected by the owner because a stopped box could then fail to resume after another box took its volume. The cost is that a second writer waits for the first box's `rm`, not its stop.

**A bare volume name means read-write.** The owner decided on 2026-09-25 that `volumes = ["cache"]` holds the volume for writing, matching the architecture's `volumes = ["dev"]` example, which implies a writer; `{ name, mode = "ro" }` is the reader form (BVOL-011). The alternative, a bare name meaning read-only, was rejected by the owner because it diverges from that example.

**Generality:** a second backing fits because the requirements name the interface (the `volumes` key, the single-writer rule, the `min volume` verbs, survival past `min box rm`), not the directory.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never let two boxes hold one volume for writing at the same time.
  enforced by: the host daemon's writer hold on each volume, checked when a box is created and held until the box is reaped
  covered by: BVOL-004, BVOL-010

- **Invariant:** THE SYSTEM SHALL never mount a volume created by one project into a box of another project.
  enforced by: the host daemon keys each volume on its project and name (architecture threat AT21, Box Volume poisoning)
  covered by: BVOL-009

## Open questions

- [NEEDS CLARIFICATION (HIGH): the state directory path on each host kind and who owns the volume directories (the daemon's user, the box's user, or root); the epic's own note on S19 asks for this before sizing.]
- [NEEDS CLARIFICATION (MEDIUM): neither the architecture's `box.toml` nor its Glossary gives the path at which a volume is mounted inside a box; BVOL-001 fixes `/volumes/<name>` as this spec's decision pending an architecture line.]
- [NEEDS CLARIFICATION (MEDIUM): the architecture's `box.toml` writes `volumes` with no access mode; BVOL-011 adds one pending an architecture line.]
- [NEEDS CLARIFICATION (MEDIUM): what identifies a project for BVOL-009, its root directory's path or a stable id; a path changes when the project directory moves, which would orphan its volumes.]
- [NEEDS CLARIFICATION (LOW): whether `min box rm` of the last box that wrote a volume should warn that the volume remains (BVOL-008).]
