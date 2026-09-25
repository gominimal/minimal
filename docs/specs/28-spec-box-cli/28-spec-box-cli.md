---
id: BCLI
title: The box grammar — `min box`, the type nouns, and the migration from the session verbs
owner: mitodrummer
epic: gominimal/inbox#731
arch: https://github.com/gominimal/arch/blob/main/architecture.md
updated: 2026-09-25
---

# BCLI — The box grammar — `min box`, the type nouns, and the migration from the session verbs

## Context

Today's CLI has no `box` noun. A session is driven by `min session activate`, `destroy`, `exec`, `rename`, `policy`, `hooks` and `run`, a task by `min task run --keep`, and the daemon by a bare `min stop`; `min ls` prints none of type, state, provider or host. The architecture's command tree names one grammar instead: `min box` verbs for any box, the type nouns `session` and `task` as filtered forms of them, `min shell`, `min run`, `min attach` and `min ls` as daily shortcuts, `min type`, `min host` and `min provider`, versioned `-o json` schemas, and one exit-code table.

The box model, the record, the spec and the operations on them, is `docs/specs/25-spec-box-local-first` (BOX). This spec is the grammar that drives those operations from `min`. It is separate so the model can land first and unblock the networking and egress-proxy specs, and so the grammar is scheduled and reviewed on its own; it lands after BOX. Surfaces: the `min` CLI, its help, completions and synced reference docs.

**Success:** every verb in the architecture's `min box` and type-noun tree exists with its flags, `-o json` output carries the versioned schemas, exit codes follow the architecture's table, and each old spelling works for one release with a hint naming its replacement.

**First slice:** `min box list|show|stop|rm` and `min ls` over the existing daemon, rendering id, type, state, provider and host (BCLI-001, BCLI-003, BCLI-004, BCLI-045, BCLI-051), before any alias work.

## Users and stories

**Roles:** developer or an agent, developer debugging any box, developer with scripts and muscle memory, developer

- AS A developer or an agent, I WANT `min box start|run|list|show|spec|stop|rm|prune|resume|logs|wait|events|cp|exec` for any box and `min session list|start|attach|stop|rm`, `min task run|list|logs|stop|rm` as aliases, with `min shell`, `min run`, `min attach`, and `min ls` as the daily shortcuts, SO THAT one verb means one thing under every noun, and a script written for a session works for a task.
- AS A developer debugging any box, I WANT `min box exec <box> [-t] [--detach] -- <cmd>` to run a command inside a running box under its own namespaces, limits, and posture, with a re-attachable PTY when I ask for one, SO THAT I can get a shell into a task or check a session without another mechanism.
- AS A developer with scripts and muscle memory, I WANT `min session activate`, `min session destroy`, `min session exec`, and bare `min stop` to keep working for one release with a hint naming the new verb, SO THAT the rename is a migration I can schedule, not a break I discover.
- AS A developer, I WANT `min provider list --all` to show `local0` and `local-minvmd0`, and `min host list|show|stop` to work on them, SO THAT the daemon I stop, the VM I look at, and the provider a remote box will come from are one vocabulary.

## Requirements

<!-- Every requirement below was moved or split from BOX on 2026-09-25; the comment under each names its BOX id so readers of gominimal/arch#97 and #98 can follow. BCLI-036 to BCLI-040 returned to BOX as BOX-149 to BOX-153; BCLI-053 to BCLI-057 are the exec verbs that drive them. -->

### Verbs over the box record and spec

- **BCLI-001** WHEN `min box list` or `min ls` runs THE SYSTEM SHALL print id, name, type, state, provider and host per box, scoped to the current project unless `--all` is given, and carry `"schema": "min/v1/box"` under `-o json`.
  <!-- was BOX-006 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_list_prints_columns_and_schema

- **BCLI-002** THE SYSTEM SHALL accept a box address as an id, a name, or `provider/host/name`.
  <!-- was BOX-007, without its `self` sub-bullet, which stays in BOX -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_address_accepts_id_name_and_qualified
  - IF an unqualified name matches more than one running box across hosts THEN THE SYSTEM SHALL fail with exit 2 listing the candidates.
    tier:   T0
    verify: cargo nextest run -p minimal ambiguous_name_across_hosts_exit2_lists_candidates

- **BCLI-003** WHEN `min box show <box>` runs THE SYSTEM SHALL render the box's state as BOX-011 defines it.
  <!-- split from BOX-011: the rendering half; the state model stays in BOX -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_renders_state

- **BCLI-004** IF `min box rm` targets a running box without `--force` THEN THE SYSTEM SHALL refuse and name `--force`.
  <!-- was the sub-bullet of BOX-019 -->
  tier:     T0
  verify:   cargo nextest run -p minimal rm_running_box_refuses_naming_force

- **BCLI-005** IF `min box prune` runs off a TTY without `--yes` THEN THE SYSTEM SHALL fail with exit 2 naming `--yes`.
  <!-- was the sub-bullet of BOX-021 -->
  tier:     T0
  verify:   cargo nextest run -p minimal prune_off_tty_needs_yes

- **BCLI-006** THE SYSTEM SHALL report the disk held by each stopped or exited box in `min box show` and the sum in `min box prune --dry-run`.
  <!-- was BOX-023 -->
  tier:     T0
  verify:   cargo nextest run -p minimal show_and_prune_dry_run_report_disk

- **BCLI-007** WHEN `min shell`, `min attach`, or `min box resume` targets a stopped or exited session THE SYSTEM SHALL resume it as BOX-025 defines.
  <!-- split from BOX-025: which verbs resume; the resume itself stays in BOX -->
  tier:     T0
  verify:   cargo nextest run -p minimal shell_attach_and_resume_verbs_resume_stopped_session

- **BCLI-008** WHEN `min shell` resumes a session THE SYSTEM SHALL attach to it.
  <!-- was BOX-026 -->
  tier:     T0
  verify:   cargo nextest run -p minimal shell_resume_attaches

- **BCLI-009** IF resume targets a box whose spec does not set `pty_enabled` THEN THE SYSTEM SHALL fail with exit 2 naming `min run`.
  <!-- was the sub-bullet of BOX-030 -->
  tier:     T0
  verify:   cargo nextest run -p minimal resume_non_pty_box_exit2_names_run

- **BCLI-010** WHEN `min run <task> [-- <args>…]` runs without `--detach` THE SYSTEM SHALL create a box of type `task` from the entry, connect the box's stdin, stdout and stderr to the command's, write nothing else to stdout, and exit with the entrypoint's code.
  <!-- was BOX-032 -->
  tier:     T0
  verify:   cargo nextest run -p minimal run_wires_stdio_and_propagates_exit
  - WHERE `--detach` is given to `min run` THE SYSTEM SHALL print only the `box_id` to stdout, close the task's stdin at creation, capture the task's output for `min task logs`, and return.
    tier:   T0
    verify: cargo nextest run -p minimal run_detach_prints_id_closes_stdin

- **BCLI-011** THE SYSTEM SHALL provide `min task run` as the noun form of `min run` and remove the previous hidden `min run` that only errored.
  <!-- was BOX-033 -->
  tier:     T0
  verify:   cargo nextest run -p minimal task_run_is_noun_form_of_run

- **BCLI-012** WHEN `min task logs <box> -f` runs THE SYSTEM SHALL follow the task's captured output.
  <!-- was BOX-035 -->
  tier:     T0
  verify:   cargo nextest run -p minimal task_logs_follow

- **BCLI-013** WHEN `min box wait <box>` runs THE SYSTEM SHALL return the box's retained exit code, reading the stored `exited` event when the box has already ended.
  <!-- was BOX-036 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_wait_returns_retained_exit_code

- **BCLI-014** IF a task box ends with `exited.reason = "timeout"` THEN THE SYSTEM SHALL emit a machine-mode error with `code = "timeout"` and return 124 from `min run`.
  <!-- split from BOX-037: the CLI half; the timeout reason stays in BOX -->
  tier:     T0
  verify:   cargo nextest run -p minimal run_timeout_returns_124_with_code_timeout

- **BCLI-015** THE SYSTEM SHALL list exited tasks in `min task list` until they are pruned.
  <!-- was BOX-039 -->
  tier:     T0
  verify:   cargo nextest run -p minimal task_list_shows_exited_until_pruned

- **BCLI-016** WHEN `min box events <box> -o jsonl` runs THE SYSTEM SHALL replay the full retained stream, with each line carrying `"schema": "min/v1/event"`, `ts`, `box`, `parent`, `type` and `data`.
  <!-- was BOX-042 -->
  tier:     T0
  verify:   cargo nextest run -p minimal events_jsonl_replay_schema_fields
  - WHERE `--follow` is given to `min box events` THE SYSTEM SHALL replay the stream then tail it.
    tier:   T0
    verify: cargo nextest run -p minimal events_follow_replays_then_tails
  - WHERE `--parent <box>` is given to `min box events` THE SYSTEM SHALL merge the children's streams.
    tier:   T0
    verify: cargo nextest run -p minimal events_parent_merges_children

- **BCLI-017** WHEN `min init` runs with no entry THE SYSTEM SHALL scaffold a `minimal.toml` in the entry-based shape.
  <!-- was BOX-055 -->
  tier:     T0
  verify:   cargo nextest run -p minimal init_scaffolds_entry_shape

- **BCLI-018** WHEN `min init <entry> --type <type>` or its `--session`/`--task` alias runs THE SYSTEM SHALL append that one entry.
  <!-- was BOX-056 -->
  tier:     T0
  verify:   cargo nextest run -p minimal init_entry_type_appends_one

- **BCLI-019** WHEN `min type list` runs THE SYSTEM SHALL show the six built-in types with source `builtin`.
  <!-- was BOX-057 -->
  tier:     T0
  verify:   cargo nextest run -p minimal type_list_shows_six_builtins

- **BCLI-020** WHEN `min type show <name>` runs THE SYSTEM SHALL render the type's defaults and constraints exactly as the architecture's shipped-types table states, naming the source of every value.
  <!-- was BOX-058 -->
  tier:     T0
  verify:   cargo nextest run -p minimal type_show_matches_shipped_table_with_sources

- **BCLI-021** WHEN `min box spec <entry>` runs THE SYSTEM SHALL render the expanded spec in the format `-o toml|json|yaml` names, with secrets as references only.
  <!-- was BOX-066, without its validation sub-bullet, which stays in BOX -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_formats_secrets_as_refs

- **BCLI-022** WHEN `min box spec <box>` runs THE SYSTEM SHALL render the spec stored in that box's record.
  <!-- was BOX-069 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_box_renders_stored_copy

- **BCLI-023** THE SYSTEM SHALL render every section of a spec in `min box spec` whether or not the current host enforces it.
  <!-- was BOX-078 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_unenforced_sections

- **BCLI-024** THE SYSTEM SHALL document `--network` and `--ingress` as overrides of the entry's `[network]` keys.
  <!-- was BOX-082 -->
  tier:     T0
  verify:   cargo nextest run -p minimal network_flags_documented_as_overrides

- **BCLI-025** WHEN `min box show <box> --network` runs THE SYSTEM SHALL render the effective `[network]` section from the stored spec.
  <!-- was BOX-083 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_network_renders_effective

### The command tree, aliases and hosts

- **BCLI-026** THE SYSTEM SHALL provide `min box start`, `run`, `list`, `show`, `spec`, `stop`, `rm`, `prune`, `resume`, `logs`, `wait`, `events`, `cp` and `exec` with the flags the architecture's command reference lists.
  <!-- was BOX-086 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_verbs_exist_with_arch_flags

- **BCLI-027** THE SYSTEM SHALL accept the plural of every countable noun.
  <!-- was BOX-087 -->
  tier:     T0
  verify:   cargo nextest run -p minimal plural_nouns_accepted

- **BCLI-028** THE SYSTEM SHALL generate `--help` at every level and shell completions from one command model.
  <!-- was BOX-088 -->
  tier:     T0
  verify:   cargo nextest run -p minimal help_and_completions_from_one_model

- **BCLI-029** WHEN `min session start <entry>` runs THE SYSTEM SHALL create the box and attach, or print the id and return under `--detach`.
  <!-- was BOX-089 -->
  tier:     T0
  verify:   cargo nextest run -p minimal session_start_attaches_or_detaches
  - IF `min shell` or `min session start` without `--detach` runs off a TTY THEN THE SYSTEM SHALL fail with exit 2 naming `session start --detach`.
    tier:   T0
    verify: cargo nextest run -p minimal shell_off_tty_exit2_names_detach

- **BCLI-030** THE SYSTEM SHALL provide `min session list|start|attach|stop|rm` and `min task run|list|logs|stop|rm` as aliases of the `min box` forms, filtered to boxes of that type.
  <!-- was BOX-148 -->
  tier:     T0
  verify:   cargo nextest run -p minimal type_noun_verbs_alias_box_forms

- **BCLI-031** WHEN `min shell [<session>]` runs THE SYSTEM SHALL resolve the named entry, else the sole session entry, else the entry named `default`, and start, re-attach, or resume it; and WHERE `--new` is given THE SYSTEM SHALL start a parallel instance.
  <!-- was BOX-090 -->
  tier:     T0
  verify:   cargo nextest run -p minimal shell_resolves_named_sole_or_default_and_new
  - IF `min shell` runs with no argument and the file has several session entries and none named `default` THEN THE SYSTEM SHALL fail with exit 2 listing the entries.
    tier:   T0
    verify: cargo nextest run -p minimal shell_ambiguous_entries_exit2_lists

- **BCLI-032** WHEN `min attach <box>` targets a box whose spec sets `pty_enabled` THE SYSTEM SHALL re-attach its PTY.
  <!-- was BOX-093 -->
  tier:     T0
  verify:   cargo nextest run -p minimal attach_reattaches_pty_box
  - IF `min attach` targets a box without `pty_enabled` and no `--exec <id>` naming a PTY exec THEN THE SYSTEM SHALL fail with exit 2.
    tier:   T0
    verify: cargo nextest run -p minimal attach_non_pty_without_exec_exit2

- **BCLI-033** THE SYSTEM SHALL emit `-o json` and `-o jsonl` output under the versioned schemas `min/v1/box`, `min/v1/event` and `min/v1/error`.
  <!-- was BOX-095 -->
  tier:     T0
  verify:   cargo nextest run -p minimal json_output_carries_versioned_schemas
  - IF a command fails in a machine output mode THEN THE SYSTEM SHALL write one JSON object to stderr carrying `code`, `message` and `hint`.
    tier:   T0
    verify: cargo nextest run -p minimal machine_mode_error_object_on_stderr

- **BCLI-034** THE SYSTEM SHALL use exit code 2 for usage errors, 3 for invalid configuration, 4 for not found, 5 for policy refusals, 7 for an unreachable host, 8 for insufficient resources, and 125 to 127 for runtime failures.
  <!-- was BOX-097 -->
  tier:     T0
  verify:   cargo nextest run -p minimal exit_code_table

- **BCLI-035** WHEN a run-style command's entrypoint exits THE SYSTEM SHALL propagate the entrypoint's exit code.
  <!-- was BOX-098 -->
  tier:     T0
  verify:   cargo nextest run -p minimal run_style_propagates_entrypoint_exit

- **BCLI-053** WHEN `min box exec <box> -- <cmd>` runs THE SYSTEM SHALL execute the command in the box as BOX-149 defines, refused as BOX-153 defines, and exit with the command's exit code.
  <!-- the presentation half of BOX-099, formerly BCLI-036; the exec operation returned to BOX as BOX-149 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_exec_runs_command_and_exits_with_its_code
  - WHERE `-t` is given to `min box exec` THE SYSTEM SHALL request a PTY exec as BOX-149 defines and print its exec id.
    tier:   T0
    verify: cargo nextest run -p minimal box_exec_tty_prints_exec_id
  - WHERE `--detach` is given to `min box exec` THE SYSTEM SHALL start a detached exec as BOX-149 defines, print its exec id, and return.
    tier:   T0
    verify: cargo nextest run -p minimal box_exec_detach_prints_id_and_returns

- **BCLI-054** WHEN `min attach <box> --exec <id>` runs THE SYSTEM SHALL re-attach that exec's PTY as BOX-149 defines.
  <!-- the presentation half of BOX-099, formerly a sub-bullet of BCLI-036 -->
  tier:     T0
  verify:   cargo nextest run -p minimal attach_exec_reattaches_exec_pty

- **BCLI-055** WHEN `min box stop <box> --exec <id>` runs THE SYSTEM SHALL stop that exec as BOX-151 defines.
  <!-- the presentation half of BOX-103, formerly BCLI-038 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_stop_exec_stops_that_exec

- **BCLI-056** WHEN `min box logs <box> --exec <id>` runs THE SYSTEM SHALL print that exec's captured output as BOX-149 defines.
  <!-- the presentation half of BOX-099, formerly a sub-bullet of BCLI-036 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_logs_exec_prints_exec_output

- **BCLI-057** WHEN `min box wait <box> --exec <id>` runs THE SYSTEM SHALL return that exec's retained exit code as BOX-149 defines.
  <!-- the presentation half of BOX-099, formerly a sub-bullet of BCLI-036 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_wait_exec_returns_exec_code

- **BCLI-041** THE SYSTEM SHALL accept `min session exec` as a hidden alias of `min box exec` for one release.
  <!-- was BOX-106 -->
  tier:     T0
  verify:   cargo nextest run -p minimal session_exec_alias_hidden_one_release

- **BCLI-042** THE SYSTEM SHALL accept `session activate` (mapping a path to the entry and `--name` to the box name, `--network` and `--ingress` to the overrides), `session destroy`, `session exec`, `session rename`, `session policy`, `session hooks`, `session run`, `task run --keep`, and bare `stop` as hidden aliases of their new forms for one release, printing one stderr hint naming the replacement and leaving `-o json` output unchanged.
  <!-- was BOX-107 -->
  tier:     T0
  verify:   cargo nextest run -p minimal legacy_session_verbs_alias_with_hint
  - IF an alias from BCLI-041 or BCLI-042 is invoked after the release that accepted it THEN THE SYSTEM SHALL fail with exit 2 carrying the same hint.
    tier:   T0
    verify: cargo nextest run -p minimal aliases_exit2_after_grace_release

- **BCLI-043** THE SYSTEM SHALL keep `session setup-zed` hidden and unchanged.
  <!-- was BOX-108 -->
  tier:     T0
  verify:   cargo nextest run -p minimal setup_zed_unchanged

- **BCLI-044** THE SYSTEM SHALL describe only the new grammar in the synced reference and concept docs, with one migration note listing the aliases and their removal release.
  <!-- was BOX-110 -->
  tier:     T0
  verify:   cargo nextest run -p minimal docs_describe_new_grammar_with_migration_note

- **BCLI-045** THE SYSTEM SHALL keep `min ls` as the alias of `min box list`.
  <!-- was BOX-111 -->
  tier:     T0
  verify:   cargo nextest run -p minimal ls_aliases_box_list

- **BCLI-046** THE SYSTEM SHALL name the well-known local providers `local0..N` (native daemon) and `local-minvmd0..N` (one per VM), each with exactly one host of the same name, and accept `local-minimald` and `local-minvmd` as aliases for one release with a hint.
  <!-- was BOX-112 -->
  tier:     T0
  verify:   cargo nextest run -p minimal local_provider_names_and_aliases

- **BCLI-047** WHEN `min host list` runs THE SYSTEM SHALL render each local host with its name and state, beside the resource figures BRES-014 adds.
  <!-- was BOX-113 -->
  tier:     T0
  verify:   cargo nextest run -p minimal host_list_name_and_state

- **BCLI-048** WHEN `min host show <host>` runs THE SYSTEM SHALL add the host-side socket path and the daemon version.
  <!-- was BOX-114 -->
  tier:     T0
  verify:   cargo nextest run -p minimal host_show_socket_and_version

- **BCLI-049** WHEN `min host stop <host>` runs THE SYSTEM SHALL stop that daemon, and its VM where one exists, once its boxes are stopped, or at once under `--force`.
  <!-- was BOX-115 -->
  tier:     T0
  verify:   cargo nextest run -p minimal host_stop_stops_daemon_and_vm
  <!-- runs on the VM lane (NET-107): the behaviour exists only with the VM host daemon in the loop -->

- **BCLI-050** THE SYSTEM SHALL map bare `min stop`, a BCLI-042 alias, to `min host stop` on the local host for one release, after which BCLI-042 applies.
  <!-- was BOX-116 -->
  tier:     T0
  verify:   cargo nextest run -p minimal bare_stop_aliases_host_stop

- **BCLI-051** THE SYSTEM SHALL show the host of every box in `min ls` and `min box list`.
  <!-- was BOX-117 -->
  tier:     T0
  verify:   cargo nextest run -p minimal list_shows_host_per_box

- **BCLI-052** WHEN `min provider list --all` runs THE SYSTEM SHALL list every well-known local provider present on the machine.
  <!-- was BOX-147 -->
  tier:     T0
  verify:   cargo nextest run -p minimal provider_list_all_shows_local_providers

## Non-goals

- The box model: the record, its states and retention, the expanded spec, the projection, stop, reap, resume, rename, events and the un-enrolled path: `docs/specs/25-spec-box-local-first` (BOX). This spec renders and drives them and adds no behaviour to them.
- Resource verbs and figures (`min host list|show` capacity, allocatable, allocated, default box size and enforcement; the 137 return on an OOM end): `docs/specs/26-spec-box-resources` (BRES), which carries them as BRES-011 and BRES-014.
- Volume verbs (`min volume list|show|rm|prune`): `docs/specs/27-spec-box-volumes` (BVOL), which carries them as BVOL-006, BVOL-007 and BVOL-012. BRES and BVOL keep their own verbs because they are small and move with the behaviour they render.
- The dash (epic story S14): an amendment to `docs/specs/07-spec-min-dash-tui`.
- The local providers serving the Box Provider API (epic story S16): they wait on gominimal/arch#45, and `min host` and `min provider` read the daemon directly until then.
- `min box sync` and `min box port`: the architecture's `min box` reference; not scheduled by this epic.

## Design reasoning

**The grammar is a sibling of the model.** The owner split the grammar out of BOX on 2026-09-25. The model lands first because the networking and egress-proxy specs bind to the box spec and record, not to verbs, and are blocked until it exists; the grammar is scheduled and reviewed separately; and a client other than the CLI binds to the model, so BOX states its behaviour as operations and this spec maps verbs onto them. Every requirement here was moved from BOX with its text, tier and test, and the comment under each names its BOX id. The exec operations (running the command in the box, client loss, stopping an exec, its events and `exec_enabled`) are daemon behaviour and live in BOX as BOX-149 to BOX-153; BCLI-053 to BCLI-057 are only the verbs and flags that drive them.

**Old spellings hint for one release, then fail.** The architecture's command tree is taken verbatim; `min box rename` and `min host stop` are the only additions, each an open question below. Every old spelling (the session verbs, `task run --keep`, bare `min stop`, and the `local-minimald` and `local-minvmd` provider values) stays as a hidden alias for one release, printing one hint naming its replacement, and fails with exit 2 and the same hint the release after (BCLI-041, BCLI-042, BCLI-046, BCLI-050). Bare `min stop` maps to `min host stop` because what it stops today is the daemon, not a box.

**`min shell` with several entries and no `default` is a usage error.** Starting the first entry in file order would depend on layout; prompting was rejected as more code for the daily loop. Listing the candidates matches the ambiguous-name rule (BCLI-002, BCLI-031).

**`min host show` names the host-side socket only.** On the VM provider it is the host-side socket the client connects to (BCLI-048); adding the in-VM path was rejected as an in-VM fact the client never uses.

**Stopping a VM host runs on the VM lane.** It exists only with the VM host daemon in the loop, so BCLI-049's test names the VM lane (NET-107) rather than `tier: none`, which would have left the VM path unverified.

**Generality:** the grammar binds to the operations BOX defines, not to a daemon's internals, so a second client (the dash, a remote provider's client) drives the same operations without this grammar, and a second host is addressed by the same `provider/host/name`. The deliberate exceptions are BCLI-046 and BCLI-052, which name the well-known local providers because those names are the behaviour.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never write a secret value in any output mode.
  enforced by: every rendering of a spec or record carries a secret as a reference only (architecture Output conventions: secrets never appear in any output mode)
  covered by: BCLI-021, BCLI-033

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): the architecture's exit-code table has no row for a task timeout; BCLI-014 returns 124 by convention beside 137 for OOM and needs the row added (gominimal/arch#97).]
- [NEEDS CLARIFICATION (MEDIUM): the architecture's command tree lacks `min box rename`, the replacement BCLI-042 names for `session rename`, and `min host stop` (BCLI-049, BCLI-050); both are written to this spec's additions pending one architecture line each (gominimal/arch#98).]
