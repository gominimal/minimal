---
id: BOX
title: Box — one record, one spec, one grammar for every session and task
owner: mitodrummer
epic: gominimal/inbox#731
arch: https://github.com/gominimal/arch/blob/main/architecture.md
updated: 2026-09-25
---

# BOX — Box — one record, one spec, one grammar for every session and task

## Context

A session and a task are the same kind of thing in the architecture of record: a box, described by one expanded spec, named by one grammar, retained after it ends. The daemon today holds a session model with three live states and no exit, a task that is an ephemeral session the client destroys, a `minimal.toml` with a single `[session]` table, and a CLI with no `box` noun. The networking and egress-proxy specs (NET, BEP) bind their configuration "in the box spec" and have no schema to bind to; the remote-host specs were parked until the local story is settled; the Box Provider API draft requires the built-in local providers to serve the same surface as a remote one.

After this ships, a developer on a stock install with no identity plane runs sessions and tasks as boxes: each has a stable id, a type, a spec they can read before it runs, and a record that survives its exit and can be resumed, inspected, or reaped. The record, spec, projection and provider surface are the ones a remote host reads later, so nothing here is redone when boxes leave the laptop. Surfaces: the CLI, the daemon, the config expander, and the local provider's host commands.

**Success:** on one machine with no identity plane, `min shell`, `min run`, and `min box list|show|spec|stop|rm|prune|resume` all operate on the same box records; a stopped session resumes with its files; a task leaves an exited box whose exit code and files are readable; and the same `minimal.toml` expands to identical bytes whether the host is enrolled or not.

**First slice:** every existing session becomes a box with a stable id, type, parent and the `stopped`/`exited` states, listed by `min ls` and `min box list` with provider and host, and stoppable, on today's create path and before any schema change (BOX-001, BOX-003, BOX-006, BOX-011, BOX-013, BOX-112 and BOX-117). Resume follows the stored spec (BOX-068).

## Users and stories


**Roles:** developer who scripts against Minimal, developer, developer or a script, developer or an orchestrating script, developer editing `minimal.toml`, developer or platform engineer, developer or a reviewer, developer declaring a box, and as the networking and egress-proxy epics, developer or an agent, developer debugging any box, developer with scripts and muscle memory, developer on a stock install

- AS A developer who scripts against Minimal, I WANT every box to carry a UUIDv7 `box_id`, a type, and a parent from creation, with its name as an alias, SO THAT a rename, a re-creation under the same name, or a second host never changes what my script refers to.
- AS A developer, I WANT `stop` to end a box's processes and keep its record and files, and `rm` and `prune` to be the only things that delete them, SO THAT I can read an exit code, pull results, and decide when disk is reclaimed.
- AS A developer, I WANT `min shell` or `min attach` on a stopped or exited session to bring it back with its files and name, SO THAT closing a laptop or stopping a box to free memory never means starting over.
- AS A developer or a script, I WANT `min run <task>` to wire my stdio through, return the entrypoint's exit code, and leave an exited box with its files, SO THAT tasks compose in pipelines and their results are inspectable after they end.
- AS A developer or an orchestrating script, I WANT `min box events <box>` to replay and follow the lifecycle events minimald authored for that box, SO THAT I can see when it was created, started, stopped, or killed without reading a daemon log.
- AS A developer editing `minimal.toml`, I WANT to declare `[sessions.<name>]`, `[tasks.<name>]`, and `[boxes.<name>]` entries with `[defaults]` and `[defaults.<type>]`, and keep my existing `[session]` table working for one release, SO THAT one file describes every box I run, in the shape the architecture documents.
- AS A developer or platform engineer, I WANT the six shipped Box Types to exist as data, and to define my own with `[box_types.<name>] extends = …`, with defaults I can override and constraints that only narrow, SO THAT what a session or task is lives in one reviewable table, and a project can say what a box means without editing `min`.
- AS A developer or a reviewer, I WANT `min box spec <entry>` to render the fully expanded Box Spec, byte for byte what minimald receives and stores, with the same digest on both sides, SO THAT the review artifact is the runtime artifact, locally today and under an identity plane later.
- AS A developer declaring a box, and as the networking and egress-proxy epics, I WANT `[machine]`, `[io]`, `[execution]`, `[network]`, `[network.bep]`, `[secrets]`, `[params]`, and `[nesting]` accepted, validated, and rendered in the spec, whether or not this host enforces every key yet, SO THAT a key is declared once, in one file, and the epic that enforces it reads it from the spec instead of adding a flag.
- AS A developer or an agent, I WANT `min box start|run|list|show|spec|stop|rm|prune|resume|logs|wait|events|cp|exec` for any box and `min session list|start|attach|stop|rm`, `min task run|list|logs|stop|rm` as aliases, with `min shell`, `min run`, `min attach`, and `min ls` as the daily shortcuts, SO THAT one verb means one thing under every noun, and a script written for a session works for a task.
- AS A developer debugging any box, I WANT `min box exec <box> [-t] [--detach] -- <cmd>` to run a command inside a running box under its own namespaces, limits, and posture, with a re-attachable PTY when I ask for one, SO THAT I can get a shell into a task or check a session without another mechanism.
- AS A developer with scripts and muscle memory, I WANT `min session activate`, `min session destroy`, `min session exec`, and bare `min stop` to keep working for one release with a hint naming the new verb, SO THAT the rename is a migration I can schedule, not a break I discover.
- AS A developer, I WANT `min provider list --all` to show `local0` and `local-minvmd0`, and `min host list|show|stop` to work on them, SO THAT the daemon I stop, the VM I look at, and the provider a remote box will come from are one vocabulary.
- AS A developer on a stock install, I WANT everything above to work with no Gatehouse and no per-box identity, and the same `minimal.toml` to work unchanged when my host is later enrolled, SO THAT local-first costs nothing now and remote costs no rewrite later.


## Requirements


### O1 One box record

- **BOX-001** WHEN a box is created THE SYSTEM SHALL assign it a UUIDv7 `box_id` whose random fields come from the OS CSPRNG, a `box_type`, and a `parent`, minted by the host-side creator outside any VM and never supplied by the client (BEP-070).
  - IF a minted `box_id` is named by any retained record THEN THE SYSTEM SHALL refuse the creation (BEP-070).
    tier:   T0
    verify: cargo nextest run -p minimald colliding_box_id_refuses_creation
  tier:     T0
  verify:   cargo nextest run -p minimald create_assigns_uuidv7_id_type_and_parent

- **BOX-002** WHERE the box host is a VM THE SYSTEM SHALL mint the `box_id` in the VM host daemon and pass it to the in-VM daemon at creation.
  tier:     T0
  verify:   cargo nextest run -p minvmd vm_host_mints_box_id_before_in_vm_create
  <!-- runs on the VM lane (NET-107): the behaviour exists only with the VM host daemon in the loop -->

- **BOX-003** WHEN the daemon starts and finds a record without `box_type` or `parent` THE SYSTEM SHALL migrate it once to `box_type = "session"` with no parent, assigning a fresh id only when the stored id is nil, and leave it unchanged on any later start.
  tier:     T0
  verify:   cargo nextest run -p sessions restart_migrates_records_missing_type_or_parent_once

- **BOX-004** THE SYSTEM SHALL keep a box name unique among the running boxes of one host, let a stopped or exited box keep its name, and allow a new box on that host to reuse it.
  tier:     T1
  verify:   cargo nextest run -p sessions name_unique_among_running_on_host_reusable_after_stop
  property: For every sequence of create, stop, exit, rename and reap operations on one host, no two running boxes share a name, and a name held by a stopped or exited box is reusable.

- **BOX-005** WHEN an unqualified name is resolved THE SYSTEM SHALL return the running box of that name, else the most recently created box of that name.
  tier:     T1
  verify:   cargo nextest run -p sessions unqualified_name_resolves_running_else_latest
  property: For every store state and name, resolution returns the unique running box of that name if one exists, else the most recently created box of that name, else none.

- **BOX-006** WHEN `min box list` or `min ls` runs THE SYSTEM SHALL print id, name, type, state, provider and host per box, scoped to the current project unless `--all` is given, and carry `"schema": "min/v1/box"` under `-o json`.
  tier:     T0
  verify:   cargo nextest run -p minimal box_list_prints_columns_and_schema

- **BOX-007** THE SYSTEM SHALL accept a box address as an id, a name, or `provider/host/name`.
  tier:     T0
  verify:   cargo nextest run -p minimal box_address_accepts_id_name_and_qualified
  - IF an unqualified name matches more than one running box across hosts THEN THE SYSTEM SHALL fail with exit 2 listing the candidates.
    tier:   T0
    verify: cargo nextest run -p minimal ambiguous_name_across_hosts_exit2_lists_candidates
  - IF an entry or box is named `self` THEN THE SYSTEM SHALL refuse creation with exit 3.
    tier:   T0
    verify: cargo nextest run -p mfile self_as_name_is_exit3

- **BOX-010** WHEN `min box rename <box> <name>` runs THE SYSTEM SHALL change only the alias, leave `box_id`, spec, events and filesystem unchanged, and record a `renamed` event carrying the old and new names.
  tier:     T1
  verify:   cargo nextest run -p sessions rename_changes_only_alias_and_records_event
  property: For every box and every new name, rename leaves id, spec and filesystem path equal before and after, preserves every prior event, and appends exactly one `renamed` event.

- **BOX-011** THE SYSTEM SHALL hold every box record in exactly one of the states `pending`, `materializing`, `running`, `stopped`, or `exited`, with `stopped` and `exited` records carrying `exit_code` and a `reason` (`stopped` for a `stopped` record; `exit`, `timeout` or `oom` for an `exited` one), and render the state in `min box show`.
  tier:     T2
  verify:   cargo nextest run -p sessions record_state_is_one_of_five_with_exit_reason
  property: For every reachable store state, each record is in exactly one state, `stopped` records carry an exit code and reason `stopped`, and `exited` records carry an exit code and one of `exit`, `timeout` or `oom`.
  harness:  sessions/src/core/record.rs `state_is_exactly_one` over `kani::any::<Record>()`, unwind 1

- **BOX-012** WHEN the daemon restarts THE SYSTEM SHALL reap only records in `pending` or `materializing`.
  tier:     T2
  verify:   cargo nextest run -p sessions restart_reaps_only_pending_and_materializing
  property: For every store state, restart reaping removes exactly the records in `pending` or `materializing` and no others.
  harness:  sessions/src/core/record.rs `restart_reaps_only_pending_or_materializing` over a bounded store of at most 4 records, unwind 4

- **BOX-013** WHEN `min box stop <box>` runs THE SYSTEM SHALL send SIGTERM to the box's process tree, wait, then send SIGKILL, set the state to `stopped`, and record an `exited` event with `reason = "stopped"`.
  tier:     T0
  verify:   cargo nextest run -p minimald stop_sends_term_then_kill_and_records_exited_stopped
  - WHERE `--force` is given to `min box stop` THE SYSTEM SHALL kill the process tree at once.
    tier:   T0
    verify: cargo nextest run -p minimald stop_force_kills_at_once

- **BOX-015** THE SYSTEM SHALL never stop a box for idleness or for the loss of a client.
  tier:     T0
  verify:   cargo nextest run -p minimald daemon_never_stops_for_idle_or_client_loss

- **BOX-016** WHEN a PTY client disconnects THE SYSTEM SHALL record a `detached` event and leave the box running.
  tier:     T0
  verify:   cargo nextest run -p minimald pty_client_loss_records_detach

- **BOX-017** WHILE a box is stopped or exited THE SYSTEM SHALL keep its filesystem on disk and serve `min box cp <box>:<path> <local>` from it with no running process.
  tier:     T0
  verify:   cargo nextest run -p minimald stopped_box_filesystem_served_by_cp

- **BOX-018** WHILE a box is stopped or exited THE SYSTEM SHALL keep its spec, exit code, events and parent readable until it is reaped.
  tier:     T0
  verify:   cargo nextest run -p minimald stopped_box_record_readable_until_reaped

- **BOX-019** WHEN `min box rm <box>` runs on a stopped or exited box THE SYSTEM SHALL delete the record and its filesystem.
  tier:     T0
  verify:   cargo nextest run -p minimald rm_deletes_record_and_filesystem
  - IF `min box rm` targets a running box without `--force` THEN THE SYSTEM SHALL refuse and name `--force`.
    tier:   T0
    verify: cargo nextest run -p minimal rm_running_box_refuses_naming_force

- **BOX-021** WHEN `min box prune` runs with `--stopped`, `--older-than <d>`, or `--parent <box>` THE SYSTEM SHALL reap every box the selectors match, treating `--stopped` as matching both `stopped` and `exited`, and print what it reaped.
  tier:     T0
  verify:   cargo nextest run -p minimald prune_selectors_reap_and_print
  - IF `min box prune` runs off a TTY without `--yes` THEN THE SYSTEM SHALL fail with exit 2 naming `--yes`.
    tier:   T0
    verify: cargo nextest run -p minimal prune_off_tty_needs_yes

- **BOX-023** THE SYSTEM SHALL report the disk held by each stopped or exited box in `min box show` and the sum in `min box prune --dry-run`.
  tier:     T0
  verify:   cargo nextest run -p minimal show_and_prune_dry_run_report_disk

- **BOX-024** THE SYSTEM SHALL run no automatic reaper of stopped or exited boxes.
  tier:     T0
  verify:   cargo nextest run -p minimald no_automatic_reaper_runs

- **BOX-025** WHEN `min shell`, `min attach`, or `min box resume` targets a stopped or exited session THE SYSTEM SHALL start its processes again from the stored spec and retained filesystem under the same `box_id` and name, and record a `resumed` event.
  tier:     T0
  verify:   cargo nextest run -p minimald resume_restarts_from_stored_spec_same_id_and_name
  - IF a resuming box's stored spec can no longer be satisfied THEN THE SYSTEM SHALL refuse with the exit code creation would give and leave the box's state unchanged.
    tier:   T0
    verify: cargo nextest run -p minimald resume_refuses_unsatisfiable_spec_keeps_state

- **BOX-026** WHEN `min shell` resumes a session THE SYSTEM SHALL attach to it.
  tier:     T0
  verify:   cargo nextest run -p minimal shell_resume_attaches

- **BOX-027** WHEN a box resumes THE SYSTEM SHALL run no lifecycle hook other than `on_attach` on attach, unless BOX-028 applies.
  tier:     T0
  verify:   cargo nextest run -p minimald resume_runs_only_on_attach_hook

- **BOX-028** WHERE an entry sets `hooks_on_resume = true` THE SYSTEM SHALL run `on_activate` again on resume and render the key in `min box spec`.
  tier:     T0
  verify:   cargo nextest run -p minimald hooks_on_resume_reruns_on_activate

- **BOX-030** THE SYSTEM SHALL allow resume of any box whose spec sets `pty_enabled`, from `stopped` or `exited`.
  tier:     T0
  verify:   cargo nextest run -p minimald pty_box_resumes_from_stopped_and_exited
  - IF resume targets a box whose spec does not set `pty_enabled` THEN THE SYSTEM SHALL fail with exit 2 naming `min run`.
    tier:   T0
    verify: cargo nextest run -p minimal resume_non_pty_box_exit2_names_run

- **BOX-032** WHEN `min run <task> [-- <args>…]` runs without `--detach` THE SYSTEM SHALL create a box of type `task` from the entry, connect the box's stdin, stdout and stderr to the command's, write nothing else to stdout, and exit with the entrypoint's code.
  tier:     T0
  verify:   cargo nextest run -p minimal run_wires_stdio_and_propagates_exit
  - WHERE `--detach` is given to `min run` THE SYSTEM SHALL print only the `box_id` to stdout, close the task's stdin at creation, capture the task's output for `min task logs`, and return.
    tier:   T0
    verify: cargo nextest run -p minimal run_detach_prints_id_closes_stdin

- **BOX-033** THE SYSTEM SHALL provide `min task run` as the noun form of `min run` and remove the previous hidden `min run` that only errored.
  tier:     T0
  verify:   cargo nextest run -p minimal task_run_is_noun_form_of_run

- **BOX-035** WHEN `min task logs <box> -f` runs THE SYSTEM SHALL follow the task's captured output.
  tier:     T0
  verify:   cargo nextest run -p minimal task_logs_follow

- **BOX-036** WHEN `min box wait <box>` runs THE SYSTEM SHALL return the box's retained exit code, reading the stored `exited` event when the box has already ended.
  tier:     T0
  verify:   cargo nextest run -p minimal box_wait_returns_retained_exit_code

- **BOX-037** IF a task runs past its declared `timeout` THEN THE SYSTEM SHALL end the box with `exited.reason = "timeout"`, emit a machine-mode error with `code = "timeout"`, and return 124 from `min run`.
  tier:     T0
  verify:   cargo nextest run -p minimald task_timeout_exits_124_with_reason_timeout

- **BOX-038** WHEN a task's entrypoint returns THE SYSTEM SHALL end the box from the daemon whether or not a client is connected, and retain the record.
  tier:     T0
  verify:   cargo nextest run -p minimald task_ends_on_entrypoint_return_without_client

- **BOX-039** THE SYSTEM SHALL list exited tasks in `min task list` until they are pruned.
  tier:     T0
  verify:   cargo nextest run -p minimal task_list_shows_exited_until_pruned

- **BOX-040** THE SYSTEM SHALL write `created`, `started`, `exec_started`, `exec_exited`, `oom_killed`, `exited`, `renamed`, `resumed` and `detached` events into the box record outside the box filesystem.
  tier:     T0
  verify:   cargo nextest run -p minimald events_written_outside_box_filesystem

- **BOX-041** THE SYSTEM SHALL reject any append to a box's events stream that originates from a process inside the box's namespaces, including one running as root inside the box.
  tier:     T0
  verify:   cargo nextest run -p minimald in_box_root_cannot_append_events

- **BOX-042** WHEN `min box events <box> -o jsonl` runs THE SYSTEM SHALL replay the full retained stream, with each line carrying `"schema": "min/v1/event"`, `ts`, `box`, `parent`, `type` and `data`.
  tier:     T0
  verify:   cargo nextest run -p minimal events_jsonl_replay_schema_fields
  - WHERE `--follow` is given to `min box events` THE SYSTEM SHALL replay the stream then tail it.
    tier:   T0
    verify: cargo nextest run -p minimal events_follow_replays_then_tails
  - WHERE `--parent <box>` is given to `min box events` THE SYSTEM SHALL merge the children's streams.
    tier:   T0
    verify: cargo nextest run -p minimal events_parent_merges_children

- **BOX-045** THE SYSTEM SHALL retain a box's events stream across stop and exit and delete it only on `rm` or `prune`.
  tier:     T0
  verify:   cargo nextest run -p minimald events_survive_stop_deleted_on_rm


### O2 The Box Spec in minimal.toml

- **BOX-046** THE SYSTEM SHALL read `[sessions.<name>]`, `[tasks.<name>]`, `[agents.<name>]` and `[services.<name>]` as `[boxes.<name>]` with the matching `type`.
  tier:     T0
  verify:   cargo nextest run -p mfile type_noun_tables_are_boxes_sugar
  - IF an entry name is not DNS-safe, is not unique across the file, or is `self` THEN THE SYSTEM SHALL fail with exit 3 naming the entry.
    tier:   T0
    verify: cargo nextest run -p mfile entry_name_invalid_exit3_names_entry

- **BOX-048** THE SYSTEM SHALL merge `[defaults]` into every entry and `[defaults.<type>]` into entries of that type, unioning lists and replacing scalars and tables with the more specific layer's.
  tier:     T1
  verify:   cargo nextest run -p mfile defaults_merge_lists_union_scalars_replace
  property: For every pair of layers, merging unions list values in layer order and replaces scalars and tables with the more specific layer's.

- **BOX-049** THE SYSTEM SHALL accept per-entry keys written flat (`timeout`, `pty_enabled`, and the `[machine]` and `on_oom` keys as BRES-001 defines them) and keep the meaning of `packages`, `patches`, `vars` and `lifecycle_hooks`.
  tier:     T0
  verify:   cargo nextest run -p mfile flat_per_entry_keys_and_legacy_keys_keep_meaning

- **BOX-050** WHERE a file carries a top-level `[session]` table THE SYSTEM SHALL read it as `[defaults.session]` for one release and print one hint from `mip check` and `min box spec`.
  tier:     T0
  verify:   cargo nextest run -p mfile legacy_session_table_reads_as_defaults_session_with_hint
  - IF a legacy table from BOX-050, BOX-051 or BOX-052 is present after the release that accepted it THEN THE SYSTEM SHALL fail with exit 3 carrying the same hint.
    tier:   T0
    verify: cargo nextest run -p mfile legacy_tables_exit3_after_grace_release

- **BOX-051** WHERE a file carries `state_key` or `profile` under top-level `[defaults]` THE SYSTEM SHALL read them as `[defaults.task]` for one release and print one hint.
  tier:     T0
  verify:   cargo nextest run -p mfile legacy_defaults_task_keys_with_hint

- **BOX-052** WHERE a file carries a top-level `[params]` parameter schema THE SYSTEM SHALL read it as `[args]` for one release, print one hint, and leave per-task `args` keys unchanged.
  tier:     T0
  verify:   cargo nextest run -p mfile legacy_params_reads_as_args_with_hint

- **BOX-054** IF a `[tasks.*]` entry sets `interactive = true` THEN THE SYSTEM SHALL fail with exit 3 naming a `[sessions.*]` entry as the fix.
  tier:     T0
  verify:   cargo nextest run -p mfile interactive_task_exit3_names_session

- **BOX-055** WHEN `min init` runs with no entry THE SYSTEM SHALL scaffold a `minimal.toml` in the entry-based shape.
  tier:     T0
  verify:   cargo nextest run -p minimal init_scaffolds_entry_shape

- **BOX-056** WHEN `min init <entry> --type <type>` or its `--session`/`--task` alias runs THE SYSTEM SHALL append that one entry.
  tier:     T0
  verify:   cargo nextest run -p minimal init_entry_type_appends_one

- **BOX-057** WHEN `min type list` runs THE SYSTEM SHALL show the six built-in types with source `builtin`.
  tier:     T0
  verify:   cargo nextest run -p minimal type_list_shows_six_builtins

- **BOX-058** WHEN `min type show <name>` runs THE SYSTEM SHALL render the type's defaults and constraints exactly as the architecture's shipped-types table states, naming the source of every value.
  tier:     T0
  verify:   cargo nextest run -p minimal type_show_matches_shipped_table_with_sources

- **BOX-059** THE SYSTEM SHALL resolve a `[box_types.<name>]` with `extends`, `defaults` and `constraints` transitively to a built-in root.
  tier:     T1
  verify:   cargo nextest run -p mfile box_type_resolves_to_builtin_root
  property: For every type graph whose chains terminate at a built-in, resolution yields that built-in as the root.
  - IF a project type lacks `extends`, forms a cycle, or redefines a built-in name THEN THE SYSTEM SHALL fail with exit 3 naming the type, and for a redefinition both definitions.
    tier:   T1
    verify: cargo nextest run -p mfile box_type_missing_extends_cycle_or_redefinition_exit3
    property: For every type graph with a missing extends, a cycle, or a built-in name redefinition, resolution fails naming the type, and for a redefinition both definitions.

- **BOX-061** IF an entry sets a value a type constrains to a different value THEN THE SYSTEM SHALL fail with exit 3 naming the type.
  tier:     T1
  verify:   cargo nextest run -p mfile entry_violating_constraint_exit3_names_type
  property: For every type and entry, an entry value outside the type's constraint set is rejected.

- **BOX-062** THE SYSTEM SHALL never let a type constraint add a package, a port, or an egress entry.
  tier:     T1
  verify:   cargo nextest run -p mfile constraint_never_adds_package_port_or_egress
  property: For every type constraint and expanded spec, the constrained spec's package, port and egress lists are subsets of the unconstrained spec's.

- **BOX-063** THE SYSTEM SHALL expand and validate entries of type `agent`, `service`, `build` and `container-build`.
  tier:     T0
  verify:   cargo nextest run -p mfile other_builtin_types_expand_and_validate

- **BOX-064** THE SYSTEM SHALL expand an entry in the order `[upstream]`, type defaults, `[defaults]`, `[defaults.<type>]`, entry, selected loadouts, unioning lists in that order and replacing scalars and tables wholesale.
  tier:     T1
  verify:   cargo nextest run -p mfile expansion_order_and_merge_rules
  property: For every set of layers, expansion equals the fold of the merge rule over the layers in the stated order.

- **BOX-065** THE SYSTEM SHALL produce an expanded spec whose serialization is byte-identical across two runs over one file.
  tier:     T1
  verify:   cargo nextest run -p mfile expansion_is_byte_identical_across_runs
  property: For every minimal.toml, expanding twice yields identical bytes.

- **BOX-066** WHEN `min box spec <entry>` runs THE SYSTEM SHALL render the expanded spec in the format `-o toml|json|yaml` names, with secrets as references only.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_formats_secrets_as_refs
  - IF an expanded spec carries an invalid key or value THEN THE SYSTEM SHALL fail with exit 3 naming the key and the layer it came from.
    tier:   T0
    verify: cargo nextest run -p mfile invalid_key_exit3_names_key_and_layer

- **BOX-068** WHEN a box is created THE SYSTEM SHALL send the daemon the expanded spec rather than the entry and store it in the record.
  tier:     T0
  verify:   cargo nextest run -p minimald-rpc create_sends_expanded_spec_and_stores_it

- **BOX-069** WHEN `min box spec <box>` runs THE SYSTEM SHALL render the spec stored in that box's record.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_box_renders_stored_copy

- **BOX-071** WHEN a box is created THE SYSTEM SHALL compute, in both the client and the daemon, the Gatehouse §6.3.2 Box Spec projection of the expanded spec, exactly the §6.3.2 field set (`v`; `type.name`, `type.source`, `type.root`, and `type.registry` when the source is `org`; `network.mode`, `egress_dns`, `egress_subnets`, `ingress_ports` and `quic443`; `bep.steering`; `registry_pinned`; `registry_commit`; `loadout_mode`; `pty_enabled`; `lifetime`; the `[nesting]` bounds; `secret_grants`), and digest it as SHA-256 over its RFC 8785 JCS bytes.
  - WHEN a box is created THE SYSTEM SHALL store the daemon's recomputed digest beside the client's in the record.
    tier:   T0
    verify: cargo nextest run -p minimald projection_digests_stored_side_by_side
  tier:     T1
  verify:   cargo nextest run -p mfile projection_is_the_6_3_2_field_set
  property: For every expanded spec, the digest equals SHA-256 over the RFC 8785 JCS bytes of the §6.3.2 record built from that spec: changing a field outside the §6.3.2 set leaves the digest unchanged, and changing one inside it changes the digest.

- **BOX-072** IF the client's and the daemon's projection digests differ THEN THE SYSTEM SHALL refuse creation.
  tier:     T0
  verify:   cargo nextest run -p minimald projection_digest_mismatch_refuses_create

- **BOX-073** WHILE the host is un-enrolled THE SYSTEM SHALL evaluate no policy against the projection.
  tier:     T0
  verify:   cargo nextest run -p minimald unenrolled_evaluates_no_policy

- **BOX-074** THE SYSTEM SHALL link one expansion crate into both the client and the daemon and report its version from the daemon.
  tier:     T0
  verify:   cargo nextest run -p minimald-rpc get_version_reports_expander_crate_version
  - IF the client's expander version differs from the daemon's THEN THE SYSTEM SHALL report both versions before creation and continue, leaving BOX-072's digest comparison as the check that refuses.
    tier:   T0
    verify: cargo nextest run -p minimal expander_skew_reports_and_continues

- **BOX-145** THE SYSTEM SHALL pin golden vectors for the canonical expanded spec of the example `minimal.toml`, its projection digest, and the six built-in types' rendered definitions.
  tier:     T0
  verify:   cargo nextest run -p mfile golden_vectors_pinned

- **BOX-076** THE SYSTEM SHALL accept every Box Spec section with the keys and value types of the architecture's `box.toml`, except that the `[machine]` keys and `[execution] on_oom` are as BRES-001 defines them and `[network]` egress keys take the nested `egress.*` shape the networking and egress-proxy specs bind.
  tier:     T0
  verify:   cargo nextest run -p mfile sections_follow_box_toml_with_nested_egress
  - IF a spec carries an unknown key or a value of the wrong shape THEN THE SYSTEM SHALL fail with exit 3 naming the key.
    tier:   T0
    verify: cargo nextest run -p mfile unknown_key_or_shape_exit3

- **BOX-078** THE SYSTEM SHALL render every section of a spec in `min box spec` whether or not the current host enforces it.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_unenforced_sections

- **BOX-079** THE SYSTEM SHALL accept `[network] mode` values `none`, `host_ip` and `own_ip`, and accept the legacy spellings with a hint.
  tier:     T0
  verify:   cargo nextest run -p mfile network_mode_values_and_legacy_hint

- **BOX-080** THE SYSTEM SHALL validate `[network] egress`, `[network] ingress`, `[network.bep]` and `[secrets]` and pass them to the daemon unchanged.
  tier:     T0
  verify:   cargo nextest run -p minimald-rpc network_bep_secrets_passed_unchanged
  - IF a spec sets `mode = "none"` and any `egress.*` key THEN THE SYSTEM SHALL fail with exit 3.
    tier:   T0
    verify: cargo nextest run -p mfile mode_none_with_egress_exit3

- **BOX-081** WHILE the host is un-enrolled and no node-local egress proxy is present, IF a spec carries `[secrets] source = "broker"` THEN THE SYSTEM SHALL fail with exit 5 and `code = "gatehouse_unenrolled_node"`.
  tier:     T0
  verify:   cargo nextest run -p minimald broker_secret_unenrolled_exit5

- **BOX-082** THE SYSTEM SHALL document `--network` and `--ingress` as overrides of the entry's `[network]` keys.
  tier:     T0
  verify:   cargo nextest run -p minimal network_flags_documented_as_overrides

- **BOX-083** WHEN `min box show <box> --network` runs THE SYSTEM SHALL render the effective `[network]` section from the stored spec.
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_network_renders_effective

- **BOX-085** THE SYSTEM SHALL accept `[params]` on an entry and render it in `min box spec`.
  tier:     T0
  verify:   cargo nextest run -p mfile params_accepted_and_rendered


### O3 One grammar

- **BOX-086** THE SYSTEM SHALL provide `min box start`, `run`, `list`, `show`, `spec`, `stop`, `rm`, `prune`, `resume`, `logs`, `wait`, `events`, `cp` and `exec` with the flags the architecture's command reference lists.
  tier:     T0
  verify:   cargo nextest run -p minimal box_verbs_exist_with_arch_flags

- **BOX-087** THE SYSTEM SHALL accept the plural of every countable noun.
  tier:     T0
  verify:   cargo nextest run -p minimal plural_nouns_accepted

- **BOX-088** THE SYSTEM SHALL generate `--help` at every level and shell completions from one command model.
  tier:     T0
  verify:   cargo nextest run -p minimal help_and_completions_from_one_model

- **BOX-089** WHEN `min session start <entry>` runs THE SYSTEM SHALL create the box and attach, or print the id and return under `--detach`.
  tier:     T0
  verify:   cargo nextest run -p minimal session_start_attaches_or_detaches
  - IF `min shell` runs with no argument and the file has several session entries and none named `default` THEN THE SYSTEM SHALL fail with exit 2 listing the entries.
    tier:   T0
    verify: cargo nextest run -p minimal shell_ambiguous_entries_exit2_lists
  - IF `min shell` or `min session start` without `--detach` runs off a TTY THEN THE SYSTEM SHALL fail with exit 2 naming `session start --detach`.
    tier:   T0
    verify: cargo nextest run -p minimal shell_off_tty_exit2_names_detach

- **BOX-148** THE SYSTEM SHALL provide `min session list|start|attach|stop|rm` and `min task run|list|logs|stop|rm` as aliases of the `min box` forms, filtered to boxes of that type.
  tier:     T0
  verify:   cargo nextest run -p minimal type_noun_verbs_alias_box_forms

- **BOX-090** WHEN `min shell [<session>]` runs THE SYSTEM SHALL resolve the named entry, else the sole session entry, else the entry named `default`, and start, re-attach, or resume it; and WHERE `--new` is given THE SYSTEM SHALL start a parallel instance.
  tier:     T0
  verify:   cargo nextest run -p minimal shell_resolves_named_sole_or_default_and_new

- **BOX-093** WHEN `min attach <box>` targets a box whose spec sets `pty_enabled` THE SYSTEM SHALL re-attach its PTY.
  tier:     T0
  verify:   cargo nextest run -p minimal attach_reattaches_pty_box
  - IF `min attach` targets a box without `pty_enabled` and no `--exec <id>` naming a PTY exec THEN THE SYSTEM SHALL fail with exit 2.
    tier:   T0
    verify: cargo nextest run -p minimal attach_non_pty_without_exec_exit2

- **BOX-095** THE SYSTEM SHALL emit `-o json` and `-o jsonl` output under the versioned schemas `min/v1/box`, `min/v1/event` and `min/v1/error`.
  tier:     T0
  verify:   cargo nextest run -p minimal json_output_carries_versioned_schemas
  - IF a command fails in a machine output mode THEN THE SYSTEM SHALL write one JSON object to stderr carrying `code`, `message` and `hint`.
    tier:   T0
    verify: cargo nextest run -p minimal machine_mode_error_object_on_stderr

- **BOX-097** THE SYSTEM SHALL use exit code 2 for usage errors, 3 for invalid configuration, 4 for not found, 5 for policy refusals, 7 for an unreachable host, 8 for insufficient resources, and 125 to 127 for runtime failures.
  tier:     T0
  verify:   cargo nextest run -p minimal exit_code_table

- **BOX-098** WHEN a run-style command's entrypoint exits THE SYSTEM SHALL propagate the entrypoint's exit code.
  tier:     T0
  verify:   cargo nextest run -p minimal run_style_propagates_entrypoint_exit

- **BOX-099** WHEN `min box exec <box> -- <cmd>` runs THE SYSTEM SHALL run the command inside the box's cgroup, namespaces and network posture, connect its stdio to the client's pipes, and propagate its exit code.
  tier:     T0
  verify:   cargo nextest run -p minimald exec_runs_in_box_namespaces_and_cgroup
  - WHERE `-t` is given to `min box exec` THE SYSTEM SHALL allocate a PTY inside the box and return an exec id that `min attach <box> --exec <id>` resumes.
    tier:   T0
    verify: cargo nextest run -p minimald exec_tty_returns_reattachable_id
  - WHERE `--detach` is given to `min box exec` THE SYSTEM SHALL print the exec id, capture its output to `logs --exec`, and return its exit code from `min box wait <box> --exec <id>`.
    tier:   T0
    verify: cargo nextest run -p minimald exec_detach_captures_logs_and_wait_returns_code

- **BOX-100** WHEN an exec's client disconnects THE SYSTEM SHALL end the exec and leave the box running.
  tier:     T0
  verify:   cargo nextest run -p minimald exec_client_loss_ends_exec_keeps_box

- **BOX-103** WHEN `min box stop <box> --exec <id>` runs THE SYSTEM SHALL end that exec's process group with SIGTERM, a wait, then SIGKILL.
  tier:     T0
  verify:   cargo nextest run -p minimald stop_exec_ends_process_group

- **BOX-104** WHEN an exec starts or exits THE SYSTEM SHALL record `exec_started` and `exec_exited` events carrying principal, argv, PTY flag and exit code.
  tier:     T0
  verify:   cargo nextest run -p minimald exec_events_carry_principal_argv_pty_code

- **BOX-105** IF the stored spec sets `[io] exec_enabled = false` THEN THE SYSTEM SHALL refuse `min box exec` with exit 5 naming the key.
  tier:     T0
  verify:   cargo nextest run -p minimald exec_disabled_refuses_exit5

- **BOX-106** THE SYSTEM SHALL accept `min session exec` as a hidden alias of `min box exec` for one release.
  tier:     T0
  verify:   cargo nextest run -p minimal session_exec_alias_hidden_one_release

- **BOX-107** THE SYSTEM SHALL accept `session activate` (mapping a path to the entry and `--name` to the box name, `--network` and `--ingress` to the overrides), `session destroy`, `session exec`, `session rename`, `session policy`, `session hooks`, `session run`, `task run --keep`, and bare `stop` as hidden aliases of their new forms for one release, printing one stderr hint naming the replacement and leaving `-o json` output unchanged.
  tier:     T0
  verify:   cargo nextest run -p minimal legacy_session_verbs_alias_with_hint
  - IF an alias from BOX-106 or BOX-107 is invoked after the release that accepted it THEN THE SYSTEM SHALL fail with exit 2 carrying the same hint.
    tier:   T0
    verify: cargo nextest run -p minimal aliases_exit2_after_grace_release

- **BOX-108** THE SYSTEM SHALL keep `session setup-zed` hidden and unchanged.
  tier:     T0
  verify:   cargo nextest run -p minimal setup_zed_unchanged

- **BOX-110** THE SYSTEM SHALL describe only the new grammar in the synced reference and concept docs, with one migration note listing the aliases and their removal release.
  tier:     T0
  verify:   cargo nextest run -p minimal docs_describe_new_grammar_with_migration_note

- **BOX-111** THE SYSTEM SHALL keep `min ls` as the alias of `min box list`.
  tier:     T0
  verify:   cargo nextest run -p minimal ls_aliases_box_list

- **BOX-112** THE SYSTEM SHALL name the well-known local providers `local0..N` (native daemon) and `local-minvmd0..N` (one per VM), each with exactly one host of the same name, and accept `local-minimald` and `local-minvmd` as aliases for one release with a hint.
  tier:     T0
  verify:   cargo nextest run -p minimal local_provider_names_and_aliases

- **BOX-113** WHEN `min host list` runs THE SYSTEM SHALL render each local host with its name and state, beside the resource figures BRES-014 adds.
  tier:     T0
  verify:   cargo nextest run -p minimal host_list_name_and_state

- **BOX-114** WHEN `min host show <host>` runs THE SYSTEM SHALL add the host-side socket path and the daemon version.
  tier:     T0
  verify:   cargo nextest run -p minimal host_show_socket_and_version

- **BOX-115** WHEN `min host stop <host>` runs THE SYSTEM SHALL stop that daemon, and its VM where one exists, once its boxes are stopped, or at once under `--force`.
  tier:     T0
  verify:   cargo nextest run -p minimal host_stop_stops_daemon_and_vm
  <!-- runs on the VM lane (NET-107): the behaviour exists only with the VM host daemon in the loop -->

- **BOX-116** THE SYSTEM SHALL map bare `min stop`, a BOX-107 alias, to `min host stop` on the local host for one release, after which BOX-107 applies.
  tier:     T0
  verify:   cargo nextest run -p minimal bare_stop_aliases_host_stop

- **BOX-117** THE SYSTEM SHALL show the host of every box in `min ls` and `min box list`.
  tier:     T0
  verify:   cargo nextest run -p minimal list_shows_host_per_box

- **BOX-147** WHEN `min provider list --all` runs THE SYSTEM SHALL list every well-known local provider present on the machine.
  tier:     T0
  verify:   cargo nextest run -p minimal provider_list_all_shows_local_providers

### O5 Un-enrolled

- **BOX-140** WHILE no identity plane is configured THE SYSTEM SHALL perform creation, stop, resume, exec, events, cp and prune over the local socket's file-mode trust, omit `identity.sock` from the box, and report `identity: none` in `min box show`.
  tier:     T0
  verify:   cargo nextest run -p minimald unenrolled_operations_over_file_mode_trust

- **BOX-141** WHILE no identity plane is configured THE SYSTEM SHALL pass a `[secrets] source = "store"` reference through unchanged.
  tier:     T0
  verify:   cargo nextest run -p minimald store_secret_passed_through_unenrolled

- **BOX-142** THE SYSTEM SHALL produce identical spec bytes and projection digest for one `minimal.toml` whether the host facts are un-enrolled or enrolled.
  tier:     T1
  verify:   cargo nextest run -p mfile enrolled_and_unenrolled_expansion_identical
  property: For every minimal.toml, expansion under un-enrolled and enrolled host facts yields identical spec bytes and projection digest.

- **BOX-143** THE SYSTEM SHALL key every record, event and audit entry on `box_id`, resolve a CLI name lookup to the current alias's `box_id`, and keep every id-addressed reference resolving across a rename.
  tier:     T1
  verify:   cargo nextest run -p sessions nothing_keys_on_box_name
  property: For every id-addressed operation in the record, event and audit APIs, the result is invariant under renaming any box; a name lookup resolves the current alias and only the current alias.

## Non-goals

- Network enforcement, box names in DNS, port publication, forwarding, ingress, and the VM egress filter: the networking spec, `docs/specs/18-spec-box-networking` (NET), and its epic gominimal/minimal#1437. This spec accepts and passes the `[network]` section (BOX-076 to BOX-080); NET enforces it.
- Credentialed egress, the node-local egress proxy, `[network.bep]`, `[secrets]` resolution, `min auth`, `min secret`, and `min box audit`: the egress-proxy spec, `docs/specs/24-spec-box-egress-proxy` (BEP), and gominimal/minimal#1501.
- Behaviour specific to the `agent`, `service`, `build`, and `container-build` types beyond expansion and validation (`service restart`, the agent harness, hermetic builds): the Agent Box epic gominimal/inbox#678 and successors.
- Nesting, the `local-box` provider, and running `min` inside a box, including `min box spec self`: gominimal/inbox#568.
- Memory and resource declaration, admission, the per-box cgroup limit, OOM handling and `enforced`/`advisory` reporting (epic story S15): the sibling spec `docs/specs/26-spec-box-resources`.
- The dash (epic story S14: type, state, provider and host columns; resume, reap and start from the list; the create form over entries): an amendment to `docs/specs/07-spec-min-dash-tui`, filed as a follow-up issue on that spec when this merges.
- The local providers serving the Box Provider API (epic story S16, BPA-013): they wait on gominimal/arch#45 and are specified once it settles transport and authentication.
- A test-suite requirement per requirement (epic story S18): every requirement's `tier:` and `verify:` lines carry it, and the golden vectors are BOX-145.
- Box Volumes: the sibling spec `docs/specs/27-spec-box-volumes`.
- Remote creation, attach, listing, and providers, and any enrolled-host identity: the parked CRA, RHC and Box Provider API epics (gominimal/inbox#668, #669, arch PR #45).
- Any automatic reaper or retention TTL: gominimal/arch#75.
- Guest VM sizing and the reserve left to the workstation: gominimal/inbox#698.
- `min box sync`, `min box port`, and `min box cp` beyond stopped-box retrieval: the architecture's `min box` reference; not scheduled by this epic.

## Design reasoning

**One spec, one codebase.** The epic's surfaces (CLI, daemon, expander, TUI, local provider) live in one codebase, and its four amendments to the architecture of record are one-line changes with no spec process of their own. The alternatives were a sibling spec in the architecture repository, rejected because it would carry four lines under a second prefix, and a sibling in the identity plane, rejected because the un-enrolled path changes nothing there. The amendments are Open questions here and issues on the architecture repository.

**Host-agnostic requirements, exercised on the two local providers.** Every requirement is written for any host a daemon runs on and verified on `local0` and `local-minvmd0`; a remote host inherits them unchanged, which is what makes the local box the remote box. The alternative, naming the local providers in the requirements, was rejected because the remote work would then re-specify the same behaviours. Three exceptions are deliberate: BOX-112 and BOX-147 name the well-known local providers because those names are the behaviour, BOX-002 applies only where the host is a VM, and BOX-140 names `identity.sock` because its absence is what un-enrolled means inside a box.

**The local Box Provider API, resources and the dash moved out on the author's review.** The epic committed all three. The local providers' obligations under the Box Provider API wait on gominimal/arch#45's transport and authentication decision; memory and resource declaration, admission, limits and OOM handling are the sibling spec `docs/specs/26-spec-box-resources`; and the dash is an amendment to `docs/specs/07-spec-min-dash-tui`. Each non-goal names its destination.

**VM-host behaviours run on the VM lane.** Minting the id outside the VM and stopping a VM host exist only with the VM host daemon in the loop, so their tests name the VM lane (NET-107) rather than `tier: none`. The alternative left the VM path unverified.

**Stop states the order, not the duration.** `min box stop` is SIGTERM, a wait, SIGKILL; the length of the wait is the daemon's and is an open question. Fixing ten seconds would have made a test own a number the architecture does not state; a per-entry `stop_grace` key would add schema the architecture lacks.

**Legacy tables map to their real meaning.** Today's single `[session]` table is a project-wide contribution to every session, so it reads as `[defaults.session]`, not as one named entry, which would have silently dropped the project's packages from any second session. The top-level `[params]` schema is renamed `[args]` and the per-task `args` key is left alone, the smallest change that lets a per-entry `[params]` take the architecture's meaning. A task with `interactive = true` is refused with a hint rather than mapped, because the `task` type constrains `pty_enabled` false.

**`min shell` with several entries and no `default` is a usage error.** Starting the first entry in file order would depend on layout; prompting was rejected as more code for the daily loop. Listing the candidates matches the ambiguous-name rule.

**A name is unique per host; a task ending is not a stop.** Per-host uniqueness follows the architecture's addressing (`provider/host/name`) and lets a laptop and a remote host both run `dev`. The daemon's never-stop rule covers idleness and client loss (gominimal/arch#74); a task reaching the end of its entrypoint is completion, recorded as `exited` with reason `exit`.

**Expander version skew reports and continues.** The projection digest comparison (BOX-072) is the check that refuses; a version difference is reported so an operator can act, but compatible skews across an upgrade are not blocked.

**The event log is out of reach of in-box root.** It sits outside the box's mount namespace, so the requirement is stated for every process in the box's namespaces including one running as root inside, and is testable as such. Limiting it to ordinary processes was rejected as a weaker claim than the mechanism already provides.

**Tiers.** Expansion and merge (BOX-048, 064, 065, 142) and type constraints (BOX-059 to 062) are T1 property tests, which constrains the expander and the type resolver to pure functions over in-memory inputs; names and ids (BOX-004, 005, 010, 143) are T1 over operation sequences, which forbids any name-keyed index; the record state machine (BOX-011, 012) is a T2 Kani harness, which constrains transitions to a pure function separate from disk writes, the shape the daemon's policy harnesses already use. T3 is refused throughout: there is no Lean project, and the surrounding behaviour is not safe sequential Rust.

**Generality:** a second implementation of the daemon, on a second provider or platform, fits: every requirement names the surface (record, spec, projection, grammar), and none names a provider or a file path apart from the exceptions under host-agnostic requirements above; the identity-plane requirements are written for the un-enrolled case and the enrolled case is the same spec bytes (BOX-142). What breaks if not: a host that cannot mint the id outside a VM cannot be a VM host (BOX-002), and a host whose expander disagrees with the client's refuses creation (BOX-072).

## Security considerations

- **Invariant:** THE SYSTEM SHALL identify a box by its `box_id` and never by its name.
  enforced by: the record store keys every record, event, and audit entry on the id and resolves a name to the current alias's id; rename changes one field (Gatehouse §5.2; BEP-070 for entropy and collision refusal)
  covered by: BOX-001, BOX-010, BOX-143
- **Invariant:** THE SYSTEM SHALL mint every `box_id` outside the VM escape boundary.
  enforced by: the native daemon on `local0`, the VM host daemon on `local-minvmd` (BEP-070; Gatehouse §6.10)
  covered by: BOX-001, BOX-002
- **Invariant:** THE SYSTEM SHALL refuse creation when the client's and the daemon's Box Spec projections differ.
  enforced by: independent recomputation in the daemon over the received spec (Gatehouse §6.3.2, T21)
  covered by: BOX-071, BOX-072
- **Invariant:** THE SYSTEM SHALL let a Box Type constraint only narrow a spec, never widen it.
  enforced by: constraint intersection at expansion (architecture design principle 9; Policy layers and precedence)
  covered by: BOX-061, BOX-062
- **Invariant:** THE SYSTEM SHALL keep a box's events stream unwritable from any process in the box's namespaces.
  enforced by: the record lives outside the box's mount namespace
  covered by: BOX-041
- **Invariant:** THE SYSTEM SHALL fail a brokered secret reference on an un-enrolled host with no node-local proxy rather than resolve it by other means.
  enforced by: minimald's `gatehouse_unenrolled_node` refusal at creation, not the expander, so expansion stays identical across host facts (Gatehouse §6.2; BOX-142)
  covered by: BOX-081

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): the stop grace duration between SIGTERM and SIGKILL (BOX-013, BOX-103) is unstated in the architecture; the daemon owns it until an architecture line fixes it (gominimal/arch#98).]
- [NEEDS CLARIFICATION (MEDIUM): the architecture's exit-code table has no row for a task timeout; BOX-037 uses 124 by convention beside 137 for OOM and needs the row added (gominimal/arch#97).]
- [NEEDS CLARIFICATION (MEDIUM): the architecture's command tree lacks `min box rename` and `min host stop`, its event list lacks `renamed` and `resumed` (both named in gominimal/arch#98) and `detached` (to be added to arch#98), `box.toml` lacks `hooks_on_resume`, and it names no box states; BOX-010, BOX-011, BOX-016, BOX-028, BOX-040 and BOX-115 are written to this spec's additions pending one architecture line each (gominimal/arch#98).]
- [NEEDS CLARIFICATION (MEDIUM): `box.toml` writes flat `egress_allow_*` keys while NET-060 and BEP-008 bind nested `egress.*`; BOX-076 follows the two merged specs and `box.toml` needs aligning (gominimal/arch#99).]
- [NEEDS CLARIFICATION (LOW): how the host surfaces `[params]` values to the entrypoint (file, path, format key); BOX-085 accepts and renders only, and `box.toml` says only JSON/YAML/TOML (gominimal/arch#100).]
- [NEEDS CLARIFICATION (LOW): `[io] exec_enabled` is still marked proposed in the architecture; BOX-105 honours it from the stored spec and follows whatever the architecture rules.]
