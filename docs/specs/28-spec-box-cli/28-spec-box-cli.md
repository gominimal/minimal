---
id: BCLI
title: The box grammar (`min box`, the type nouns, and the migration from the session verbs)
owner: mitodrummer
epic: gominimal/inbox#731
arch: https://github.com/gominimal/arch/blob/7a86ec7bb3c07103644d364550e10870fa66d639/architecture.md
arch_sha: "7a86ec7bb3c07103644d364550e10870fa66d639"
updated: 2026-11-03
---

# BCLI — The box grammar (`min box`, the type nouns, and the migration from the session verbs)

## Context

Today a user drives a session with `min session activate`, `attach`, `destroy`, `exec`, `rename`, `policy`, `hooks` and `run`. `min task run --keep` runs a task, and a bare `min stop` stops the daemon. The `min box` noun has only `spec`, `audit`, `list` and `show`. `min box spec [path]` renders a project's Box Egress Proxy rows (BEP-038), and `min box audit` reads a box's audit records (BEP-042). `min box list` prints each box's type and state, but not its provider or host. The architecture's command tree names one grammar instead. It has `min box` verbs for any box, and the type nouns `session` and `task` as filtered forms of them. It adds `min type`, `min host`, `min provider`, versioned `-o json` schemas and one exit-code table. This spec specifies those long forms, with `min host` limited to `list|show|stop` and `min provider` to `list`. The daily shortcuts layered on them are design work (Non-goals).

The box model is `docs/specs/29-spec-box-local-first` (BOX): the record, the spec and the operations on them. This spec is the grammar that drives those operations from `min`. It is a separate spec, so BOX merged first and unblocked the networking and egress-proxy specs. The grammar gets its own schedule and review, and merges after BOX. The surfaces are the `min` CLI with its help and completions, and the synced reference docs.

**Success:** every verb BCLI-026 and BCLI-030 name exists with its flags. The `-o json` output has the versioned schemas, and exit codes follow the architecture's table. Each old spelling works for one release with a hint naming its replacement.

**First slice:** `min box list|show|stop|rm` over the existing daemon, before any alias work. It renders id, name, type, state, provider and host (BCLI-001, BCLI-003, BCLI-004, BCLI-051, BCLI-059, BCLI-060).

## Users and stories

**Roles:** developers and agents who drive boxes from the shell. Developers who debug a box. Developers with scripts and muscle memory on the current session verbs. Developers who operate the local daemons and providers.

- AS A developer or an agent, I WANT `min box start|run|list|show|spec|stop|rm|prune|resume|rename|restart|logs|wait|events|cp|exec|attach` for any box and `min session list|start|attach|logs|stop|rm`, `min task run|list|logs|stop|rm` as aliases, SO THAT one verb means one thing under every noun, and a script written for a session works for a task.
- AS A developer debugging any box, I WANT `min box exec <box> [-t] [--detach] -- <cmd>` to run a command inside a running box under its own namespaces, limits, and posture, with a re-attachable PTY when I ask for one, SO THAT I can get a shell into a task or check a session without another mechanism.
- AS A developer with scripts and muscle memory, I WANT `min session activate`, `min session destroy`, `min session exec`, and bare `min stop` to keep working for one release with a hint naming the new verb, SO THAT the rename is a migration I can schedule, not a break I discover.
- AS A developer, I WANT `min provider list --all` to show `local` and `local-minvmd`, and `min host list|show|stop` to work on their hosts, SO THAT the daemon I stop, the VM I look at, and the provider a remote box will come from are one vocabulary.

## Requirements

<!-- Each requirement drives an operation BOX defines. BCLI-053, BCLI-055 to BCLI-057 and BCLI-068 are the exec verbs that drive BOX-149 to BOX-153. -->

### Verbs that read and drive the box record and spec

- **BCLI-001** WHEN `min box list` runs THE SYSTEM SHALL print at least the id, name, type, state, provider and host of each box BOX-158 lists. It SHALL scope the list to the current project unless the caller passes `--all`. Under `-o json` it SHALL write exactly the `"schema": "min/v1/box"` objects to stdout, and nothing else.
  tier:     T0
  verify:   cargo nextest run -p minimal box_list_prints_columns_and_schema

- **BCLI-002** THE SYSTEM SHALL accept a box address as an id, a name, or `provider/host/name`.
  <!-- BOX-007 reserves the name `self`; `self` on `min box spec|show|events` waits with running `min` inside a box (Non-goals), and `min box audit self` is BEP-042's -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_address_accepts_id_name_and_qualified
  - IF an unqualified name matches running boxes on more than one host THEN THE SYSTEM SHALL report BOX-005's refusal with exit 2. The refusal SHALL list each candidate with its host.
    tier:   T0
    verify: cargo nextest run -p minimal ambiguous_name_across_hosts_exit2_lists_candidates
  - IF only stopped or exited boxes on several hosts hold an unqualified name THEN THE SYSTEM SHALL report BOX-005's refusal with exit 2. The refusal SHALL list each candidate with its host and state.
    tier:   T0
    verify: cargo nextest run -p minimal retained_name_across_hosts_exit2_lists_host_and_state
  - IF a host is unreachable while `min` resolves an unqualified name across hosts THEN THE SYSTEM SHALL fail with exit 7 and name each unreachable host. It SHALL resolve nothing from the hosts that answered.
    tier:   T0
    verify: cargo nextest run -p minimal unqualified_name_with_unreachable_host_exit7_names_host

- **BCLI-003** WHEN `min box show <box>` runs THE SYSTEM SHALL render the record BOX-159 returns. It SHALL show the box's state as BOX-011 defines it, and its identity as BOX-140 reports it.
  <!-- the rendering of BOX-011's state model and BOX-140's identity; both stay BOX's -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_renders_state_and_identity

- **BCLI-004** IF `min box rm` targets a running box without `--force` THEN THE SYSTEM SHALL report BOX-019's refusal with exit 2 naming `--force`.
  <!-- the refusal itself is BOX-019's -->
  tier:     T0
  verify:   cargo nextest run -p minimal rm_running_box_refuses_naming_force

- **BCLI-005** IF `min box prune` runs off a TTY without `--yes` or `--dry-run` THEN THE SYSTEM SHALL fail with exit 2 naming `--yes`. A dry run reaps nothing, so it needs no `--yes` (BCLI-006).
  tier:     T0
  verify:   cargo nextest run -p minimal prune_off_tty_needs_yes

- **BCLI-006** THE SYSTEM SHALL report the disk held by each stopped or exited box in `min box show` and the sum in `min box prune --dry-run`.
  <!-- ubiquitous; BOX-021 has no dry run and BOX-159 returns no disk figure, so both halves wait on the BOX amendments gominimal/minimal#2834 tracks (Rollout) -->
  tier:     T0
  verify:   cargo nextest run -p minimal show_and_prune_dry_run_report_disk

- **BCLI-007** WHEN `min box attach`, `min session attach` or `min box resume` targets a stopped or exited box whose spec sets `pty_enabled` THE SYSTEM SHALL resume it as BOX-025 defines.
  <!-- which verbs resume; the resume itself is BOX-025's -->
  tier:     T0
  verify:   cargo nextest run -p minimal attach_and_resume_verbs_resume_stopped_pty_box
  - IF `min box attach`, `min session attach` or `min box resume` resumes a `pty_enabled` box while a running box on its host holds its name THEN THE SYSTEM SHALL report BOX-025's refusal. It SHALL exit 2 and name the running box. It SHALL check in the order BOX-025 states. Its hint offers to rename the running box with `min box rename`, or to resume this box by its `box_id` after renaming it. The hint also notes that another box can hold a volume this box declares. The volumes spec proposed in gominimal/minimal#1990 (BVOL) defines that refusal and its exit code.
    tier:   T0
    verify: cargo nextest run -p minimal resume_name_conflict_exit2_names_holder

- **BCLI-009** IF `min box attach`, `min session attach` or `min box resume` targets a stopped or exited box whose spec does not set `pty_enabled` THEN THE SYSTEM SHALL report BOX-030's refusal. It SHALL exit 2 and choose the hint by `lifetime`. The hint names `min box restart <box>` for a box whose spec sets `lifetime = "until_stopped"`, and `min box run <entry>` for a box that runs to completion. It SHALL check in the order BOX-025 states. So a non-PTY resume whose name a running box holds reports this refusal, and not BCLI-007's name hint.
  <!-- the refusal itself is BOX-030's. The hint follows `lifetime`, not type: design principle 8 (L338). Re-establishing an enrolled box's identity belongs to the identity plane and composes with this (see Design reasoning) -->
  tier:     T0
  verify:   cargo nextest run -p minimal resume_non_pty_box_exit2_hint_by_lifetime

- **BCLI-074** WHEN `min box restart <box>` runs against a box whose spec sets `lifetime = "until_stopped"` THE SYSTEM SHALL stop its processes if they run, then start them again. The new processes SHALL start from the spec stored at the box's creation (BOX-068) and its retained filesystem, under the same `box_id` and name.
  <!-- event-driven; the architecture's `min box restart` (L471), and design principle 8 (L338): `restart` follows `lifetime = "until_stopped"`, not type. BOX defines no restart operation for it (Rollout) -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_restart_until_stopped_restarts_same_id_and_name
  - IF `min box restart` targets a box whose spec does not set `lifetime = "until_stopped"` THEN THE SYSTEM SHALL fail with exit 2 and a hint naming `min box run <entry>`. This is the hint BCLI-009 chooses by `lifetime` for a box that runs to completion.
    tier:   T0
    verify: cargo nextest run -p minimal box_restart_not_until_stopped_exit2_hint_by_lifetime

- **BCLI-010** WHEN `min task run <task> [-- <args>…]` or `min box run <entry> [-- <args>…]` runs without `--detach` THE SYSTEM SHALL create a box from the entry. It SHALL connect the box's stdin, stdout and stderr to the command's, and write nothing else to stdout. The command SHALL exit with the exit code of the entrypoint.
  <!-- type-neutral, so `min box run` too; the architecture's `min box run` paragraph (L493): `run` never allocates a PTY -->
  tier:     T0
  verify:   cargo nextest run -p minimal run_entry_wires_stdio_and_exit_code
  - WHERE `min task run` or `min box run` runs with `--detach` THE SYSTEM SHALL print only the `box_id` to stdout and return. It SHALL close the box's stdin at creation, and leave its output to BOX-155's capture.
    tier:   T0
    verify: cargo nextest run -p minimal run_detach_prints_id_closes_stdin
  - IF `min box run` or `min task run` names an entry whose spec sets `pty_enabled` THEN THE SYSTEM SHALL fail with exit 2 and a hint naming `min box start --new`. It SHALL fail before it creates the box, and create nothing.
    <!-- unwanted; the architecture's `min box run` line (L469) and paragraph (L493), on and off a TTY alike -->
    tier:   T0
    verify: cargo nextest run -p minimal run_pty_entry_exit2_hints_start_new

- **BCLI-011** THE SYSTEM SHALL provide `min task run` as the task noun's run verb and remove the previous hidden `min run` that only errored.
  tier:     T0
  verify:   cargo nextest run -p minimal task_run_provided_hidden_run_removed

- **BCLI-012** WHEN `min session logs <box> -f`, `min task logs <box> -f` or `min box logs <box> -f` runs THE SYSTEM SHALL follow the box's output as BOX-155 captures it.
  <!-- event-driven; how much of the output the capture keeps is BOX-155's; gominimal/arch#159 decides the bound, and the interim cap keeps the newest 8 MiB with a drop mark -->
  tier:     T0
  verify:   cargo nextest run -p minimal type_noun_logs_follow

- **BCLI-013** WHEN `min box wait <box>` runs THE SYSTEM SHALL return the `exit_code` BOX-011 stores for the box. For a box that already ended, it SHALL read the stored `exited` event. For a `stopped` record with no `exit_code`, it SHALL return 128 plus the `signal` BOX-011 and BOX-013 store for it.
  tier:     T0
  verify:   cargo nextest run -p minimal box_wait_returns_retained_exit_code_or_128_plus_signal
  - WHEN `min box wait` reads a `stopped` record with neither `exit_code` nor `signal` (BOX-154) THE SYSTEM SHALL return 137, the shell's code for a SIGKILL end.
    tier:   T0
    verify: cargo nextest run -p minimal box_wait_orphaned_stopped_record_returns_137
  - IF `min box wait --timeout <d>` reaches `<d>` before the box ends THEN THE SYSTEM SHALL return 124 and emit a machine-mode error with `code = "timeout"`. It SHALL leave the box running.
    <!-- unwanted; the GNU `timeout` convention the architecture's 124 row borrows; that row names only the box's own timeout (gominimal/arch#160, Open questions) -->
    tier:   T0
    verify: cargo nextest run -p minimal box_wait_timeout_flag_returns_124_box_runs_on

- **BCLI-014** IF a box ends with `exited.reason = "timeout"` THEN THE SYSTEM SHALL emit a machine-mode error with `code = "timeout"` and return 124 from `min task run`, `min box run` and `min box wait`.
  <!-- the CLI half; the timeout reason is BOX-037's. `min box run` and `min box wait` follow the architecture's exit-code table (L370, L377) -->
  tier:     T0
  verify:   cargo nextest run -p minimal run_verbs_and_wait_timeout_return_124_with_code_timeout

- **BCLI-015** THE SYSTEM SHALL list exited tasks in `min task list` until a prune removes them.
  tier:     T0
  verify:   cargo nextest run -p minimal task_list_shows_exited_until_pruned

- **BCLI-016** WHEN `min box events <box> -o jsonl` runs THE SYSTEM SHALL replay the full stream as BOX-162 reads it. The stream holds the events BOX-040 writes and BOX-018 and BOX-045 retain. Each line SHALL have the fields `"schema": "min/v1/event"`, `ts`, `box`, `parent`, `type` and `data`.
  tier:     T0
  verify:   cargo nextest run -p minimal events_jsonl_replay_schema_fields
  - WHERE `min box events` runs with `--follow` THE SYSTEM SHALL replay the stream then tail it, as BOX-162's follow does.
    tier:   T0
    verify: cargo nextest run -p minimal events_follow_replays_then_tails
  - WHERE `min box events` runs with `--parent <box>` THE SYSTEM SHALL merge the children's streams.
    tier:   T0
    verify: cargo nextest run -p minimal events_parent_merges_children

- **BCLI-017** WHEN `min init` runs with no entry THE SYSTEM SHALL scaffold a `minimal.toml` in the entry-based shape.
  tier:     T0
  verify:   cargo nextest run -p minimal init_scaffolds_entry_shape

- **BCLI-018** WHEN `min init <entry> --type <type>` runs THE SYSTEM SHALL append that one entry.
  tier:     T0
  verify:   cargo nextest run -p minimal init_entry_type_appends_one
  - IF `<type>` is one BOX-063 refuses THEN THE SYSTEM SHALL fail with exit 3 as BOX-063 states and append nothing.
    tier:   T0
    verify: cargo nextest run -p minimal init_refused_type_exit3_appends_nothing
  - WHEN `min init --session <n>`, `min init --task <n>`, `min init --agent <n>` or `min init --service <n>` runs THE SYSTEM SHALL append the entry exactly as `min init <n> --type <noun>` does for that noun.
    <!-- event-driven; the architecture's `min init` reference: `min init --session dev` is exactly `min init dev --type session` -->
    tier:   T0
    verify: cargo nextest run -p minimal init_noun_flag_is_type_alias
  - IF `min init` receives more than one of `--session`, `--task`, `--agent` and `--service`, or one of them together with `--type`, THEN THE SYSTEM SHALL fail with exit 2 and append nothing.
    <!-- unwanted; the architecture makes the noun flags mutually exclusive with each other and with `--type` -->
    tier:   T0
    verify: cargo nextest run -p minimal init_noun_flags_exclusive_exit2_appends_nothing

- **BCLI-019** WHEN `min type list` runs THE SYSTEM SHALL show every resolved type: the six built-in types and each type the project defines. Each row SHALL name its source, `builtin`, `project` or `org`. It SHALL name each type as BOX-161 names the type that supplies a value.
  <!-- `org` is reserved now, in the text and the `-o json` source enum, so organization types (gominimal/inbox#579, a BOX non-goal) need no schema change; no type carries it until then -->
  tier:     T0
  verify:   cargo nextest run -p minimal type_list_shows_builtin_and_project_types_with_source

- **BCLI-020** WHEN `min type show <name>` runs THE SYSTEM SHALL render the type's defaults and constraints exactly as the architecture's table of built-in types states. It SHALL name the source of every value. The rows the table marks [proposed] are outside this requirement.
  <!-- event-driven; the table at L1181; the `[io] exec_enabled` row is in scope, and the [proposed] `on_oom` row belongs to the resources spec proposed in gominimal/minimal#1762 (BRES) -->
  tier:     T0
  verify:   cargo nextest run -p minimal type_show_matches_shipped_table_with_sources

- **BCLI-021** WHEN `min box spec <entry>` runs THE SYSTEM SHALL render the entry's expanded spec in the format `-o toml|json|yaml` names, with secrets as references only. Beside each value it SHALL name the layer and type BOX-161 reports for it. For an entry that declares a credentialed upstream, it SHALL include the rows BEP-038 renders.
  <!-- `min box spec [path]` (BEP-038) renders a project's Box Egress Proxy rows; this spec adds the entry and box forms and `-o` on top of it, and keeps the path form -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_formats_secrets_as_refs
  - WHEN `min box spec` runs without an argument or with a directory THE SYSTEM SHALL render BEP-038's rows for the project there, else the current one.
    tier:   T0
    verify: cargo nextest run -p minimal box_spec_path_form_renders_bep_rows
  - WHEN `min box spec <entry>` runs with `--network` or `--ingress` THE SYSTEM SHALL pass the flag's value to BOX-064's command-line override layer exactly as BCLI-024 does. Its expanded spec SHALL have the same BOX-065 bytes as the spec `min box start` sends with the same flags. The comparison excludes the `-o` format and the layer and type beside each value.
    tier:   T0
    verify: cargo nextest run -p minimal box_spec_entry_network_flags_match_start

- **BCLI-022** WHEN `min box spec <box>` addresses a box (BCLI-002) THE SYSTEM SHALL render the spec stored in that box's record.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_box_renders_stored_copy
  - WHEN the argument of `min box spec` is not a directory THE SYSTEM SHALL read it as an entry of the current project, else as a box address.
    tier:   T0
    verify: cargo nextest run -p minimal box_spec_argument_directory_then_entry_then_box
  - WHEN `min box spec <box>` renders a stored spec THE SYSTEM SHALL list each lifecycle hook in the spec. Each row SHALL show the hook's transition and whether it is inline or external.
    <!-- event-driven; the rows `min session hooks` lists today (11-spec-lifecycle-hooks, Disabling and listing), less the declarer: BOX-068 stores the expanded spec, in which BOX-064 merges every layer's `lifecycle_hooks` into one list, so the record keeps no declarer (Open questions); a box created with hooks disabled carries none -->
    tier:   T0
    verify: cargo nextest run -p minimal box_spec_box_lists_hooks

- **BCLI-023** THE SYSTEM SHALL render every section of a spec in `min box spec` whether or not the current host enforces it.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_unenforced_sections

- **BCLI-024** WHEN `min session start` or `min box start` runs with `--network` or `--ingress` THE SYSTEM SHALL pass the flag's value to BOX-064's command-line override layer. That layer applies last, after loadouts. The stored spec, its projection and `min box show --network` SHALL all hold the overridden `[network]` value. The reference SHALL document both flags as overrides of the entry's `[network]` keys.
  tier:     T0
  verify:   cargo nextest run -p minimal network_flags_override_stored_spec_and_projection

- **BCLI-073** WHERE an entry sets `loadout_mode = "open"`, WHEN `min box start` runs with `--loadout <l>` THE SYSTEM SHALL pass each loadout that `--loadout` names to BOX-064's selected-loadouts layer. The stored spec SHALL hold each of them. `min session start` SHALL do the same.
  <!-- event-driven; the architecture's `session start` and `box start` carry `--loadout <l>…` (gominimal/arch#124), a per-invocation Loadout Entry. `open` is the session type's default. What `sealed` and `upstream-only` admit is a residual of the Agent Box epic gominimal/inbox#678, which BOX's Non-goals name, so this requirement binds only the `open` case -->
  tier:     T0
  verify:   cargo nextest run -p minimal start_loadout_flag_selects_loadouts_layer

- **BCLI-025** WHEN `min box show <box> --network` runs THE SYSTEM SHALL render the effective `[network]` section from the stored spec.
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_network_renders_effective

### The command tree, aliases and hosts

- **BCLI-026** THE SYSTEM SHALL provide `min box start`, `run`, `list`, `show`, `spec`, `stop`, `rm`, `prune`, `resume`, `rename`, `restart`, `logs`, `wait`, `events`, `cp`, `exec` and `attach` with the flags the architecture's command reference lists. The exceptions are the Non-goals: `--all-providers`, `--provider` naming a remote provider, `--using <pkg>[@<ver>]`, `min box wait --parent <box|self> [--any]`, and `self` as the value of `--parent`. The verbs SHALL also take BCLI-053's `--timeout` for `exec`, BCLI-068's `--exec` for `attach`, BCLI-069's `--name` for `start` and `run`, and BCLI-070's `--new` for `start`.
  <!-- limited to the flags this spec delivers, the rest in Non-goals -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_verbs_exist_with_arch_flags

- **BCLI-027** THE SYSTEM SHALL accept the plural of every countable noun.
  tier:     T0
  verify:   cargo nextest run -p minimal plural_nouns_accepted

- **BCLI-028** THE SYSTEM SHALL generate `--help` at every level and shell completions from one command model.
  tier:     T0
  verify:   cargo nextest run -p minimal help_and_completions_from_one_model

- **BCLI-029** WHEN `min box start [<entry>]` or `min session start [<entry>]` runs THE SYSTEM SHALL create the box. Where its spec sets `pty_enabled` and the caller does not pass `--detach`, it SHALL attach the caller's terminal to the box. Otherwise it SHALL print the id and return.
  tier:     T0
  verify:   cargo nextest run -p minimal start_attaches_pty_box_unless_detached
  - IF `min box start` or `min session start` runs off a TTY without `--detach` for an entry whose spec sets `pty_enabled` THEN THE SYSTEM SHALL fail with exit 2 naming `--detach`. It SHALL fail before it creates the box, and create nothing.
    tier:   T0
    verify: cargo nextest run -p minimal start_off_tty_exit2_names_detach
  - WHERE `min box start` or `min session start` returns unattached and the spec does not set `pty_enabled` THE SYSTEM SHALL close the box's stdin at creation. It SHALL print one stderr hint. The hint SHALL name `min box run` for wired stdio, and `min box logs` and `min box wait` for the output and exit code. A `pty_enabled` box keeps its terminal input for a later attach (BCLI-068).
    tier:   T0
    verify: cargo nextest run -p minimal unattached_start_closes_stdin_and_hints_run_logs_wait

- **BCLI-069** WHERE `min box start`, `min box run`, `min session start` or `min task run` runs with `--name <name>` THE SYSTEM SHALL pass the name to BOX-064's command-line override layer as `[box] name`. BOX-163 then names the box with it, or bases a fresh instance's `<name>-<n>` on it.
  tier:     T0
  verify:   cargo nextest run -p minimal create_verbs_name_flag_overrides_box_name
  - IF `min box start` or `min session start` without `--new` creates a box whose name a running box on the same host holds THEN THE SYSTEM SHALL report BOX-163's refusal. It SHALL exit 2 and name the holder, with a hint naming `--new` and `--name`.
    tier:   T0
    verify: cargo nextest run -p minimal create_name_held_exit2_names_holder_hints_name_flag

- **BCLI-070** WHEN `min task run` or `min box run` runs, or `min box start` or `min session start` runs with `--new`, THE SYSTEM SHALL request a fresh instance. BOX-163 then names the box `<name>-<n>` and never refuses it for a held name.
  tier:     T0
  verify:   cargo nextest run -p minimal run_and_start_new_request_fresh_instance

- **BCLI-071** WHEN `min session start` runs with no entry THE SYSTEM SHALL start the `default` session entry, else the project's only session entry. When it counts session entries, it SHALL include the implicit `default` entry BOX-165 expands.
  tier:     T0
  verify:   cargo nextest run -p minimal session_start_without_entry_picks_default_else_sole
  - IF `min session start` runs with no entry and the project declares several session entries, none of them `default`, THEN THE SYSTEM SHALL fail with exit 2. It SHALL list the session entries, with a hint naming `min session start <entry>`.
    tier:   T0
    verify: cargo nextest run -p minimal session_start_without_entry_ambiguous_exit2_lists_entries
  - IF a bare `min session start` finds zero session entries, and another type's entry blocks BOX-165's implicit `default`, THEN THE SYSTEM SHALL fail with exit 2. It SHALL name that entry, with a hint to declare a session entry or rename the blocking entry.
    tier:   T0
    verify: cargo nextest run -p minimal session_start_without_entry_blocked_default_exit2_names_fix

- **BCLI-072** WHEN `min box start` runs with no entry THE SYSTEM SHALL start the `default` entry, whatever its type, else the project's only entry. When it counts entries, it SHALL include the implicit `default` entry BOX-165 expands.
  tier:     T0
  verify:   cargo nextest run -p minimal box_start_without_entry_picks_default_else_sole
  - IF `min box start` runs with no entry and the project declares several entries, none of them `default`, THEN THE SYSTEM SHALL fail with exit 2. It SHALL list the entries, with a hint naming `min box start <entry>`.
    tier:   T0
    verify: cargo nextest run -p minimal box_start_without_entry_ambiguous_exit2_lists_entries

- **BCLI-030** THE SYSTEM SHALL provide `min session list|start|attach|logs|stop|rm` and `min task run|list|logs|stop|rm` as aliases of the `min box` forms, filtered to boxes of that type, `min session attach` included (BCLI-032).
  tier:     T0
  verify:   cargo nextest run -p minimal type_noun_verbs_alias_box_forms

- **BCLI-032** WHEN `min session attach <box>` runs THE SYSTEM SHALL behave as `min box attach <box>` (BCLI-068), filtered to boxes of type `session`.
  tier:     T0
  verify:   cargo nextest run -p minimal session_attach_is_box_attach_filtered_to_sessions
  - IF `min session attach` targets a box without `pty_enabled` THEN THE SYSTEM SHALL report BCLI-068's refusal for a box without a PTY.
    tier:   T0
    verify: cargo nextest run -p minimal session_attach_non_pty_reports_box_attach_refusal
  - WHEN `min session attach` runs with no address THE SYSTEM SHALL resolve the box as a bare `min box attach` does (BCLI-068), counting only boxes of type `session`.
    <!-- event-driven; the architecture's `min box attach` paragraph (L491): `min session attach` is the same verb filtered to sessions, with and without an address -->
    tier:   T0
    verify: cargo nextest run -p minimal session_attach_without_address_picks_project_else_sole
  - IF `min session attach` runs with no address and more than one session box is a candidate THEN THE SYSTEM SHALL fail with exit 2 listing them.
    <!-- unwanted; design principle 3 admits a prompt only for destructive or file-access decisions, so no picker on a TTY either -->
    tier:   T0
    verify: cargo nextest run -p minimal session_attach_without_address_ambiguous_exit2_lists
  - IF `min session attach` runs with no address and no session box is a candidate THEN THE SYSTEM SHALL fail with exit 4 and a hint naming `min session start`.
    tier:   T0
    verify: cargo nextest run -p minimal session_attach_without_address_none_exit4_hints_start
  - IF a bare `min session attach` meets an unreachable host while it looks up session boxes THEN THE SYSTEM SHALL fail with exit 7. It SHALL name each unreachable host and attach to nothing.
    <!-- unwanted; BCLI-002's rule for an incomplete cross-host lookup takes precedence, since an unreachable host can hold another candidate -->
    tier:   T0
    verify: cargo nextest run -p minimal session_attach_without_address_unreachable_host_exit7

- **BCLI-033** THE SYSTEM SHALL emit every object in `-o json` and `-o jsonl` output with a `schema` field `min/v1/<type>`, the types being `box`, `event`, `error`, `type`, `host`, `provider`, `spec` and `exec` (the exec listing in `box show`).
  <!-- bound to every object, as the architecture's Output conventions (L381) and design principle 4 (L334) state -->
  tier:     T0
  verify:   cargo nextest run -p minimal json_output_schema_per_object
  - IF a command fails in a machine output mode THEN THE SYSTEM SHALL write one JSON object to stderr carrying `code`, `message` and `hint`.
    tier:   T0
    verify: cargo nextest run -p minimal machine_mode_error_object_on_stderr

- **BCLI-063** WHEN a `min` command renders a spec, record, event or error object THE SYSTEM SHALL write each secret as a reference only. It SHALL do so in every output mode, and never write the secret's value.
  tier:     T1
  verify:   cargo nextest run -p minimal secrets_rendered_as_refs_in_every_output_mode
  property: pick any output mode and any secret-bearing field of a rendered object. The rendered output contains the secret's reference and never its value.

- **BCLI-064** IF a box address resolves to no box under BOX-005 THEN THE SYSTEM SHALL fail with exit 4, naming the address. This applies to every `min box`, `min session` and `min task` verb, and runs before any other check on the box. Parsing the command line comes before it, so an expired alias (BCLI-042) fails with exit 2 and its hint before any address resolves. During its window, `session destroy --force` is the one exception: an address that resolves to no box exits 0 (BCLI-042). BCLI-002's unreachable-host refusal (exit 7) wins over it. A name that the reachable hosts lack can still exist on an unreachable one.
  <!-- unwanted; the architecture's exit-code table, row 4 -->
  tier:     T0
  verify:   cargo nextest run -p minimal unknown_box_address_exit4_names_address

- **BCLI-034** THE SYSTEM SHALL end each command with the exit code the architecture's exit-code table assigns to its outcome. The rows the table marks [proposed] are outside this requirement.
  <!-- ubiquitous; bound to the table as a whole so the spec restates no partial list; the [proposed] rows, exit 8 and exit 5's provider-quota case, belong to the resources spec proposed in gominimal/minimal#1762 (BRES, epic gominimal/inbox#698) -->
  tier:     T0
  verify:   cargo nextest run -p minimal exit_code_table

- **BCLI-035** WHEN a run-style command's entrypoint exits THE SYSTEM SHALL propagate its exit code.
  tier:     T0
  verify:   cargo nextest run -p minimal run_style_propagates_entrypoint_exit

- **BCLI-053** WHEN `min box exec <box> -- <cmd>` runs THE SYSTEM SHALL execute the command in the box as BOX-149 defines, and exit with the command's exit code. It SHALL report BOX-149's refusal of a box that is not running with exit 2, and BOX-153's `exec_enabled = false` refusal with exit 5.
  <!-- the presentation half of BOX-149's exec operation; the architecture's exit-code table puts the state refusal under 2 and the `exec_enabled` refusal under 5 (L363, L366) -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_exec_runs_command_and_exits_with_its_code
  - WHERE `min box exec` runs with `-t` THE SYSTEM SHALL request a PTY exec as BOX-149 defines and print its exec id to stderr. It SHALL write nothing but the exec's output to stdout.
    tier:   T0
    verify: cargo nextest run -p minimal box_exec_tty_prints_exec_id_to_stderr
  - WHERE `min box exec` runs with `--detach` THE SYSTEM SHALL start a detached exec as BOX-149 defines, print only its exec id to stdout, and return.
    tier:   T0
    verify: cargo nextest run -p minimal box_exec_detach_prints_id_and_returns
  - WHERE `min box exec` runs with `--timeout <duration>` THE SYSTEM SHALL request the exec's own timeout as BOX-149 defines.
    tier:   T0
    verify: cargo nextest run -p minimal box_exec_timeout_flag_requests_exec_timeout
  - IF an exec ends at its own timeout (BOX-149) THEN THE SYSTEM SHALL emit a machine-mode error with `code = "timeout"`. Both `min box exec` and `min box wait <box> --exec <id>` SHALL return 124.
    tier:   T0
    verify: cargo nextest run -p minimal exec_timeout_returns_124_from_exec_and_wait_exec

- **BCLI-067** WHEN `min box show <box>` runs THE SYSTEM SHALL list the box's live execs. Each row SHALL show the exec id, the argv, and whether the exec holds a PTY or runs detached.
  tier:     T0
  verify:   cargo nextest run -p minimal box_show_lists_live_execs

- **BCLI-068** WHEN `min box attach <box>` runs without `--exec` against a box whose spec sets `pty_enabled` THE SYSTEM SHALL re-attach the caller's terminal to the box's PTY.
  tier:     T0
  verify:   cargo nextest run -p minimal box_attach_reattaches_pty_box
  - IF `min box attach` runs without a client TTY THEN THE SYSTEM SHALL fail with exit 2. It SHALL fail before it resumes the box (BCLI-007), so the box's state and events stay unchanged.
    <!-- unwanted; the architecture's `min box attach` paragraph and design principle 3 -->
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_without_tty_exit2
  - IF `min box attach <box>` runs without `--exec` against a running box whose spec does not set `pty_enabled` THEN THE SYSTEM SHALL fail with exit 2, naming `min box logs <box>`. Against a stopped or exited box without `pty_enabled`, BCLI-009's restart refusal applies instead, with BCLI-009's hint by `lifetime`. `min session attach` (BCLI-032) inherits the same split.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_running_non_pty_box_exit2_names_logs
  - WHEN `min box attach <box> --exec <exec-id>` names a live PTY exec in the box THE SYSTEM SHALL re-attach the caller's terminal to that exec as BOX-149 defines. It SHALL resolve the exec id against the live exec ids BOX-159 returns.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_exec_reattaches_live_pty_exec
  - IF the exec id does not name an exec of the box, live or ended, THEN THE SYSTEM SHALL fail with exit 4, naming the exec id. This check comes first. The ended-exec refusal comes next, and the no-PTY refusal last.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_exec_unknown_id_exit4_names_id
  - IF the exec id names a live exec that did not request a PTY THEN THE SYSTEM SHALL fail with exit 2, naming `min box logs <box> --exec <exec-id>`.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_exec_non_pty_exit2_names_logs
  - IF the exec id names an exec that ended, with or without a PTY, THEN THE SYSTEM SHALL fail with exit 4, naming `min box logs <box> --exec <exec-id>` and `min box wait <box> --exec <exec-id>`.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_exec_ended_exit4_names_logs_and_wait
  - WHEN `min box attach` runs with no address THE SYSTEM SHALL attach to the current project's running box whose spec sets `pty_enabled`. Without one, it SHALL attach to the project's only retained box whose spec sets `pty_enabled`, and resume it as BCLI-007 does. The project root BOX-001 records identifies the project's boxes.
    <!-- event-driven; the architecture's `min box attach` line (L470) and paragraph (L491) -->
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_without_address_picks_running_else_sole_retained
  - IF `min box attach` runs with no address and more than one box is a candidate THEN THE SYSTEM SHALL fail with exit 2 listing them.
    <!-- unwanted; no picker, as design principle 3 admits a prompt only for destructive or file-access decisions -->
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_without_address_ambiguous_exit2_lists
  - IF `min box attach` runs with no address and no box is a candidate THEN THE SYSTEM SHALL fail with exit 4 and a hint naming `min box start`.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_without_address_none_exit4_hints_start
  - IF a bare `min box attach` meets an unreachable host while it looks up candidates THEN THE SYSTEM SHALL fail with exit 7. It SHALL name each unreachable host and attach to nothing.
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_without_address_unreachable_host_exit7
  - IF `min box attach` runs with `--exec` and no box THEN THE SYSTEM SHALL fail with exit 2.
    <!-- unwanted; a PTY exec can run in any box, not only the one the bare form finds -->
    tier:   T0
    verify: cargo nextest run -p minimal box_attach_exec_without_box_exit2
  - WHEN the caller detaches, or the box's entrypoint exits on its own, THE SYSTEM SHALL end the attach with exit code 0.
    <!-- event-driven; this covers `min box attach` and `min session attach`, with or without `--exec` -->
    tier:   T0
    verify: cargo nextest run -p minimal attach_detach_or_entrypoint_exit_returns_0
  - IF the daemon ends an attach from the other side THEN THE SYSTEM SHALL exit with 254 after one stderr line that names the cause. The other side is a stop or removal of the box, or another client that takes its PTY. A stop or removal gives 254 although it also ends the entrypoint.
    tier:   T0
    verify: cargo nextest run -p minimal attach_ended_from_other_side_notice_exit254
  - IF the connection to the box's host fails during an attach THEN THE SYSTEM SHALL fail with exit 7 naming the host.
    tier:   T0
    verify: cargo nextest run -p minimal attach_connection_failure_exit7

- **BCLI-055** WHEN `min box stop <box> --exec <id>` runs THE SYSTEM SHALL stop that exec as BOX-151 defines.
  <!-- the presentation half of BOX-151's exec stop -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_stop_exec_stops_that_exec

- **BCLI-056** WHEN `min box logs <box> --exec <id>` runs THE SYSTEM SHALL print that exec's captured output as BOX-149 defines.
  <!-- the presentation half of BOX-149's exec operation; the bound on the capture is gominimal/arch#159's, as for BCLI-012 -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_logs_exec_prints_exec_output

- **BCLI-057** WHEN `min box wait <box> --exec <id>` runs THE SYSTEM SHALL return that exec's retained exit code as BOX-149 defines.
  <!-- the presentation half of BOX-149's exec operation -->
  tier:     T0
  verify:   cargo nextest run -p minimal box_wait_exec_returns_exec_code

- **BCLI-058** WHEN `min box rename <box> <name>` runs THE SYSTEM SHALL rename the box as BOX-010 defines, reporting BOX-010's refusal with exit 2 naming the holder.
  tier:     T0
  verify:   cargo nextest run -p minimal box_rename_renames_as_box_010

- **BCLI-059** WHEN `min box stop <box>` runs without `--exec` THE SYSTEM SHALL stop the box as BOX-013 defines, requesting BOX-013's forced stop under `--force`.
  tier:     T0
  verify:   cargo nextest run -p minimal box_stop_stops_as_box_013_force_forces

- **BCLI-060** WHEN `min box rm <box>` runs THE SYSTEM SHALL reap the box as BOX-019 defines, requesting BOX-019's forced reap under `--force`.
  tier:     T0
  verify:   cargo nextest run -p minimal box_rm_reaps_as_box_019_force_forces

- **BCLI-061** WHEN `min box prune` runs THE SYSTEM SHALL prune as BOX-021 defines, narrowed by the `older-than <d>` or `parent <box>` selector for `--older-than <d>` or `--parent <box>`.
  tier:     T0
  verify:   cargo nextest run -p minimal box_prune_flags_map_to_box_021_selectors

- **BCLI-062** WHEN `min box cp <box>:<path> <local>` targets a stopped or exited box THE SYSTEM SHALL copy the file from the retained filesystem as BOX-017 serves it.
  tier:     T0
  verify:   cargo nextest run -p minimal box_cp_reads_stopped_box_as_box_017

- **BCLI-042** THE SYSTEM SHALL accept each old spelling below as a hidden alias until its window ends. Each alias SHALL print one stderr hint naming the replacement after the command ends, and leave `-o json` output unchanged. When an alias fails in a machine output mode, the hint SHALL be the `hint` field of BCLI-033's error object, with no separate line. `session activate` maps to `session start` as its sub-bullets state. `session destroy` maps to `box rm --force`, with or without `--force`. Under `--force`, an address that resolves to no box exits 0, as today. `session destroy --all` maps to `box rm --force` on every box of type `session` the local host lists, filtered as BCLI-030 filters `session` verbs. `session exec` maps to `box exec`. One command argument runs as the box's shell `-c '<argument>'`, as today, and the hint names `min box exec <box> -- sh -c '…'`. `session rename` maps to `box rename`. `session policy` maps to `box show --network`, with its `-o`. `session hooks <name>` resolves `<name>` as a box address (BCLI-002) and maps to `box spec <box-id>` for that box, never to an entry of the same name. Its hint names `min box spec <box-id>` with the box's id, because `min box spec <name>` reads an entry first (BCLI-022). Its `--json` maps to `-o json`. `task run --keep` maps to `task run`, which ignores `--keep`, and `task run --path <dir>` to the global `-C <dir>`. Bare `stop` maps to `host stop` on the local host today's `min stop` stops, with the global flags passed through unchanged. Without `--force`, the alias checks that host for running boxes before it calls `host stop`. `host stop` itself does not check (BCLI-049). While any box runs there, it fails with exit 2. It prints today's refusal message unchanged, because the installer matches that message (07-spec-installer). With `--force`, it maps to `host stop --force`.
  <!-- the mapping follows epic S12. `session destroy` maps to the forced reap (BOX-019) so a live box is still stopped and removed and BEP-043's revoke-on-destroy fires; a bare `session rm` of a running box is refused (BCLI-004). `session hooks` maps to the hook rows of `box spec <box>` (BCLI-022), since the record `box show` renders holds no hooks. A bare `session attach` is no alias: it is BCLI-032's permanent form -->
  tier:     T0
  verify:   cargo nextest run -p minimal legacy_session_verbs_alias_with_hint
  - WHEN `min session activate` runs without `--attach` THE SYSTEM SHALL create the box as `min session start --detach` does. With `--attach`, it SHALL create the box as `min session start` does and attach the caller's terminal. Without a path, it SHALL pick the entry as a bare `min session start` does (BCLI-071).
    <!-- event-driven; today's `activate` attaches only under `--attach`, and succeeds off a TTY without it, so scripts that call it keep working through the window -->
    tier:   T0
    verify: cargo nextest run -p minimal activate_alias_detaches_unless_attach_flag
  - WHEN `min session activate` runs with a path, `--name`, `--network`, `--ingress`, `--loadout`, `--no-loadouts` or `--no-prompt` THE SYSTEM SHALL map each one. A path names the project as the global `-C <path>` does. `--name` maps to BCLI-069's `--name`, `--network` and `--ingress` to BCLI-024's overrides, and `--loadout` to BCLI-073's layer. `--no-loadouts` leaves BOX-064's selected-loadouts layer empty, the client config's default loadouts included. `--no-prompt` maps to the global `--no-input`.
    tier:   T0
    verify: cargo nextest run -p minimal activate_alias_maps_create_flags
  - WHEN `min session activate` gets a network policy flag THE SYSTEM SHALL set the key below in BOX-064's command-line override layer. The stored spec and its projection SHALL hold that value.
    - `--dynamic-ingress <allow|ask|deny>` sets `dynamic_ingress` (NET-043).
    - `--dynamic-range <lo>-<hi>` sets `dynamic_allowed_range` to that inclusive port range (NET-047).
    - `--allow-subnets`, `--allow-dns-hosts`, `--allow-protocols` and `--deny-subnets` each add one item to `egress.allow_subnets`, `egress.allow_dns_hosts`, `egress.allow_protocols` and `egress.deny_subnets` (NET-060). Each use of the flag adds one item.
    - `--deny-all-egress` declares every allow list in `egress` present and empty (NET-140).
    - `--credentialed-upstream` declares the box's credentialed upstream present, with no hosts of its own (BEP-012).
    <!-- event-driven; NET-140 defines `--deny-all-egress` as every allow list present and empty, so the alias never starts a box with egress open where the caller asked for none -->
    tier:   T0
    verify: cargo nextest run -p minimal activate_alias_maps_network_policy_flags_to_override_layer
  - WHEN `min session activate` runs with `--sync` or `--no-hooks` THE SYSTEM SHALL keep the flag's meaning on `min session activate`. `--sync` selects how the project's files load into the box. `--no-hooks` runs none of the box's lifecycle hooks, as the lifecycle-hooks spec defines.
    <!-- event-driven; the architecture's grammar has neither flag, so each keeps its meaning for the window only (Open questions) -->
    tier:   T0
    verify: cargo nextest run -p minimal activate_alias_keeps_sync_and_no_hooks
  - IF an alias receives a flag that is neither mapped nor global THEN THE SYSTEM SHALL fail with exit 2, naming the flag. It SHALL run nothing. A flag's short form, such as `-n` on `activate` or `-f` on `stop` and `destroy`, maps where its long form maps.
    <!-- unwanted; an alias never drops a flag, so a flag a later release adds to an old spelling is refused until a mapping names it -->
    tier:   T0
    verify: cargo nextest run -p minimal alias_unmapped_flag_exit2_names_flag
  - IF a caller uses an alias after its window ends THEN THE SYSTEM SHALL fail with exit 2 and the same hint. An alias's window ends one release after every requirement and script that the Rollout lists for it uses the new spelling. This applies to every alias of BCLI-042 and BCLI-046.
    tier:   T0
    verify: cargo nextest run -p minimal aliases_exit2_after_grace_release

- **BCLI-066** IF a caller runs `min session run` THEN THE SYSTEM SHALL fail with exit 2 and a hint naming `min task run <task>`.
  tier:     T0
  verify:   cargo nextest run -p minimal session_run_exit2_hints_task_run

- **BCLI-043** THE SYSTEM SHALL keep `session setup-zed` hidden and unchanged.
  tier:     T0
  verify:   cargo nextest run -p minimal setup_zed_unchanged

- **BCLI-044** THE SYSTEM SHALL document every verb BCLI-026 and BCLI-030 name in the CLI reference, `docs/reference/cli-min.md`.
  <!-- the reference-reading test form NET-036 and NET-111 use; the justfile has no doc-check recipe -->
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reference_documents_box_grammar
  - THE SYSTEM SHALL name each alias of BCLI-042 and BCLI-046, with its replacement and removal release, only in one migration note in `docs/reference` and `docs/concepts`.
    tier:   T0
    verify: cargo nextest run -p minimal docs_name_aliases_only_in_one_migration_note

- **BCLI-046** THE SYSTEM SHALL name the well-known local providers `local`, `local-minvmd` and `local-box`, and name each of their hosts by its daemon instance (`local0..N`, `local-minvmd0..N`).
  <!-- one provider per local deployment style, and hosts carry the instance names (gominimal/arch#45) -->
  tier:     T0
  verify:   cargo nextest run -p minimal local_provider_and_host_names
  - WHERE a command runs with `--provider local-minimald` THE SYSTEM SHALL read it as `local` for one release and print one stderr hint naming `local` after the command ends.
    tier:   T0
    verify: cargo nextest run -p minimal local_minimald_alias_reads_as_local

- **BCLI-047** WHEN `min host list` runs THE SYSTEM SHALL render each local host with its name and state. The resources spec proposed in gominimal/minimal#1762 (BRES, epic gominimal/inbox#698) adds its resource figures beside them.
  tier:     T0
  verify:   cargo nextest run -p minimal host_list_name_and_state

- **BCLI-048** WHEN `min host show <host>` runs THE SYSTEM SHALL add the host-side socket path and the daemon version.
  tier:     T0
  verify:   cargo nextest run -p minimal host_show_socket_and_version

- **BCLI-049** WHEN `min host stop <host>` runs THE SYSTEM SHALL stop each running box on that host as BOX-013 defines. It SHALL then stop that daemon, and its VM where one exists.
  tier:     T0
  verify:   ./scripts/session-e2e.sh host_stop_stops_boxes_then_daemon_and_vm
  <!-- the session e2e the VM lanes run, as NET-049 and NET-107 are verified: the behaviour exists only with the VM host daemon in the loop -->
  - WHERE `min host stop` runs with `--force` THE SYSTEM SHALL stop each running box with BOX-013's forced stop. It SHALL then stop the daemon without waiting for its clean shutdown.
    tier:   T0
    verify: cargo nextest run -p minimal host_stop_force_forces_boxes_and_daemon

- **BCLI-051** THE SYSTEM SHALL show the host of every box in `min box list`.
  tier:     T0
  verify:   cargo nextest run -p minimal list_shows_host_per_box

- **BCLI-052** WHEN `min provider list --all` runs THE SYSTEM SHALL list every well-known local provider present on the machine.
  tier:     T0
  verify:   cargo nextest run -p minimal provider_list_all_shows_local_providers

## Non-goals

- The box model belongs to `docs/specs/29-spec-box-local-first` (BOX). That covers the record with its states and retention, the expanded spec and the projection. It also covers stop, reap, resume, rename, events and the un-enrolled path. This spec renders and drives them, and does not add behaviour to them.
- Resource verbs and figures belong to the resources spec proposed in gominimal/minimal#1762 (BRES), from the epic gominimal/inbox#698. They include the capacity, allocatable, allocated, default box size and enforcement figures of `min host list|show`. They also include the 137 return on an OOM end.
- Volume verbs (`min volume list|show|rm|prune`): the volumes spec proposed in gominimal/minimal#1990 (BVOL), which carries them as BVOL-006, BVOL-007 and BVOL-012. BRES and BVOL keep their own verbs because they are small and move with the behaviour they render.
- The dash (epic story S14): an amendment to `docs/specs/07-spec-min-dash-tui`.
- The Box Provider API and its local providers (epic story S16): the Box Provider spec proposed in gominimal/minimal#2667 (BPA). For `local` and `local-minvmd`, `min` is the provider. It walks the per-host state directories and reads each host over that host's own socket. Only `local-box` has a daemon that serves it, the parent minimald inside a box (architecture L53). So `min host` and `min provider` read the local hosts directly, and this spec specifies no listener.
- `min box sync`, `min box port` and `min box add`: the architecture's `min box` reference names them, and no spec or epic schedules them yet (Open questions).
- `--all-providers`, and `--provider` naming a remote provider: they select remote providers, which need a provider that BPA serves. The global `--provider` flag stays. It selects one of the well-known local providers (BCLI-046) for any `min` command, and the `min box` verbs and the type nouns take it from there.
- The global flags and their environment variables, from `-o` and `--no-input` to `--host` and the `MIN_*` variables, belong to the architecture's Global flags table (L342). This spec neither adds a global flag nor removes one. Each global flag `min` has keeps its meaning, and passes through BCLI-042's aliases unchanged.
- `min box list --using <pkg>[@<ver>]`: it reads a box's SBOM, which the SBOM epic owns (gominimal/inbox#582).
- `min box wait --parent <box|self> [--any]`, and `self` as the value of `--parent` on the verbs this spec specifies: they manage a box's children, which needs nesting. Nesting has no owner yet (Open questions).
- `self` as the box argument of `min box spec`, `min box show` and `min box events`: only a `min` running inside a box can use it. The BOX spec leaves that out of scope, and these verbs take `self` with nesting. `min box audit` already takes `self` and `--parent self` (BEP-042), and this spec does not change that.
- `min host create|pause|resume|rm` and `min provider show|add|rm|login|use`: they drive the operations BPA defines, and no spec or epic schedules their verbs yet (Open questions). The architecture reserves `min host snapshot`, and no provider serves it.
- The `min agent` and `min service` nouns, including `min service restart`: the Agent Box epic gominimal/inbox#678.
- `min box audit`: the egress-proxy spec, `docs/specs/24-spec-box-egress-proxy` (BEP).
- Daily shortcuts (`min shell`, `min run`, `min attach`, `min ls` and any like them): user-experience design layered on this grammar, specified from design work and user journeys, not here. Today's `min ls` is left as it is.

## Design reasoning

**The grammar is a sibling of the model.** The grammar is a separate spec from BOX, for three reasons. First, the networking and egress-proxy specs bind to the box spec and record, which the model owns. They waited on the model, so BOX merged first. Second, the grammar gets its own schedule and review. Third, a client other than the CLI binds to the model. So BOX states its behaviour as operations, and this spec maps verbs onto them. The exec operations are daemon behaviour and live in BOX as BOX-149 to BOX-153. They cover the command run in the box and client loss. They also cover `exec_enabled`, and the stop and events of an exec. BCLI-053, BCLI-055 to BCLI-057 and BCLI-068 are only the verbs and flags that drive them.

**The grammar specifies the long forms, and leaves the daily shortcuts to design work.** This spec specifies the `min box` verbs and the type nouns, which tie to the domain model. It leaves out the daily shortcuts `min shell`, `min run`, `min attach` and `min ls`. Those are user-experience design built on this grammar from design work and user journeys. A requirement whose trigger included a shortcut keeps its long-form trigger. `min box attach` and its filtered form `min session attach` stand for `min attach` (BCLI-007, BCLI-009, BCLI-032, BCLI-068). `min task run` stands for `min run` (BCLI-010, BCLI-014, BCLI-066). A shortcut with no long form, such as `min shell` or `min ls`, has no requirement here. Re-attaching a detached PTY exec gets a long form, `min box attach <box> --exec <exec-id>` (BCLI-068). Without it, nothing can re-attach a PTY exec whose client left. Without `--exec`, `min box attach <box>` re-attaches the box's own PTY, as the bare form of every other verb targets the box. With no address, it attaches the project's PTY box (BCLI-068). `min session attach` is its filtered form for the type noun (BCLI-032). The aliases for today's spellings (BCLI-042) stay, because they serve the migration. The architecture's command tree has no shortcuts. It has `min box attach`, bare and with `--exec`, with `session attach` as its alias (gominimal/arch#114). It also has a per-exec `--timeout` on `min box exec` (BCLI-053). An exec can have its own timeout (BOX-149). A timed-out exec returns 124 from `min box exec` and `min box wait --exec`, the convention BCLI-014 uses for a task.

**The listing's columns are a floor.** BCLI-001 names the minimum columns. A listing can add banners and more columns, as today's listing does. The `-o json` schema stays exact, so scripts can bind to it.

**`min init` names a type as the architecture does.** `--type <type>` is the general form and takes any type, a project-defined one included. `--session`, `--task`, `--agent` and `--service` are its aliases, and BCLI-018 keeps them mutually exclusive with each other and with `--type`, as the architecture's `min init` reference states. `min type list` shows the project's types beside the built-in ones, each with its source (BCLI-019).

**A secret is never rendered, in any output mode.** BCLI-063 is T1, with a property over every output mode and every secret-bearing field. The invariant is a universal. One example test leaves every untested mode free to leak.

**Old spellings hint for one release, then fail.** This spec takes the architecture's command tree verbatim, apart from the daily shortcuts. It adds `min box rename`, `min box attach` (BCLI-068), `min box exec --timeout` (BCLI-053), `--name` on the create verbs (BCLI-069) and `min host stop`. It also adds `min box prune --dry-run` (BCLI-006) and the create-time `--network` and `--ingress` overrides (BCLI-024). `min box spec <entry>` accepts those overrides too, so the pre-flight render is what the daemon receives (BCLI-021). The architecture has every one of them (gominimal/arch#117, gominimal/arch#124). The architecture's `min box prune` has no `--stopped` (gominimal/arch#112), so BCLI-061 does not accept it. `session destroy` maps to `box rm --force`, because the forced reap still stops a live session and removes it, and BEP-043's revoke-on-destroy still fires. A plain `session rm` refuses a running box (BCLI-004). `session policy` stays reachable as an alias of `box show --network` (BCLI-025). That successor shows NET-061's effective egress and the exposures of the draft GWI-003. Every old spelling stays as a hidden alias, and prints one hint naming its replacement. Its window ends one release after every requirement and script that the Rollout lists for it uses the new spelling. After that, it fails with exit 2 and the same hint (BCLI-042, BCLI-046). The old spellings are the session verbs except `session run`, `task run --keep`, bare `min stop`, and the `local-minimald` provider value. Bare `min stop` maps to `min host stop` because today it stops the daemon. During its window the alias keeps today's refusal while boxes run, so a script that relied on that refusal never stops running boxes.

**`session activate` keeps its behaviour through the window, and an alias never drops a flag.** Today `min session activate` attaches only under `--attach`, and it succeeds off a TTY. `min session start` attaches a PTY box by default, and refuses off a TTY without `--detach` (BCLI-029). So the alias maps a plain `activate` to `start --detach`, and `activate --attach` to `start`. Every script and end-to-end setup that calls `activate` then keeps working until the alias expires. Each of today's `activate` flags keeps its meaning through a mapping (BCLI-042). A flag with no mapping fails with exit 2. A silent drop of `--deny-all-egress` starts the box with egress open, which is the failure that rule prevents. A second `activate` under a name a running box holds gets BOX-163's refusal, as it does today, and the alias adds no `--new`. `session hooks` maps to `box spec <box>`, which lists each hook with its transition (BCLI-022). It does not show a declarer, because the record does not keep one (Open questions). The record that `box show` renders does not hold hooks.

**An alias hint follows the command, never an attached terminal.** `session activate --attach` attaches the caller's terminal to a shell. A line before that shell goes under its prompt, or mixes with its output in the PTY stream. So each hint from BCLI-042 and BCLI-046 prints after the command ends and the shell gives the terminal back. The caller then reads it at their own prompt. One rule for every alias keeps the hint in one place and one test. `--provider local-minimald` is a global flag, and the same rule keeps its hint off a healthy `min session start`.

**`min session run` fails at once, with no alias.** `min session run` fails with exit 2 and a hint naming `min task run <task>` (BCLI-066), and BCLI-042 has no row for it. The alternative is to alias it to `box exec <box> -- min task run <task>`. That needs `min` inside the box and the nested `local-box` provider, and nesting has no owner yet (Open questions). On a stock box it exits 127, so a one-release alias cannot work for this verb.

**The exec id never enters the exec's stdout.** `min box exec -t` prints the exec id to stderr, so stdout has only the exec's output. `--detach` has no other output, so it prints only the id on stdout. `min box show <box>` lists the live execs (BCLI-053, BCLI-067). The id stays off stdout under `-t`. There it ends up in the attached PTY stream and in any transcript that wraps it. That breaks the architecture's payload-only stdout (design principle 4).

**Resume restarts processes, and enrolled identity composes with it.** BCLI-007 and BCLI-009 drive the restart of a stopped or exited box's processes that BOX-025 and BOX-030 define. The refusal is only for restarting the processes of a non-PTY box. Its hint follows `lifetime`, not type (design principle 8). A box whose spec sets `lifetime = "until_stopped"` comes back with `min box restart` (BCLI-074). A box that runs to completion comes back with a new `min box run <entry>`. Under enrollment, the identity plane re-establishes the identity of any box, non-PTY included, and the architecture names `min box resume <box>` among its paths. That composes with this, as the Design reasoning of BOX states. A resume refused because a running box holds the name exits 2. The architecture's exit-code table puts a name that the target does not admit under 2. A resume refused because another box holds a volume the box declares belongs to BVOL, which sets its exit code. The name check runs before the spec and volume checks, so a resume that meets both refusals reports the name.

**`run` and `--new` make a fresh instance, and a plain `start` refuses a held name.** The architecture's Addressing rule (gominimal/arch#117) has `start` create the box under its name. `start` refuses a name that a running box on the host holds. `run` and `start --new` create a fresh instance, `<name>-<n>`. BCLI-069 reports the refusal with a hint naming `--new` and `--name`, and BCLI-070 maps `run` and `--new` onto BOX-163's fresh instance. So a second concurrent `min task run build` on one host succeeds as `build-1`, which is the CI case. `run` never refuses a held name, because such a refusal stops that second run.

**`run` follows the architecture's stdio contract and never allocates a PTY.** The architecture's `min box run` wires the box's stdio to the command and writes only the payload to stdout (design principle 4). An entry whose spec sets `pty_enabled` fails with exit 2 and a hint naming `min box start --new` (BCLI-010). Each alternative fails. An attach makes `run` a copy of `start --new`. Plain pipes into a `pty_enabled` entry make a session box with no terminal, which the type requires. Interactive use of a PTY entry stays with `min box start --new` and `min box exec -t`.

**A bare attach resolves within the project, and an unreachable host refuses rather than guesses.** The architecture's `min box attach` takes an optional address, and so does `session attach`. With none, it attaches the project's running PTY box, else the project's only retained one (BCLI-068, BCLI-032). It resolves by the project root BOX-001 records. So a developer enters their project's session from its directory, and the bare form is permanent. An ambiguous match fails with exit 2 listing the candidates instead of opening a picker. Design principle 3 admits a prompt only for destructive or file-access decisions. Resolving an unqualified name across hosts refuses with exit 7 when a host does not answer (BCLI-002). A match on the hosts that answered is not known to be the only one, and picking it bypasses BOX-005's ambiguity refusal.

**A bare `start` picks `default`, else the only entry.** The architecture states this rule (gominimal/arch#124). `min session start` with no entry starts the `default` session entry, else the only session entry (BCLI-071). `min box start` with no entry starts the `default` entry, whatever its type, else the only entry (BCLI-072). Entry names are unique across a project (BOX-046), so at most one entry has the name `default`. More than one candidate is exit 2 listing them. `min box start` picks by name and never by type, as design principle 8 requires, and the preference for sessions lives in the type noun. A project with no session entry has BOX-165's implicit `default`, so bare `min session start`, and through BCLI-042 bare `min session activate`, keeps working for every `[session]`-only project. A non-session `default` entry blocks the implicit one, and bare `min session start` then fails with exit 2 naming the fix.

**`min host stop` stops the boxes first.** BCLI-049 stops each running box as BOX-013 defines, then the daemon. `--force` forces both. So a host shuts down in one step. Each stopped PTY box can resume later, and an `until_stopped` box comes back with `min box restart`. The architecture's `host stop` paragraph says every record resumes later, and gominimal/arch#148 corrects it. Refusing while any box runs makes the caller stop each box by hand first, for no gain in safety. A record left `running` by a daemon that did not get to stop it becomes `stopped` on restart (BOX-154).

**`min box wait` returns 128 plus the stored signal.** A stop that a signal ended stores that signal (BOX-011, BOX-013). BCLI-013 returns 128 plus it, the shell convention: 143 for SIGTERM, 137 for SIGKILL. A fixed reserved code for every stop hides which signal ended the box. A record that BOX-154 set to `stopped` does not store a signal, because the daemon that ended it is gone. BCLI-013 returns 137 for it. That is the code of a process killed outright, which is what an unclean daemon end amounts to.

**One provider per local deployment style, with hosts named after the instances.** The architecture names one provider per local deployment style (gominimal/arch#45). The `0..N` suffix is the state-directory convention, so it names hosts, not providers. `local` serves the native daemons on this machine, `local-minvmd` serves its VMs, and `local-box` serves the parent daemon of the box `min` runs in. `local-minvmd/local-minvmd0/<box>` is a box on the first VM. The architecture's global `--host` flag names a host too, and it arrives with the global flags (Non-goals). `local-minvmd` is a canonical provider name and does not expire, so NET-049, NET-051 and TEL-034 cite the right spelling. `local-box` exists only inside a box, which needs nesting (Non-goals), so BCLI-052 lists it only where it is present. A local host's endpoint is `unix:<path>` with port 0. The socket's file mode is its access control, as §3 of the Box Provider API states.

**`min box spec` keeps its path form and adds the entry and box forms.** `min box spec [path]` renders the Box Egress Proxy rows for a project (BEP-038). This spec keeps that form and adds the architecture's `<entry>` and `<box>` forms and `-o` (BCLI-021, BCLI-022). One positional argument takes all three forms. `min box spec` tries a directory first, so each existing `min box spec <path>` call keeps its output. Any other argument names an entry of the current project, else a box. The entry form shows BEP-038's rows inside the expanded spec, beside the values they come from.

**`min host show` names the host-side socket only.** On the VM provider it is the host-side socket the client connects to (BCLI-048). The in-VM path is an in-VM fact the client never uses, so `min host show` leaves it out.

**Stopping a VM host runs on the VM lane.** It exists only with the VM host daemon in the loop. So BCLI-049's test is a case of `scripts/session-e2e.sh`, the session proof the VM lanes run, as NET-049 and NET-107 are.

**Generality:** the grammar binds to the operations BOX defines, and never to the internals of a daemon. So a second client, such as the dash or the client of a remote provider, drives the same operations without this grammar. The same `provider/host/name` addresses a second host. The deliberate exceptions are BCLI-046 and BCLI-052, which name the well-known local providers because those names are the behaviour.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never write a secret value in any output mode.
  enforced by: every rendering shows a secret as a reference only (the architecture's Output conventions).
  covered by: BCLI-063

## Rollout

**BCLI-074 needs a restart operation that BOX does not define.** BCLI-074 drives the restart of a box whose spec sets `lifetime = "until_stopped"`. BOX resumes only a box whose spec sets `pty_enabled` (BOX-025, BOX-030). Its Non-goals send the `until_stopped` rules to the Agent Box epic gominimal/inbox#678. BCLI-074 needs a daemon operation that restarts an `until_stopped` box, and so do the hints of BCLI-009 and BCLI-068 that name `min box restart <box>`. That operation comes from an amendment to `docs/specs/29-spec-box-local-first` in its own PR, tracked by gominimal/minimal#2761. BCLI-074 and those hints depend on it.

**BCLI-006 needs a dry run and a disk figure that BOX does not define.** `min box prune --dry-run` needs a prune that lists what it matches and the disk each box holds, and reaps nothing. BOX-021 defines no such mode. gominimal/minimal#2834 tracks that mode and the BOX-021 amendment that names it. The `min box show` half needs the disk a stopped or exited box holds, and the record BOX-159 returns has no such figure. The same issue tracks the BOX-159 amendment that adds it. The figure counts what a reap frees and excludes Box Volumes, which a reap leaves in place (BVOL-008). BCLI-006 depends on gominimal/minimal#2834.

**Merged requirements and scripts cite spellings BCLI-042 and BCLI-046 remove.** These requirements and scripts on main use an old spelling. `scripts/session-e2e.sh` is the VM lane's session proof, and BCLI-049's verify line runs it. Each alias it calls stays open until it moves:

- `min session activate`: NET-018, NET-020, NET-035, NET-040, NET-049, NET-051 and NET-122, the last in a sub-bullet's comment. A BOX-001 sub-bullet cites it too. The installer's closing card names `min session activate --attach .` (`docs/specs/07-spec-installer`, R10.4). The lifecycle-hooks spec cites `min session activate --no-hooks` (`docs/specs/11-spec-lifecycle-hooks`). Scripts: `scripts/session-e2e.sh`, `scripts/bulk-upload-e2e.sh`, `scripts/stress-session-e2e.sh` and `scripts/kernel-bump-review.sh`.
- `min session policy`: NET-044, NET-058, NET-061, NET-075, NET-130 (in a sub-bullet's comment), NET-140, NET-146 and a NET-160 sub-bullet's comment, and BEP-085's comment. The draft GWI-003 cites it too. Script: `scripts/session-e2e.sh`.
- `min session hooks`: the lifecycle-hooks spec. Script: `scripts/session-e2e.sh`.
- `min session rename`: no requirement. Script: `scripts/session-e2e.sh`.
- `min session destroy`: NET-058 and BEP-043. Scripts: `scripts/session-e2e.sh`, and `scripts/bulk-upload-e2e.sh`, whose cleanup runs `session destroy --all --force`.
- `min session exec`: NET-058, a NET-015 sub-bullet and TEL-031. Script: `scripts/session-e2e.sh`.
- Bare `min stop`: TEL-011, and the installer's R5.5. The installer, `scripts/install.sh`, runs `min stop` and matches its refusal for live sessions by message. Without that match it runs `min stop --force`. The end-to-end scripts `scripts/session-e2e.sh`, `scripts/stress-session-e2e.sh` and `scripts/bulk-upload-e2e.sh`, and the installer's tests in `scripts/install_test.sh`, call `min stop` too.

BCLI-042's sub-bullet ends an alias's window one release after the requirements and scripts listed for it above use the new spelling. So the installer changes first. Once bare `min stop` fails, an installer that still calls it does not see the refusal it matches. It then force-stops every upgrade.

The same NET-015 sub-bullet also cites `min session run`, which BCLI-066 refuses at once, with no alias window. A task runs as its own box, not inside a session, so NET-015 must cite `min task run` before the release that contains BCLI-066.

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): nesting has no owner. The BOX Non-goals name gominimal/inbox#568, which closed as a duplicate, and gominimal/inbox#572 closed as not planned. `min box wait --parent` and `--parent self` wait on whichever spec or epic takes nesting up.]
- [NEEDS CLARIFICATION (MEDIUM): `min box sync`, `min box port`, `min box add`, `min host create|pause|resume|rm` and `min provider show|add|rm|login|use` have no owner. The architecture names them, BPA defines the provider operations under the host and provider verbs, and BPA names this spec for the grammar. gominimal/minimal#2868 decides which spec owns each verb and schedules them.]
- [NEEDS CLARIFICATION (MEDIUM): `min session hooks` names the loadout or project that declared each hook, from the daemon's saved composition snapshot (11-spec-lifecycle-hooks). BOX does not keep a declarer. BOX-064 merges every layer's hooks into one list, and BOX-161 reports provenance only at expansion, by layer. So BCLI-022 lists hooks without a declarer. A BOX amendment that stores each hook's declarer will restore the column.]
- [NEEDS CLARIFICATION (MEDIUM): the architecture's grammar has no `--no-hooks` and no `--sync`. BCLI-042 keeps both on `min session activate` for its window only. After it, nothing disables a box's lifecycle hooks at creation. The architecture decides whether `min box start` takes such a flag in gominimal/arch#161, and the lifecycle-hooks spec follows it.]
- [NEEDS CLARIFICATION (LOW): the architecture's 124 row names only a box that its own `timeout` ended. BCLI-013 returns 124 when `min box wait --timeout` elapses too, with the box still running, the GNU `timeout` convention. The architecture's exit-code table has to state this case (gominimal/arch#160).]
- [NEEDS CLARIFICATION (LOW): `min box spec` tries a directory before an entry name (BCLI-021, BCLI-022). So a bare name cannot reach an entry that shares its name with a directory here. One fix moves the path form to `--repo-dir`, with a one-release alias. Another gives the entry form a marker that a path cannot carry. Until someone picks one, the directory comes first.]
