---
id: TEL
status: draft
title: Opt-in OpenTelemetry traces, logs and a local spool for min, minimald and minvmd
owner: unassigned
epic: gominimal/inbox#515
arch: gominimal/arch (architecture.md AT7, AT20, the Box Spec `[otel]` block; specs/networking/deployment-and-egress-gateway.md §5.1)
arch_sha: "5c1201517ba07347344fb9725efb06ee39d5c03e"
updated: 2026-10-06
---

# TEL: opt-in OpenTelemetry traces, logs and a local spool

## Context

When a `min` command is slow or fails, the work it caused runs in several
processes. The CLI does part of it, the session daemon (`minimald`, natively
or as the microVM guest's `/init`) does part, and the VM supervisor
(`minvmd`) does the rest. Each writes its own log. Nothing joins those logs
except a `trace_id` field that a person has to grep for by hand
([spec 10](../10-spec-diagnostics/10-spec-diagnostics.md), Unit 4). Spec 10
kept the OpenTelemetry runtime out of scope and left an exporter as later
work. This spec is that work.

With this work in a release, a user who opts in gets every process's spans
and log records at a collector they run. The records travel as OTLP over
HTTP, joined into one trace per command. The same user also gets a local
OTLP-JSON copy of those records that survives a crash. A user who does not opt in gets nothing new.

**Arch alignment (re-checked 2026-10-05 against `gominimal/arch` `5c120151`).**
This spec covers AT20 ("telemetry is opt-in and minimized") and the
threat-model scrub rule of gominimal/inbox#515 follow-up 4. Where this spec
differs from AT20, gominimal/arch#102 carries the amendment, and this spec
differs from AT20 until arch#102 closes. A box receives `TRACEPARENT` and
nothing else from the host telemetry environment (TEL-023, TEL-024,
TEL-005). Propagation into the box is in scope. The decision is option 2 of
gominimal/arch#103: the host telemetry environment decides, with no Box
Spec key. Reporting `TRACEPARENT` as an injected variable is TEL-047, a
known gap until `min box spec` exists (spec 24). A
nested `min` continues the caller's trace without exporting itself (TEL-025,
TEL-026, decision 2026-10-04, "option A"). The guest daemon's records reach
the host over vsock port 7353 and leave the host under the host's switches
(TEL-034, [guest-vsock.md](guest-vsock.md)).
Some related items stay out of this spec. The Box Spec `[otel]` workload
mapping of `architecture.md` (Story 8) applies to spec-declared keys, never
to the host's ambient variables. The `min telemetry` subcommands wait for the
command-tree ruling gominimal/arch#101. How telemetry leaves a Box Host is
gominimal/arch#105 (the epic's decision 4). That question applies to every
VM-backed box, local VMs included, and the lab proves the guest path on
LocalVM only. Gatehouse audit export is gominimal/arch#104.

**Success:** with `MINIMAL_TELEMETRY=1` and an endpoint set, run one `min`
command that starts a VM and runs a command in a box. The collector shows it
as one trace. That trace holds the CLI's `cmd` span, the daemon's `rpc` and
`exec` spans, `minvmd`'s `vm.boot` and the guest's `guest.ready`. Without the
opt-in, the same command does not open a connection and does not write a
telemetry file.

**First slice:** `MINIMAL_TELEMETRY=1 min ls` against a local collector: the
`cmd` span and the daemon's `rpc` span arrive in one trace, and the same
records are in the spool.

## Users and stories

This spec transcribes the stories from gominimal/inbox#515 and keeps its numbers.
The commits that build them cite the spec's former numbering, in which the
minvmd and guest work was "Story 4". That work is the VM clause of Story 1
here. The epic's Story 4 (sharing with Minimal) is a Non-goal.

**Roles:** a developer who runs `min` on a laptop and needs to see where a
command's time went. Also a Minimal support engineer who reads a user's
bundle, and a platform engineer who runs their own collector. And a team
that runs `min` in CI.

- AS A developer debugging a failure, I WANT every `min` operation recorded
  as a trace on my own machine, SO THAT I can see what happened across the
  CLI, daemon, and VM without re-running with debug flags (Story 1).
- AS A Minimal support engineer, I WANT the diagnostic bundle to include the
  full trace of the failing operation, SO THAT I start from a span waterfall
  instead of grepping logs (Story 2).
- AS A platform engineer, I WANT minimal's telemetry in my own OTel
  collector, SO THAT minimal shows up in the same dashboards and alerts as
  the rest of our build and dev infrastructure (Story 3).
- AS A team running minimal in CI, I WANT my build's own OTel spans to nest
  under the `min run` span, SO THAT one trace shows the runner, the VM, and
  the build tool (Story 8).
- A telemetry failure is a silent no-op. It never affects a command or the
  `min bug` path (principle 8).

This spec covers these of the epic's acceptance criteria. From Story 1: the
spool with its age and size bounds, one trace from the CLI through the
daemons and the guest, and `OTEL_SDK_DISABLED`. From Story 2: the spool in
`min bug`. From Story 3: the `MINIMAL_TELEMETRY` opt-in with the
`MINIMAL_`-prefixed names, static headers, OTLP over HTTP/protobuf, and a
collector that never slows a command. From Story 8: `TRACEPARENT` into the
box with every other host telemetry variable scrubbed. Non-goals lists the
rest.

## Requirements

Requirements are `TEL-NNN` in document order. The headings are those of the
lab's requirement table (opt-in, best effort, spool, one trace, minvmd,
shutdown, privacy, diagnostics). The appendix maps the lab's former ids to
these. Each requirement has these fields.

`verify:` is the command that runs the in-tree test. It reads `lab scenario
NNN (not in tree)` when only the lab's end-to-end scenarios check the
requirement, and `none` when nothing checks it yet. `test:` is the in-tree
test or Kani harness, as `path::name`. `lab:` lists the lab scenarios that
also check it. Those scenarios are in the lab harness, not in this
repository, and the spec names them so a reviewer can ask for the run.

Kani harnesses run with `just kani`. In CI the Kani lane's path filter
does not name `crates/mlog` or `crates/minvmd`, so a pull request that
changes only their harnesses does not run it. Widening that frozen
workflow is a maintainer-owned change (gominimal/minimal#2075). A test marked
"known gap" runs no product code. It names one gap, what covers it today
and its issue, and fails on request (`TEST_KNOWN_GAPS=1`) so a lane can
list the gaps. It is removed when the requirement gets a real test. These
are the known gaps on 2026-10-07, each with an issue to follow. TEL-009
has lab scenario 785 only. TEL-034 has its VM test in the tree, gated
`MINVMD_E2E=1` so it runs on the VM lane only, and lab scenario 715b. TEL-044 has unit tests for its
scrub and lab scenario 782 for the whole path. TEL-047 has
no check, because nothing reports a box's injected environment yet
(minimal#2036, spec 24). macOS was verified by hand once, on arm64 on
2026-10-05. `min` and `minvmd` built there and 486 unit tests passed. One
traced command ran through `minvmd` to `vm.boot` with `libkrun`, and the
boot line was byte-identical with telemetry off. That run found a TEL-032
bug, a task that held the start phase open past READY, which is fixed and
has a unit test. No repeatable macOS VM lane exists yet (minimal#2037).

### Opt-in and switches (Story 3)

- **TEL-001** THE SYSTEM SHALL export nothing, spool nothing and open no
  connection for telemetry unless `MINIMAL_TELEMETRY` is `1`, `true`, `yes`
  or `on` (any case). Plain `OTEL_*` variables alone never turn it on.
  tier:     T2
  verify:   cargo nextest run -p mlog without_the_opt_in_export_is_off_and_installs_nothing
  test:     crates/mlog/src/otel.rs::without_the_opt_in_export_is_off_and_installs_nothing;
            crates/mlog/src/otel.rs::enable_and_endpoint_rules;
            crates/mlog/src/otel.rs::spool_is_written_only_when_telemetry_is_on;
            crates/minvmd/tests/otel_integration.rs::minvmd_writes_nothing_with_telemetry_off;
            crates/minimal/tests/otel_cli.rs::ambient_otel_alone_opens_no_connection
  property: for all switch values, telemetry != True implies export = Off for both signals
  harness:  crates/mlog/src/otel/switches.rs::nothing_is_exported_without_the_opt_in (no loops)
  lab:      712
- **TEL-002** WHILE `DO_NOT_TRACK` has any non-empty value, or
  `OTEL_SDK_DISABLED` is `true`, in a process's own environment, THE SYSTEM
  SHALL export nothing and spool nothing from that process, whatever else is
  set. `DO_NOT_TRACK=0` and `DO_NOT_TRACK=false` veto too; an empty value
  counts as unset. What a request from such a process means to a daemon
  that is on is TEL-045.
  tier:     T2
  verify:   cargo nextest run -p mlog any_do_not_track_value_vetoes_telemetry
  test:     crates/mlog/src/otel/switches.rs::any_do_not_track_value_vetoes_telemetry;
            crates/mlog/src/otel.rs::spool_is_written_only_when_telemetry_is_on
  property: do_not_track != Unset or sdk_disabled implies export = Off and spool = false for both signals
  harness:  crates/mlog/src/otel/switches.rs::a_disabled_sdk_spools_nothing,
            crates/mlog/src/otel/switches.rs::the_spool_follows_its_switches,
            crates/mlog/src/otel/switches.rs::nothing_is_exported_without_the_opt_in
  lab:      712, 712b
- **TEL-003** THE SYSTEM SHALL treat only `true` (any case) as setting
  `OTEL_SDK_DISABLED`; `1`, `yes` and other values leave it unset.
  tier:     T0
  verify:   cargo nextest run -p mlog only_true_disables_the_sdk
  test:     crates/mlog/src/otel/switches.rs::only_true_disables_the_sdk
  lab:      712b
- **TEL-004** WHILE telemetry is enabled THE SYSTEM SHALL send each signal to
  the first endpoint that is set in this order: the signal's own
  `MINIMAL_OTEL_EXPORTER_OTLP_<signal>_ENDPOINT` (used as given), the
  `MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT` base (plus `/v1/traces` or
  `/v1/logs`), the signal's own plain `OTEL_` endpoint (used as given), the
  plain `OTEL_` base (plus the signal path); so a `MINIMAL_` endpoint SHALL
  always win over every plain one, a plain per-signal one included; a signal
  whose `*_EXPORTER` setting is `none` SHALL be neither exported nor spooled.
  tier:     T2
  verify:   cargo nextest run -p mlog enable_and_endpoint_rules
  test:     crates/mlog/src/otel.rs::enable_and_endpoint_rules;
            crates/mlog/src/otel/switches.rs::a_minimal_endpoint_beats_a_plain_signal_endpoint;
            crates/mlog/src/otel/switches.rs::a_prefixed_exporter_setting_hides_the_plain_one
  property: an enabled signal goes to the first set endpoint, every prefixed one before every plain one
  harness:  crates/mlog/src/otel/switches.rs::a_prefixed_endpoint_wins,
            crates/mlog/src/otel/switches.rs::an_enabled_signal_goes_to_the_nearest_endpoint
  lab:      712b phase D
- **TEL-005** WHILE the traces signal is off (`*_TRACES_EXPORTER=none`) THE
  SYSTEM SHALL install no tracer and SHALL put no `TRACEPARENT` into any box.
  tier:     T0
  verify:   cargo nextest run -p mlog --test otel_requirements logs_only_installs_no_tracer
  test:     crates/mlog/tests/otel_requirements.rs::logs_only_installs_no_tracer;
            crates/minimald-rpc/src/taskenv.rs::trace_env_is_traceparent_only_and_only_on_opt_in;
            crates/minimald/src/exec.rs::an_unrecorded_exec_span_gives_the_box_no_traceparent
  lab:      712b phase D
- **TEL-006** THE SYSTEM SHALL stamp the resource with a random
  `service.instance.id` generated at process start, one per process and the
  same on its traces and its logs, and never with the machine id or any host
  identifier from a resource detector.
  tier:     T0
  verify:   cargo nextest run -p mlog --test otel_requirements one_instance_id_per_process_and_never_the_machine_id
  test:     crates/mlog/tests/otel_requirements.rs::one_instance_id_per_process_and_never_the_machine_id;
            crates/mlog/tests/otel_requirements.rs::the_trace_and_log_resources_of_a_process_share_one_instance_id
- **TEL-007** IF an OTLP exporter cannot be built THEN THE SYSTEM SHALL log one
  warning for that signal that names the whole error chain, SHALL turn that
  signal's export off for the process, and SHALL keep spooling.
  tier:     T0
  verify:   cargo nextest run -p mlog an_error_chain_names_every_cause
  test:     crates/mlog/src/otel.rs::an_error_chain_names_every_cause;
            crates/mlog/tests/otel_without_ca_roots.rs::an_http_exporter_builds_with_no_ca_roots_on_disk;
            crates/mlog/src/otel.rs::http_and_https_endpoints_get_a_client
  lab:      715f
- **TEL-008** WHILE a signal's endpoint comes from a `MINIMAL_` variable THE
  SYSTEM SHALL send it `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` and never the
  plain `OTEL_EXPORTER_OTLP_HEADERS` or `OTEL_EXPORTER_OTLP_<signal>_HEADERS`;
  IF a plain one is set and `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` is not THEN
  THE SYSTEM SHALL not export that signal, SHALL log one warning for it that
  names both variables, and SHALL keep spooling. An endpoint from a plain
  variable keeps the plain headers (review S3).
  tier:     T2
  verify:   cargo nextest run -p mlog --test otel_requirements a_prefixed_endpoint_never_carries_plain_headers
  test:     crates/mlog/tests/otel_requirements.rs::a_prefixed_endpoint_never_carries_plain_headers;
            crates/mlog/src/otel/switches.rs::plain_headers_refuse_a_prefixed_endpoint_unless_prefixed_headers_are_set;
            crates/mlog/src/otel.rs::a_prefixed_client_swaps_plain_headers_for_minimal_ones;
            crates/mlog/src/otel.rs::a_refusal_names_both_variables;
            crates/mlog/src/otel.rs::headers_parse_as_the_exporter_reads_them;
            crates/mlog/src/otel.rs::enable_and_endpoint_rules
  property: for all switch values, an export through a `MINIMAL_` endpoint has no plain
            headers set or `MINIMAL_` headers set, and a refusal happens exactly then
  harness:  crates/mlog/src/otel/switches.rs::a_prefixed_endpoint_never_carries_plain_headers (no loops),
            crates/mlog/src/otel/switches.rs::an_enabled_signal_goes_to_the_nearest_endpoint

- **TEL-009** WHILE a daemon runs THE SYSTEM SHALL keep the telemetry switches of
  the daemon's own environment (the one its autospawning `min` passed); a
  later command's opt-in SHALL not turn the daemon on, and a later command's
  opt-out SHALL not turn it off. A daemon keeps its own switches, and a
  request that opts out is not recorded (TEL-045). Decided 2026-10-04
  (review S7), and tightened 2026-10-05: stricter than the epic's decision 2.
  tier:     T0
  verify:   lab scenario 785 (ci / daemon-off / daemon-on arms, four distros)
  test:     crates/minvmd/tests/otel_integration.rs::minvmd_writes_nothing_with_telemetry_off (the per-process rule)
  - Known gap: lab scenario 785 is the only end-to-end check. Issue to follow.

### Best effort (principle 8)

- **TEL-010** WHEN a CLI command exits with telemetry on THE SYSTEM SHALL wait
  for the export flush at most `CLI_EXIT_FLUSH` (200 ms) plus 250 ms of
  shutdown slack, whatever the collector does; on the `exit()` and signal
  hand-off paths the same bound SHALL apply.
  tier:     T0
  verify:   cargo nextest run -p mlog the_cli_exit_flush_is_bounded_when_the_collector_is_silent
  test:     crates/mlog/src/otel.rs::the_cli_exit_flush_is_bounded_when_the_collector_is_silent;
            crates/mlog/tests/otel_requirements.rs::the_atexit_flush_is_bounded_on_process_exit;
            crates/minimal/tests/otel_cli.rs::a_silent_collector_costs_min_ls_little_and_prints_nothing
  lab:      719
  - With an endpoint that refuses connections, the retry policy of the SDK
    spends the whole 200 ms, so each command pays about 200 ms (review S19).
    See Open questions.
- **TEL-011** IF the collector is unreachable THEN THE SYSTEM SHALL complete
  `min stop` within the daemon shutdown bound (runtime 2 s, then flush 5 s).
  tier:     T0
  verify:   cargo nextest run -p minimald --test otel_shutdown_integration a_silent_collector_does_not_hold_the_daemons_exit
  test:     crates/minimald/tests/otel_shutdown_integration.rs::a_silent_collector_does_not_hold_the_daemons_exit
            (the real daemon's exit after it answers `Shutdown`; `min stop` itself
            returns at the answer)
  lab:      719
- **TEL-012** THE SYSTEM SHALL never print the OpenTelemetry SDK's own errors on
  a console or in a file log the user reads.
  tier:     T0
  verify:   cargo nextest run -p mlog --test otel_requirements quiet_drops_sdk_errors_and_keeps_the_rest
  test:     crates/mlog/tests/otel_requirements.rs::quiet_drops_sdk_errors_and_keeps_the_rest
            (the console filter);
            crates/minimal/tests/otel_cli.rs::a_silent_collector_costs_min_ls_little_and_prints_nothing
            (`min ls`'s stderr against a silent collector)
  lab:      719
- **TEL-013** THE SYSTEM SHALL never export records from the exporter's own HTTP
  stack or the SDK (`hyper`, `hyper_util`, `h2`, `reqwest`, `tower`,
  `opentelemetry*`), whatever `MINIMAL_OTEL_FILTER` names, a directive more
  specific than the exclusion (`hyper_util::client=trace`) included.
  tier:     T0
  verify:   cargo nextest run -p mlog --test otel_requirements the_export_filter_never_admits_the_exporters_own_stack
  test:     crates/mlog/tests/otel_requirements.rs::the_export_filter_never_admits_the_exporters_own_stack;
            crates/mlog/tests/otel_requirements.rs::a_specific_directive_cannot_readmit_the_exporters_stack;
            crates/mlog/tests/otel_requirements.rs::a_real_export_spools_nothing_from_its_own_stack

### Spool (Story 1)

- **TEL-014** WHILE telemetry is on and `MINIMAL_OTEL_SPOOL` is not `0`,
  `false`, `no` or `off`, THE SYSTEM SHALL append every finished span and
  every exported log record, synchronously as it ends, as one OTLP-JSON line
  to `<service>-<pid>-<start_ms>.jsonl` in the spool directory; a process
  that records nothing SHALL create no file.
  tier:     T0
  verify:   cargo nextest run -p mlog a_finished_span_is_on_disk_as_one_otlp_json_line
  test:     crates/mlog/src/otel/spool.rs::a_finished_span_is_on_disk_as_one_otlp_json_line;
            crates/mlog/src/otel/spool.rs::a_log_record_is_one_otlp_json_line;
            crates/mlog/src/otel/spool.rs::a_process_that_records_nothing_leaves_no_file;
            crates/mlog/src/otel.rs::spool_is_written_only_when_telemetry_is_on
  lab:      711, 714b
- **TEL-015** IF the process is killed THEN THE SYSTEM SHALL leave in the spool
  every record that ended before the kill and at most one torn line, and THE
  SYSTEM SHALL start the next record on a line of its own.
  tier:     T0
  verify:   cargo nextest run -p mlog a_torn_line_never_joins_the_next_record
  test:     crates/mlog/src/otel/spool.rs::a_torn_line_never_joins_the_next_record;
            crates/mlog/src/otel/spool.rs::a_short_write_is_continued_or_reported
  lab:      711 (SIGKILL), 711b
- **TEL-016** WHEN a spool file would pass 4 MiB THE SYSTEM SHALL continue in
  `<service>-<pid>-<start_ms>-<n>.jsonl`; WHEN its open file has been
  deleted, the writer SHALL move to a new file within 5 s.
  tier:     T0
  verify:   cargo nextest run -p mlog a_long_lived_process_rotates_and_keeps_the_directory_bounded
  test:     crates/mlog/src/otel/spool.rs::a_long_lived_process_rotates_and_keeps_the_directory_bounded;
            crates/mlog/src/otel/spool.rs::a_file_pruned_away_under_a_writer_is_replaced
  lab:      714b (size rotation only)
- **TEL-017** WHEN a process opens a new spool file THE SYSTEM SHALL delete
  spool files (`<service>-<pid>-<start_ms>[-<n>].jsonl`, `start_ms` in 13
  digits) older than 7 days, then the oldest, until at most 50 MiB minus one
  segment (46 MiB) is left, and SHALL touch no other file in the directory
  but its `.pruned` stamp. A rotation SHALL always prune; a process's first
  file SHALL prune only when no prune ran in the last 60 s.
  tier:     T2
  verify:   cargo nextest run -p mlog prune_drops_old_files_then_oldest_until_under_the_size_bound
  test:     crates/mlog/src/otel/spool.rs::prune_drops_old_files_then_oldest_until_under_the_size_bound;
            crates/mlog/src/otel/spool.rs::prune_drops_files_older_than_seven_days;
            crates/mlog/src/otel/spool.rs::a_first_file_prunes_only_when_no_scan_is_recent;
            crates/mlog/src/otel/spool.rs::prune_leaves_foreign_jsonl_alone;
            crates/mlog/src/otel/spool.rs::only_spool_names_are_spool_files
  property: the plan deletes every file past max age, keeps at most prune_to bytes,
            and deletes for size only the oldest files and only when needed
  harness:  crates/mlog/src/otel/spool.rs::prune_plan_one_file (unwind 3),
            prune_plan_two_files (unwind 4), prune_plan_three_files (unwind 5)
  lab:      714b
- **TEL-018** IF a spool write fails THEN THE SYSTEM SHALL drop that record and
  try again with the next one, so spooling resumes when space returns,
  without a restart. IF opening a spool file fails (at the first record, a
  rotation or a reopen) THEN THE SYSTEM SHALL drop that record, log one
  warning per process, and try to open again on the next record and after
  that at most once every 5 s until a file opens.
  tier:     T0
  verify:   cargo nextest run -p mlog --test otel_requirements a_full_spool_drops_records_then_resumes_when_space_returns
  test:     crates/mlog/tests/otel_requirements.rs::a_full_spool_drops_records_then_resumes_when_space_returns;
            crates/mlog/src/otel/spool.rs::a_failed_open_is_retried;
            crates/mlog/src/otel/spool.rs::a_failing_open_backs_off_after_the_first_retry
  lab:      711b (ENOSPC, then SIGKILL)
- **TEL-019** THE SYSTEM SHALL create the spool directory (and any parent it
  creates) with mode 0700 and its files with mode 0600, and SHALL open the
  spool directory with `O_NOFOLLOW` and `O_DIRECTORY`. IF the directory's
  owner is not the process uid, or any group or other permission bit is
  set, THEN THE SYSTEM SHALL refuse that directory (amended 2026-10-05).
  A refused default directory means the process spools nothing.
  tier:     T0
  verify:   cargo nextest run -p mlog --test otel_requirements spool_files_are_0600_in_a_0700_directory
  test:     crates/mlog/tests/otel_requirements.rs::spool_files_are_0600_in_a_0700_directory;
            crates/mlog/tests/otel_requirements.rs::a_shared_or_foreign_spool_dir_is_refused
            (comes with the code round)
- **TEL-020** WHILE `MINIMAL_OTEL_SPOOL_DIR` is set and not empty THE SYSTEM
  SHALL spool every process there, including a daemon after it learns its
  state directory. IF TEL-019 refuses that directory THEN THE SYSTEM SHALL
  fall back to the state-directory spool and log one warning that names
  the refused directory.
  tier:     T0
  verify:   cargo nextest run -p mlog relocation_leaves_a_pinned_spool_alone_and_moves_any_other
  test:     crates/mlog/src/otel.rs::relocation_leaves_a_pinned_spool_alone_and_moves_any_other;
            crates/mlog/src/otel.rs::the_spool_dir_variable_is_the_pin;
            crates/mlog/tests/otel_requirements.rs::an_explicit_spool_dir_survives_relocation
  lab:      711b

### One trace (Story 1, Story 8)

- **TEL-021** WHEN `min` inherits a valid `TRACEPARENT` THE SYSTEM SHALL make
  the `cmd` span its child, and the daemon's `rpc` span a descendant of
  `cmd`.
  tier:     T0
  verify:   cargo nextest run -p minimal --test otel_cli a_traced_min_ls_joins_the_callers_trace
  test:     crates/minimal/tests/otel_cli.rs::a_traced_min_ls_joins_the_callers_trace
            (the real `min` and the daemon: caller -> `cmd` -> `client.rpc`, and
            `cmd` -> the daemon's `rpc` spans);
            crates/mlog/src/otel.rs::a_child_of_a_propagated_parent_exports_under_its_trace_with_the_reported_ids;
            crates/minimal/src/cmd/mod.rs::a_missing_or_malformed_traceparent_starts_a_fresh_trace
  lab:      716, trace-health on every telemetry-on run (the daemon side)
- **TEL-022** THE SYSTEM SHALL run the daemon's work for a request (manager and
  session messages, compose, checkouts, blocking-pool work, spawned
  short-lived tasks, package fetches, orchestrator and check tasks) in
  descendants of that request's span.
  tier:     T0
  verify:   cargo nextest run -p minimald a_message_carries_its_senders_context_not_its_span
  test:     crates/minimald/src/traced.rs::a_message_carries_its_senders_context_not_its_span;
            crates/minimald/src/traced.rs::a_message_from_a_nested_span_carries_the_enclosing_request;
            crates/minimald/src/traced.rs::blocking_work_runs_in_the_callers_span;
            crates/minimald/src/traced.rs::a_spawned_task_runs_in_the_callers_span;
            crates/minimald/src/rpc.rs::a_manager_and_a_session_message_are_children_of_their_senders
            (over a real RPC: `rpc` -> manager message -> session message);
            crates/minimald/src/exec.rs::an_exec_session_lookup_runs_in_the_exec_span;
            crates/minimald/src/exec.rs::a_git_receive_lookup_runs_in_its_span;
            crates/minimald/src/exec.rs::a_git_upload_lookup_runs_in_its_span;
            crates/minimald/src/exec.rs::a_git_receive_task_runs_in_its_span;
            crates/minimald/src/exec.rs::a_git_upload_task_runs_in_its_span;
            crates/minimald/src/traced.rs::no_direct_tokio_spawn_blocking (a text guard;
            review S15 lists spawn forms it misses)
  lab:      710d, 713, 716
- **TEL-023** WHEN a session exec or run starts in a box THE SYSTEM SHALL put
  the exec span's `TRACEPARENT` into the box's environment, and no other
  `OTEL_*`, `BAGGAGE` or exporter header variable from the host telemetry
  environment.
  tier:     T0
  verify:   cargo nextest run -p minimald-rpc trace_env_is_traceparent_only_and_only_on_opt_in
  test:     crates/minimald-rpc/src/taskenv.rs::trace_env_is_traceparent_only_and_only_on_opt_in
  lab:      716, 717, 717b
  - The `[otel]` variables a Box Spec declares (`architecture.md` of
    gominimal/arch, the `[otel]` block) and the agent receiver of
    gominimal/inbox#678 are outside this spec. Neither must share this
    spool, which TEL-017 prunes and TEL-044 bundles.
  - Pending a ruling on gominimal/arch#103, which proposes opt-in per Box
    Spec. This spec stays draft until it is ruled. If the ruling is opt-in
    per spec, TEL-023 becomes: WHEN a session exec or run starts in a box
    whose spec opts in to trace propagation THE SYSTEM SHALL put the exec
    span's `TRACEPARENT` into the box's environment, and no other `OTEL_*`,
    `BAGGAGE` or exporter header variable from the host telemetry
    environment. Until then the host telemetry environment decides, as
    above.
- **TEL-024** IF the exec span is not recorded (export off, or the export filter
  rejects it) THEN THE SYSTEM SHALL give the box no `TRACEPARENT`.
  tier:     T0
  verify:   cargo nextest run -p minimald an_unrecorded_exec_span_gives_the_box_no_traceparent
  test:     crates/minimald/src/exec.rs::an_unrecorded_exec_span_gives_the_box_no_traceparent;
            crates/minimald/src/exec.rs::without_an_exporter_nothing_is_recorded;
            crates/mlog/tests/otel_requirements.rs::a_span_the_export_filter_rejects_is_not_aligned;
            crates/mlog/tests/otel_requirements.rs::an_unsampled_parent_propagates_flags_00_and_spools_nothing
  lab:      717c
  - A box joins a trace only when Minimal's own export is on. Propagation
    that does not need Minimal's export is out of scope here.
- **TEL-025** WHEN a `min` runs inside a box with an inherited `TRACEPARENT` THE
  SYSTEM SHALL forward it to the daemon with that `min`'s requests, without
  the inner `min` exporting anything, so the daemon's work joins the outer
  trace.
  tier:     T0
  verify:   cargo nextest run -p minimald a_min_in_a_box_joins_the_outer_trace_through_the_helper_prefix
  test:     crates/minimald/src/env.rs::a_min_in_a_box_joins_the_outer_trace_through_the_helper_prefix
            (the shipped in-box helper under bash, then the span the daemon
            serves its line in)
  lab:      717, 717b
  - A `min` inside a box is the in-box helper, a shell function with no
    exporter. It sends the value as the request line's `traceparent%`
    prefix, and only in the 55-character W3C form; the daemon's span for
    the request adopts it. The host binary does not forward an inherited
    context when it does not export: it sends the opt-out marker instead
    (TEL-045).
- **TEL-026** WHEN `min task run` starts a task THE SYSTEM SHALL add the exec
  span's `TRACEPARENT` to the task's environment on opt-in, nothing from the
  host telemetry environment when off, and leave the task's own `env_vars`
  overlay intact.
  tier:     T0
  verify:   cargo nextest run -p minimald-rpc a_task_run_gets_traceparent_only_on_opt_in
  test:     crates/minimald-rpc/src/taskenv.rs::a_task_run_gets_traceparent_only_on_opt_in
  lab:      748
- **TEL-027** THE SYSTEM SHALL run each cache clean in a `maintenance.clean`
  span (`trigger` = `tick` or `request`) under the maintenance actor's own
  root, never under a request's trace.
  tier:     T0
  verify:   cargo nextest run -p minimald a_periodic_clean_runs_in_a_root_span
  test:     crates/minimald/src/maintenance.rs::a_periodic_clean_runs_in_a_root_span
            (paused time, so the tick comes at once);
            crates/minimald/src/maintenance.rs::a_requested_clean_runs_under_the_maintenance_root
  lab:      coverage report, seen only on runs long enough for a tick
- **TEL-028** WHEN a `min net forward` connection is opened THE SYSTEM SHALL run
  the daemon's work for it (`TrackForward` and the relay) in the CLI's trace.
  tier:     T0
  verify:   cargo nextest run -p minimald a_forwarded_connections_track_forward_is_a_child_of_the_forward_span
  test:     crates/minimald/src/connection.rs::a_forwarded_connections_track_forward_is_a_child_of_the_forward_span
            (a real direct-tcpip open and relay);
            crates/minimald/src/connection.rs::a_forward_adopts_a_traceparent_originator_and_ignores_an_address
  lab:      769
- **TEL-029** WHEN an interactive attach arrives with a `TRACEPARENT` THE SYSTEM
  SHALL open an `attach` span in the CLI's trace, and the session's `Attach`
  message SHALL be its child.
  tier:     T0
  verify:   cargo nextest run -p minimald an_attach_joins_the_callers_trace
  test:     crates/minimald/src/connection.rs::an_attach_joins_the_callers_trace
  - The attach shell itself gets no `TRACEPARENT` today. See Open questions.
- **TEL-030** THE SYSTEM SHALL run a long-lived actor (session actor, session
  host loop, binding, switch relay, env actor, manager, store, maintenance)
  in a root span of its own that links to the spawning span, and SHALL not
  hold the spawning request's span open; a mailbox message SHALL carry its
  sender's trace ids, not the sender's span.
  tier:     T0
  verify:   cargo nextest run -p minimald a_detached_task_links_its_caller_and_does_not_hold_it_open
  test:     crates/minimald/src/traced.rs::a_detached_task_links_its_caller_and_does_not_hold_it_open;
            crates/minimald/src/traced.rs::a_spawned_task_holds_its_callers_span_open (the contrast);
            crates/minimald/src/traced.rs::a_message_carries_its_senders_context_not_its_span;
            crates/minimald/src/rpc.rs::a_request_span_closes_when_its_rpc_returns
            (CreateSession's spans close at its answer; the session actor is a root)
- **TEL-031** WHEN `min` hands its process off (`exit()` with ssh's status
  after `session exec`, `run` or an attach, or dying of SIGTERM or SIGHUP in
  `min net forward`) THE SYSTEM
  SHALL end the `cmd` span and run the bounded exit flush first, and keep
  the exit status or wait status it had without telemetry.
  tier:     T0
  verify:   cargo nextest run -p minimal the_cmd_span_ends_before_a_handoff_is_finished
  test:     crates/minimal/src/cmd/mod.rs::the_cmd_span_ends_before_a_handoff_is_finished;
            crates/minimal/src/cmd/mod.rs::a_raise_handoff_comes_back_after_the_span_ends;
            crates/minimal/src/cmd/mod.rs::an_exit_handoff_keeps_its_status;
            crates/minimal/src/cmd/mod.rs::die_of_ends_the_process_by_the_signal
  lab:      766, 769

### minvmd and the guest (Story 1)

- **TEL-032** THE SYSTEM SHALL give each `minvmd` process a root span `minvmd`
  (`cmd` = the subcommand) that is a child of an inherited `TRACEPARENT`;
  for `run`, `net.switch.start` and `vm.boot` SHALL sit under
  `supervisor.start`, which SHALL end and be flushed when the VM is ready,
  and supervision SHALL continue in a separate root `supervisor.serve` linked
  to it; for `stop`, `vm.stop` and `guest.shutdown` SHALL sit under the stop
  process's root.
  tier:     T0
  verify:   cargo nextest run -p minvmd the_supervisor_start_phase_exports_at_ready_and_serve_links_back
  test:     crates/minvmd/src/telemetry.rs::the_supervisor_start_phase_exports_at_ready_and_serve_links_back;
            crates/minvmd/tests/otel_integration.rs::a_minvmd_root_span_is_a_child_of_the_callers_traceparent;
            crates/minvmd/tests/otel_integration.rs::without_a_traceparent_minvmd_starts_its_own_trace;
            crates/minvmd/tests/otel_integration.rs::a_stop_is_a_vm_stop_span_under_the_minvmd_root;
            crates/minvmd/src/rpc_client.rs::guest_shutdown_opens_before_the_guest_is_dialed
  lab:      715 (boot), 715c (stop)
- **TEL-033** WHILE telemetry is enabled on the host THE SYSTEM SHALL put on the
  guest boot line only `MINIMAL_TELEMETRY`, `MINIMAL_OTEL_FORWARD=vsock:7353`,
  `MINIMAL_OTEL_FILTER` when set, `MINIMAL_OTEL_TRACES_EXPORTER=none` or
  `MINIMAL_OTEL_LOGS_EXPORTER=none` when the host has that signal off,
  `MINIMAL_OTEL_SPOOL=0` when the host spool is off, and a well-formed
  `TRACEPARENT`. It SHALL never put an endpoint, headers, resource
  attributes, `BAGGAGE`, `TRACESTATE` or `OTEL_BSP_*` there. With telemetry
  off the boot line SHALL be byte-identical to a build without telemetry.
  tier:     T0
  verify:   cargo nextest run -p minvmd an_endpoint_never_crosses_to_the_guest
  test:     crates/minvmd/src/telemetry.rs::nothing_crosses_to_the_guest_when_telemetry_is_off;
            crates/minvmd/src/telemetry.rs::the_decision_crosses_in_order_and_traceparent_last;
            crates/minvmd/src/telemetry.rs::headers_and_resource_attributes_never_cross;
            crates/minvmd/src/telemetry.rs::an_endpoint_never_crosses_to_the_guest;
            crates/minvmd/src/telemetry.rs::the_forward_port_crosses_only_when_the_door_is_bound;
            crates/minvmd/src/telemetry.rs::no_bare_otel_variable_crosses_to_the_guest;
            crates/minvmd/src/telemetry.rs::only_a_well_formed_traceparent_crosses;
            crates/minvmd/src/vm.rs::no_guest_env_leaves_the_boot_line_byte_identical;
            crates/minvmd/src/vm.rs::the_boot_line_carries_only_allowlisted_settings_and_off_is_byte_identical;
            crates/minvmd/tests/otel_integration.rs::a_boot_and_stop_share_one_trace_with_the_guest_daemon
            (a real VM; gated `MINVMD_E2E=1`)
  lab:      715b, 715g, 715h
- **TEL-034** WHILE telemetry is on THE SYSTEM SHALL send the guest daemon's
  finished spans and log records to `minvmd` over the VM's vsock port 7353,
  and `minvmd` SHALL stamp them with `minimal.forwarded_by` and
  `minimal.vm`, append them to the host spool and forward them to the
  host's endpoints under the host's switches, so that `guest.ready` is a
  child of `vm.boot` in the supervisor's trace and the guest does not use
  the network for telemetry (design: [guest-vsock.md](guest-vsock.md)).
  tier:     T0
  verify:   cargo nextest run -p mlog -p minvmd -E 'test(a_forward_destination_queues_every_record_and_builds_no_exporter) | test(only_one_otlp_request_per_line_is_accepted) | test(a_forwarded_line_is_stamped_with_the_hosts_provenance) | test(a_guests_minimal_attributes_are_dropped_at_every_level)'
  test:     crates/mlog/src/otel.rs::a_forward_destination_queues_every_record_and_builds_no_exporter;
            crates/mlog/src/otel.rs::forwarded_lines_go_where_this_process_exports_with_its_headers;
            crates/minimald/src/telemetry_forward.rs::frames_are_length_prefixed_lines_without_the_newline;
            crates/minvmd/src/guest_telemetry.rs::frames_are_batched_per_signal_and_flushed_at_the_end;
            crates/minvmd/src/guest_telemetry.rs::only_one_otlp_request_per_line_is_accepted;
            crates/minvmd/src/guest_telemetry.rs::a_forwarded_line_is_stamped_with_the_hosts_provenance;
            crates/minvmd/src/guest_telemetry.rs::a_batch_is_one_strict_json_request_serialized_from_the_parsed_lines;
            crates/minvmd/src/guest_telemetry.rs::a_reconnect_does_not_reset_the_byte_budget;
            crates/minvmd/src/guest_telemetry.rs::a_read_timeout_inside_a_frame_keeps_the_framing;
            crates/minvmd/src/guest_telemetry.rs::a_stuck_forwarder_never_stops_the_reader;
            crates/minimald/src/telemetry_forward.rs::a_record_over_the_frame_bound_is_dropped_not_sent;
            crates/sandbox2/src/lib.rs::no_seal_admits_af_vsock;
            crates/sandbox2/src/lib.rs::every_seal_refuses_a_vsock_socket;
            crates/minvmd/tests/otel_vsock_integration.rs::the_guest_daemons_records_reach_the_host_spool_and_endpoint_over_vsock;
            crates/minvmd/tests/otel_integration.rs::a_boot_and_stop_share_one_trace_with_the_guest_daemon
            (real VMs; gated `MINVMD_E2E=1`)
  lab:      715b, 715f, 715i, 715j, 715k, 715l
  - On a stop, the guest's spans reach the host before the VM goes down,
    within a bounded grace after the guest acknowledges Shutdown (TEL-049),
    not before the acknowledgement. The door's forward to the host's
    endpoints is drained when the VMM exits (TEL-050).
  - A forwarded record keeps the guest's timestamps, taken on the guest's
    clock. The guest's clock follows the host's only to within the timekeep
    step threshold (80 ms) plus what it drifts between the host's updates,
    so a guest span whose parent is a host span (the guest's `rpc` under
    `guest.shutdown`, or under a CLI's `cmd` with the `local-minvmd`
    provider) can appear to start before its parent by that offset. The
    host opens its span before it sends the request
    (`guest_shutdown_opens_before_the_guest_is_dialed`); the offset is the
    clocks', not the order of events. Lab 715m and 715n measure it.
- **TEL-035** IF a boot under `minvmd run` or `minvmd boot` fails THEN THE
  SYSTEM SHALL mark `vm.boot` with an error status, and leave it unset on
  success.
  tier:     T0
  verify:   cargo nextest run -p minvmd a_failed_boot_exports_vm_boot_with_an_error_status
  test:     crates/minvmd/src/telemetry.rs::a_failed_boot_exports_vm_boot_with_an_error_status
            (the span as `cmd/run.rs` declares and records it; no VM boots);
            crates/minvmd/src/telemetry.rs::an_early_return_marks_vm_boot_failed
            (the guard `minvmd boot` holds over every return before READY);
            crates/minvmd/src/telemetry.rs::an_early_return_from_run_marks_vm_boot_failed
            (the same for `minvmd run`'s boot loop);
            crates/minvmd/src/telemetry.rs::every_vm_boot_is_held_by_the_guard
- **TEL-036** WHILE `RUST_LOG` restricts a console or file log THE SYSTEM SHALL
  still export and spool at the level `MINIMAL_OTEL_FILTER` sets (default
  `info`).
  tier:     T0
  verify:   cargo nextest run -p minvmd --test otel_integration rust_log_warn_does_not_silence_the_spool
  test:     crates/minvmd/tests/otel_integration.rs::rust_log_warn_does_not_silence_the_spool
  lab:      715e
- **TEL-037** WHEN the microVM guest daemon receives Shutdown THE SYSTEM SHALL
  flush telemetry, bounded at 1500 ms, before it acknowledges, and keep its
  providers installed for the exit-time flush.
  tier:     T0
  verify:   cargo nextest run -p minimald a_clean_stop_releases_its_fds_before_the_quiesce
  test:     crates/minimald/src/rpc.rs::a_clean_stop_releases_its_fds_before_the_quiesce;
            crates/mlog/src/otel.rs::a_flush_returns_within_its_bound;
            crates/mlog/src/otel.rs::a_flush_delivers_and_leaves_the_provider_usable
  - This flush carries the records finished before it. The guest's `rpc`
    span for Shutdown ends when the acknowledgement is written, so it goes
    out with the exit-time flush after the acknowledgement, which TEL-049
    lets finish before the VM goes down.

### Shutdown

- **TEL-038** WHEN minimald stops THE SYSTEM SHALL shut its runtime down
  (bounded at 2 s) and then flush telemetry (bounded at 5 s), so spans of
  tasks still alive at shutdown are exported.
  tier:     T0
  verify:   cargo nextest run -p minimald --test otel_shutdown_integration a_connection_open_at_shutdown_still_exports_its_span
  test:     crates/minimald/tests/otel_shutdown_integration.rs::a_connection_open_at_shutdown_still_exports_its_span
            (the real daemon: a connection held open across `Shutdown` has its
            span exported; it does not pin the order of the two steps, since
            the server's connection drain ends every such span before either)
  lab:      711, 715, 719 (stop bound)
- **TEL-039** WHEN the daemon that mounted the state volume stops cleanly THE
  SYSTEM SHALL release the file log, flush telemetry, close the spool and
  only then quiesce the volume; a daemon that mounted no volume SHALL keep
  its spool open.
  tier:     T0
  verify:   cargo nextest run -p minimald a_clean_stop_releases_its_fds_before_the_quiesce
  test:     crates/minimald/src/rpc.rs::a_clean_stop_releases_its_fds_before_the_quiesce;
            crates/minimald/src/rpc.rs::a_clean_stop_without_a_mounted_volume_keeps_its_spool;
            crates/mlog/src/otel/spool.rs::a_released_spool_closes_its_file_and_drops_later_records
  lab:      none yet (a telemetry-on variant of 749 is owed)
- **TEL-049** WHEN the microVM guest daemon acknowledges Shutdown to
  `minvmd stop` THE SYSTEM SHALL wait up to 3 s for the guest to power the
  VM off before it signals the VMM, so that the guest's exit-time flush
  (TEL-038) sends its last spans, its `rpc` span under `guest.shutdown`
  included, over vsock before the VM goes down.
  tier:     T0
  verify:   cargo nextest run -p minvmd an_acked_stop_lets_the_guest_power_off_before_any_signal
  test:     crates/minvmd/src/cmd/stop.rs::an_acked_stop_lets_the_guest_power_off_before_any_signal;
            crates/minvmd/src/cmd/stop.rs::an_acked_stop_signals_a_vm_that_outlives_the_grace;
            crates/minvmd/src/cmd/stop.rs::an_unacked_stop_signals_at_once
  lab:      715k
  - The `rpc` span ends when the acknowledgement is written, so no flush
    before the acknowledgement (TEL-037) can carry it. A guest that does
    not power off within 3 s is signalled as before, and its last spans
    can then be lost. They stay in the guest's own spool.
  - The guest's exit-time drain of its vsock sender waits for records
    written or dropped, not records taken off the queue, so the guest's
    power-off does not cut the last write.
- **TEL-050** WHEN the VMM child of `minvmd run` exits THE SYSTEM SHALL wait
  up to 2 s for the guest telemetry door to read the guest's connection to
  its end and to forward every queued record to the host's endpoints, so
  that a collector receives the guest's last records and not only the
  spool.
  tier:     T0
  verify:   cargo nextest run -p minvmd the_exit_drain_waits_for_the_connection_and_the_forwarder
  test:     crates/minvmd/src/guest_telemetry.rs::the_exit_drain_waits_for_the_connection_and_the_forwarder;
            crates/minvmd/src/guest_telemetry.rs::the_exit_drain_gives_up_at_its_bound
  lab:      none yet (715k checks the spool, not the collector)

### Privacy

- **TEL-040** THE SYSTEM SHALL name each endpoint in its init summary line as
  `scheme://host[:port]` only, without userinfo, path, query or fragment.
  tier:     T0
  verify:   cargo nextest run -p mlog an_endpoint_is_logged_as_its_origin
  test:     crates/mlog/src/otel.rs::an_endpoint_is_logged_as_its_origin
- **TEL-041** THE SYSTEM SHALL record a git remote on `checkouts.*` spans
  without userinfo, query or fragment.
  tier:     T0
  verify:   cargo nextest run -p checkouts a_checkout_span_never_carries_userinfo
  test:     crates/checkouts/src/lib.rs::a_checkout_span_never_carries_userinfo (the spans);
            crates/checkouts/src/lib.rs::spans_record_a_remote_without_credentials (the scrub)
- **TEL-042** THE SYSTEM SHALL report `MINIMAL_OTEL_EXPORTER_OTLP_*` and any
  `*_HEADERS` variable in a diagnostic bundle without its value.
  tier:     T0
  verify:   cargo nextest run -p minimal telemetry_exporter_settings_are_reported_by_name_only
  test:     crates/minimal/src/diag/redact.rs::telemetry_exporter_settings_are_reported_by_name_only;
            crates/minimald/src/diag.rs::telemetry_exporter_settings_are_reported_by_name_only
- **TEL-043** THE SYSTEM SHALL record an exec's command line on its span only
  after the diagnostics secret scrubber has run over it.
  tier:     T0
  verify:   cargo nextest run -p minimald an_exec_session_lookup_runs_in_the_exec_span
  test:     crates/minimald/src/exec.rs::an_exec_session_lookup_runs_in_the_exec_span
            (an exec with an `Authorization: Bearer` argument over a real channel:
            the span's `command` is scrubbed)

### Diagnostics (Story 2)

- **TEL-044** WHEN `min bug` collects a diagnostic bundle THE SYSTEM SHALL include
  the daemon's spool files inside the daemon's bundle, which on a VM host
  are the guest daemon's spool, SHALL include the CLI's and `minvmd`'s spools
  on a host where they spool locally, and SHALL scrub every spool file so
  that no bundle contains an exporter header value or the value of a
  secret-shaped attribute.
  tier:     T0
  verify:   cargo nextest run -p minimal a_host_bundle_never_carries_a_header_value_or_a_secret_attribute
  test:     crates/minimal/src/diag/collect.rs::a_host_bundle_never_carries_a_header_value_or_a_secret_attribute;
            crates/minimal/src/diag/collect.rs::a_bundle_collected_with_telemetry_on_carries_no_secret;
            crates/minimald/src/diag.rs::a_daemon_bundle_never_carries_a_header_value_or_a_secret_attribute;
            crates/diagnostics/src/redact.rs::a_spool_line_loses_header_values_and_secret_attributes;
            crates/minimal/src/diag/collect.rs::bundle_carries_the_host_telemetry_spool;
            crates/minimald/src/diag.rs::diag_bundle_carries_the_telemetry_spool
  lab:      782
  - The host collector reads one spool directory: `MINIMAL_OTEL_SPOOL_DIR`
    in `min bug`'s own environment, else `<state>/telemetry/spool`. Each
    producer picks its directory from its own environment, so a `minvmd`
    or CLI whose spool is pinned elsewhere in its own environment (a
    service unit's, say) is not collected; `host/telemetry.json` names the
    directory read (TEL-051).
  - Each collector keeps the newest five spool files, tail-capped like the
    daemon log. On a VM host the daemon is the guest's `/init`, so its
    bundle carries the guest's spool, and `min bug` nests that bundle. The
    guest's records also reach the host spool through the vsock forward
    (TEL-034), so the host bundle carries them too.
  - The scrub replaces each configured exporter header value of 8 bytes or
    more wherever it appears. It masks the value of an OTLP attribute whose
    name looks secret, by the rule the bundle's key redaction uses. It
    withholds a line that is not JSON, such as the torn first line of a
    tail. The log scrub then runs over every line.
  - Known gap: the tests above cover each collector's scrub, and
    `a_bundle_collected_with_telemetry_on_carries_no_secret` covers the
    host's whole `min bug` collection with telemetry on. Lab scenario 782
    alone checks the whole path, a nested bundle from a real VM, and
    gominimal/minimal#2035 tracks an in-tree check of it.

### Added 2026-10-05

- **TEL-045** WHEN the CLI's telemetry decision is off, for any cause,
  `DO_NOT_TRACK` included, THE SYSTEM SHALL send an explicit opt-out with
  each request and no `TRACEPARENT`, and the daemon SHALL record nothing for
  that request: a non-recording span and no command line.
  tier:     T0
  verify:   cargo nextest run -p minimald an_opted_out_request_leaves_no_daemon_span
  test:     crates/minimald/src/exec.rs::an_opted_out_request_leaves_no_daemon_span;
            crates/minimal-client/src/lib.rs::do_not_track_sends_the_opt_out_and_no_traceparent
            (both come with the code round)
  lab:      785
- **TEL-046** IF the host receiver on vsock port 7353 is unreachable THEN THE
  SYSTEM SHALL keep the guest daemon spooling, SHALL retry the connection
  every 5 s, SHALL log one warning per guest process, and SHALL drop
  forwarded records at the queue bound, so that no request in the guest
  waits on the host.
  tier:     T0
  verify:   cargo nextest run -p minimald the_sender_drops_while_the_host_is_away_and_reconnects
  test:     crates/minimald/src/telemetry_forward.rs::the_sender_drops_while_the_host_is_away_and_reconnects;
            crates/mlog/src/otel/forward.rs::a_full_queue_drops_the_newest_and_counts;
            crates/minvmd/src/guest_telemetry.rs::a_stream_cut_mid_frame_keeps_what_came_before;
            crates/minvmd/src/guest_telemetry.rs::an_oversized_or_empty_frame_ends_the_connection_after_a_flush
  lab:      715j, 715k
  - A frame the host refuses as too long (over 1 MiB) or empty ends that
    connection. The guest reconnects after the same 5 s, and the host logs
    its counts (accepted, refused, forwarded, dropped) on every close and
    at every 1000 refusals, never a guest byte.
- **TEL-047** WHEN the host telemetry environment injects `TRACEPARENT` into
  a box THE SYSTEM SHALL list `TRACEPARENT` wherever it reports the box's
  injected environment, and the box spec SHALL show it once `min box spec`
  exists (spec 24).
  tier:     T0
  verify:   none, known gap until spec 24 is implemented, tracked in gominimal/minimal#2036
  test:     none yet
  lab:      none yet
  - Known gap: nothing in this tree reports a box's injected environment,
    and `min box spec` is spec 24's future work. The code round implemented
    nothing for it. The decision itself (option 2 of gominimal/arch#103)
    stands in Context and Design reasoning.
- **TEL-048** WHEN the daemon records a span for a request from a box THE
  SYSTEM SHALL take the span's box and session ids from the host-side
  connection, never from data the box supplied.
  tier:     T0
  verify:   cargo nextest run -p minimald a_box_request_span_carries_the_host_side_box_identity
  test:     crates/minimald/src/env.rs::a_box_request_span_carries_the_host_side_box_identity
            (comes with the code round)
  lab:      none yet

### Added 2026-10-06

- **TEL-051** WHEN `min bug` collects a bundle THE SYSTEM SHALL record the
  telemetry switch state, each signal's exporter state and each endpoint in
  the TEL-040 form, and the trace id of the newest command span when the
  spool holds one.
  tier:     T0
  verify:   cargo nextest run -p minimal the_bundle_records_the_telemetry_state
  test:     crates/minimal/src/diag/collect.rs::the_bundle_records_the_telemetry_state;
            crates/minimal/src/diag/collect.rs::the_mirrored_switch_agrees_with_mlog;
            crates/minimal/src/diag/collect.rs::a_trace_lookup_passes_over_torn_lines
  lab:      none yet
  - The record is `host/telemetry.json`. It names the variable that decided
    the switch, the spool's state and its directory, says that directory is
    the only spool directory read, and says whose state it is: the `min bug`
    process's environment. A daemon or `minvmd` keeps the
    switches it started with (TEL-009), so its state can differ. The
    exporter, endpoint and spool state come from mlog's own decision. The deciding variable
    mirrors mlog's switch, which mlog does not export, and a test holds the
    two together.
  - The id is TEL-051 because the fix for lab scenario 715k took TEL-049
    and TEL-050.

### Former requirement ids

The lab's notes, scenario headers (`# spec:`) and proof tables written before
2026-10-05 use these ids, and the header of
`crates/mlog/tests/otel_requirements.rs` names the families. They map one to
one. The map is also `patches/lab-scenarios-spec-ids-20261005/idmap.json` in
the lab. TEL-009 was OT-9 and TEL-044 was DG-1 in the lab only. The ids
TEL-045 to TEL-048 were added on 2026-10-05 and have no former id.
TEL-049 and TEL-050 came with the fix for lab scenario 715k on 2026-10-06
and have no former id either. TEL-051 was added on 2026-10-06 and has no former
id.

| former | now |
|---|---|
| OT-1 | TEL-001 |
| OT-2 | TEL-002 |
| OT-3 | TEL-003 |
| OT-4 | TEL-004 |
| OT-5 | TEL-005 |
| OT-6 | TEL-006 |
| OT-7 | TEL-007 |
| OT-8 | TEL-008 |
| OT-9 | TEL-009 |
| BE-1 | TEL-010 |
| BE-2 | TEL-011 |
| BE-3 | TEL-012 |
| BE-4 | TEL-013 |
| SP-1 | TEL-014 |
| SP-2 | TEL-015 |
| SP-3 | TEL-016 |
| SP-4 | TEL-017 |
| SP-5 | TEL-018 |
| SP-6 | TEL-019 |
| SP-7 | TEL-020 |
| TR-1 | TEL-021 |
| TR-2 | TEL-022 |
| TR-3 | TEL-023 |
| TR-4 | TEL-024 |
| TR-5 | TEL-025 |
| TR-6 | TEL-026 |
| TR-7 | TEL-027 |
| TR-8 | TEL-028 |
| TR-9 | TEL-029 |
| TR-10 | TEL-030 |
| TR-11 | TEL-031 |
| VM-1 | TEL-032 |
| VM-2 | TEL-033 |
| VM-3 | TEL-034 |
| VM-4 | TEL-035 |
| VM-5 | TEL-036 |
| VM-6 | TEL-037 |
| SD-1 | TEL-038 |
| SD-2 | TEL-039 |
| PV-1 | TEL-040 |
| PV-2 | TEL-041 |
| PV-3 | TEL-042 |
| PV-4 | TEL-043 |
| DG-1 | TEL-044 |
| (none) | TEL-045 |
| (none) | TEL-046 |
| (none) | TEL-047 |
| (none) | TEL-048 |
| (none) | TEL-049 |
| (none) | TEL-050 |
| (none) | TEL-051 |
| BE-N01 | TEL-N01 |
| SP-N01 | TEL-N02 |

## Non-goals

- A shipper that uploads the spool to a collector later. That is the
  daemon-side shipper of Story 1, a follow-up under gominimal/inbox#515.
  Until then nothing ships the guest's spool to a collector except the vsock
  forward (TEL-034).
- Metrics: not part of this work. The exporter sends traces and logs only.
- OTLP over gRPC: the exporter speaks OTLP over HTTP with protobuf only.
- `min bug --trace <id>` and a span waterfall in the bundle explorer (Story 2):
  follow-ups. The bundle includes the spool (TEL-044), and [spec 10](../10-spec-diagnostics/10-spec-diagnostics.md)
  keeps its file-based path otherwise. With telemetry off, `min bug` is
  unchanged but for the TEL-051 record, which says telemetry is off. The
  bundle gains the spool by default only when the spool is on by default
  (the next increment). The bundle holds no telemetry from the software in
  a box.
- The installer's own telemetry (Story 1 names it): a follow-up. This spec
  covers `min`, `minimald` and `minvmd`.
- The `min telemetry` subcommands (status, on, off, local, view) and
  `[telemetry.export.<name>]` config blocks: wait for gominimal/arch#101. The
  environment contract above is the whole surface of this spec.
- A narrower default export filter or an attribute inventory: tracked as a
  follow-up under gominimal/inbox#515.
- A failed command printing its trace id (Story 1): a follow-up.
- A header-helper command with a refresh interval, and mTLS (Story 3): a
  follow-up. This spec has static headers only.
- Retries with backoff from the spool to an unreachable endpoint (Story 3):
  the shipper follow-up above.
- Multiple destinations, content flags such as `log_command_args`, and
  `min telemetry status` naming each destination (Story 3): with the
  `[telemetry.export.<name>]` blocks above.
- Sharing anonymous aggregate data with Minimal (the epic's Story 4): a
  separate spec. Nothing in this spec sends anything to Minimal.
- Telemetry from the software in a box (Story 8): the `[otel]` mapping,
  reach from a box to a collector, and an opt-in propagation rule are out
  of scope. gominimal/inbox#678 and gominimal/arch#103 track them.

## Non-functional requirements

Platforms. The same code runs on Linux (native `minimald`, and `minvmd` with
KVM) and on macOS (`minvmd` with the Hypervisor framework, and the daemon as
the guest's `/init`). The lab proves every requirement above on Linux, on
four distributions with Cloud Hypervisor guests. macOS has unit tests and
one manual end-to-end run on arm64 (2026-10-05). It has no repeatable VM
lane until gominimal/minimal#2037 adds one.

The bounds below are the whole cost telemetry can add to a process when the
collector is down, slow or unreachable. Each bound names the constant it
comes from, so a change shows in a diff.

| Where | When | Bound | Constant |
|---|---|---|---|
| `min` | process exit, `exit()` hand-offs, `atexit` | 200 ms (the wait gives up after 450 ms) | `mlog::otel::CLI_EXIT_FLUSH` |
| `minimald` | process exit | runtime shutdown 2 s, then flush 5 s | `crates/minimald/src/main.rs` |
| `minvmd` | every process exit | 2 s | `crates/minvmd/src/main.rs` |
| `minvmd run` | VM ready (non-terminal flush) | 2 s | `SupervisorStart::READY_FLUSH` |
| guest `minimald` | before the Shutdown ack (non-terminal) | 1500 ms (the handler stops waiting at 2 s) | `CLEAN_STOP_TELEMETRY_FLUSH` |
| every exporter | one export request | 3 s | `mlog::otel::EXPORT_TIMEOUT` |
| guest `minimald` | records queued for the host | 1024 lines, then the newest is dropped | `mlog::otel::forward::QUEUE_LINES` |
| `minvmd run` | guest batches waiting for the forwarder | 16 batches, then a batch is dropped (the lines are spooled) | `minvmd::guest_telemetry::FORWARD_QUEUE_BATCHES` |
| `minvmd run` | one forwarded batch to the host's endpoint | 3 s, on the forwarder's own thread | `mlog::otel::EXPORT_TIMEOUT` |

- **TEL-N01** WHILE the collector accepts connections and never answers THE
  SYSTEM SHALL complete a `min` command at most `CLI_EXIT_FLUSH` plus 250 ms
  later than with telemetry off.
  tier:   T0
  verify: cargo nextest run -p mlog the_cli_exit_flush_is_bounded_when_the_collector_is_silent
- **TEL-N02** WHILE several processes spool into one directory THE SYSTEM
  SHALL keep the directory under 50 MiB plus one 4 MiB segment per concurrent
  writer, plus what short-lived processes write within 60 s.
  tier:   T0
  verify: cargo nextest run -p mlog a_long_lived_process_rotates_and_keeps_the_directory_bounded

## Design reasoning

**Generality:** the requirements hold for any OTLP/HTTP collector and any
host that runs `min`, `minimald` or `minvmd`. Nothing here depends on the
lab's collector, its bridge or its scenarios. The spec names them only as the
proof that held a requirement at the time of writing.

**Opt-in by a minimal-specific variable.** Developers' shells and CI runners
often export `OTEL_EXPORTER_OTLP_ENDPOINT` for their own services. If `min`
exported on that alone, a user's commands end up in a collector meant for
another program. So export needs `MINIMAL_TELEMETRY=1`, and only then does
`min` read the plain `OTEL_*` names, with `MINIMAL_`-prefixed names first
(the Docker CLI pattern). `DO_NOT_TRACK` follows consoledonottrack.com: any
value is the signal. `DO_NOT_TRACK=0` also vetoes, because the conservative
reading of an ambiguous opt-out is "out".

**A synchronous local spool beside the network exporter.** The batch
exporters of the SDK buffer in memory and lose their tail on a SIGKILL or a
hang. That is exactly when someone needs the record. (Spec 10 rejected the
SDK for its bundle path for this reason.) The spool writes each record as it
ends, in the OTLP-JSON shape the collector's file exporter writes. A later
shipper can POST each line unchanged. Segment size, total size and age
bound the spool, so it can stay on by default once telemetry is on.

**The boot line is a public channel.** The guest's `/init` has no
environment, so the kernel command line is the one way to pass settings in.
That line is world-readable inside the guest, and `minvmd` logs it. So the
guest gets an allowlist rather than a denylist, and no endpoint is on it.
The guest's records go back to `minvmd` over vsock port 7353, and `minvmd`
exports them as its own switches say ([guest-vsock.md](guest-vsock.md)).
The guest then works without a network, a CA store or an endpoint. The
host's rules for headers apply to the guest's records unchanged. Boxes
cannot open the port: no `sandbox2` socket-family seal admits `AF_VSOCK`.
`minvmd` treats what arrives as data. It takes one OTLP request with one
resource per line, parsed as strict JSON, at most 1 MiB a frame and 64 KiB
a second per VM after a 4 MiB burst, across reconnects, a line costing the
larger of its frame and its spooled form. It stamps every resource with
its own provenance (`minimal.forwarded_by`, `minimal.vm`), dropping any
`minimal.*` attribute the guest wrote at any level, and sends on only what
it serialized from the parsed value. It forwards on a thread of its own
behind a bounded queue, so a hanging collector never stops it reading.
Guest lines share the host spool's 50 MiB bound, so the byte budget is
their share: past the burst, one VM at the limit needs 736 s, about 12
minutes, to write a spool's worth. The budget is per VM and the spool is
shared, so two VMs at the limit take 336 s.

**A box gets one variable.** User code runs in a box, so the box gets
`TRACEPARENT` only, and only when the daemon recorded the span it names. A
nested `min` can then join the trace, and nothing that can authenticate to
the collector enters the box. The host setting is enough to turn this on
(option 2 of gominimal/arch#103): the host telemetry environment decides.
TEL-047 asks that the variable be visible wherever a box's injected
environment is reported, once something reports it.

**An opt-out travels with the request.** A daemon keeps the switches it
started with (TEL-009). So a daemon that is on records a command whose own
`min` is off, unless told otherwise. That command's user said no. So the
CLI tells the daemon with each request and sends no `TRACEPARENT`
(TEL-045). The marker is `MINIMAL_OTEL=off`, sent as channel environment,
as the `direct-tcpip` originator for a forward, and as the same variable on
the OpenSSH attach path. The daemon's spans for that request get an
unsampled parent and `telemetry=opt-out`, and no `command`. The daemon
then does not keep a recorded span or a command line for it.
This is stricter than the epic's decision 2, which lets `DO_NOT_TRACK`
leave a team's own collector alone.

**Long-lived actors as linked roots.** The exporter sends a span when it
ends. An actor that ran inside the request span that spawned it kept that
span open for the actor's life. The request's trace then reached the
collector late or never. Actors get their own roots with a `follows_from` link to the
spawning span.

**Generality.** The switch rules and the spool are in `mlog` and know nothing
of minimal's processes except two names (`minimald` as pid 1 defers its
spool). A second binary gets the same behaviour from `mlog::otel::init`.
The guest rules assume two transports: settings cross on the kernel command
line, and records return over vsock port 7353. A second VM backend that
passes an environment must apply the same allowlist, because the guest's
processes can read that environment too. It must also give the guest a
channel to the host that boxes cannot open.

## Security considerations

- **Invariant:** THE SYSTEM SHALL send nothing to any collector without
  `MINIMAL_TELEMETRY` true and no veto.
  enforced by: `Switches::decide` in `mlog::otel::switches`, and the
  request opt-out for a daemon that is on
  covered by: TEL-001, TEL-002, TEL-045
- **Invariant:** THE SYSTEM SHALL never send a plain `OTEL_*_HEADERS`
  header to an endpoint named by a `MINIMAL_` variable.
  enforced by: `Switches::decide` in `mlog::otel::switches` (the refusal)
  and `mlog::otel::ExportClient` (the header swap)
  covered by: TEL-008
- **Invariant:** THE SYSTEM SHALL never put an exporter header, a resource
  attribute or an endpoint on the guest boot line.
  enforced by: `minvmd::telemetry::guest_env`
  covered by: TEL-033
- **Invariant:** THE SYSTEM SHALL accept guest telemetry only over the vsock
  port wired for that VM, as data, and SHALL send it only where the host's
  own switches send the host's records.
  enforced by: `minvmd::guest_telemetry` (the door, the strict line check
  and the bounds), `sandbox2`'s socket-family seal (no `AF_VSOCK` in any
  box) and `mlog::otel::forward_request` (the host's switches and header rule)
  covered by: TEL-034
- **Invariant:** THE SYSTEM SHALL give a box no variable from the host
  telemetry environment other than `TRACEPARENT`. Variables a Box Spec's
  `[otel]` block declares are the box's own and are outside this spec.
  enforced by: `minimald_rpc::taskenv::trace_env` and `box_traceparent`
  covered by: TEL-023, TEL-024, TEL-005, TEL-026
- **Invariant:** THE SYSTEM SHALL write spool files readable by their owner
  only, into a directory it owns alone.
  enforced by: the directory and file modes and the `O_NOFOLLOW` open in
  `mlog::otel::spool`
  covered by: TEL-019
- **Invariant:** THE SYSTEM SHALL take a box's identity on a daemon span
  from the host side, never from the box.
  enforced by: the request span's attributes in `minimald::rpc`
  covered by: TEL-048
- Trust model, the guest: the boot line is visible to every process in the
  guest through `/proc/cmdline`, boxes included. The spec accepts that.
  `TRACEPARENT` and the forward port are the only telemetry-relevant values
  there. A box can read them but cannot open the port (the socket seal). A
  compromised guest daemon can send any record it likes. The host treats
  the records as data, bounds them (one request with one resource per
  line, strict JSON, 1 MiB a frame, 64 KiB a second per VM after a 4 MiB
  burst), stamps every resource with its own provenance
  (`minimal.forwarded_by`, `minimal.vm`) and drops any `minimal.*` the
  guest wrote at any level, and forwards only what it serialized again
  from the parsed value, so a receiver tells them apart by what the host
  says and reads what the host read. Nothing the guest sent is logged on
  the host.
- Trust model, the box: a box can send a false trace context, or attach
  the daemon's work for its request to a different trace. The daemon's
  spans for a box's requests take the box and session ids from the
  host-side connection, never from box-supplied data (TEL-048). And a box
  and its host are one operator's (the single-operator rule, design §7.1,
  and AT7). So a false context misleads only its owner.
  Whether to record a box-supplied context as a span link rather than a
  parent is an open question.
- Trust model, a token in a host name: no endpoint reaches the guest, so a
  token hidden in a host name stays on the host, where the headers rule
  (TEL-008) is the one place it can travel.

## Open questions

- [RESOLVED 2026-10-04 (review S7), tightened 2026-10-05 (owner): a daemon
  keeps its own switches (TEL-009). A daemon that is on does not record a
  request from a `min` whose telemetry decision is off (TEL-045). This is
  stricter than the epic's decision 2, which keeps `DO_NOT_TRACK` away from
  a team's own collector.]
- [RESOLVED 2026-10-05 (owner): the spool is opt-in in this spec (TEL-001, TEL-014):
  nothing is written without `MINIMAL_TELEMETRY`, as lab scenario 712 proves.
  "The spool is on for everyone by default and never uploaded" (the epic's
  principle 2 and Story 1, decided 2026-09-30) is the next increment, with its
  own ruling on what `DO_NOT_TRACK` means for a purely local file; the epic's
  principle 2 and Story 1 will be amended to say so (gominimal/inbox#970).]
- [NEEDS CLARIFICATION (MEDIUM): should the daemon record a trace context
  supplied by a box as a span link rather than as the parent of its work
  (TEL-025, gominimal/minimal#2038)? A link keeps the host's trace whole when a box lies. A parent
  is what the OTel environment carrier gives a nested `min` today.]
- [NEEDS CLARIFICATION (MEDIUM): with an endpoint that refuses connections,
  disable the exporter's retry policy so a CLI command pays nothing rather
  than about 200 ms (TEL-010, review S19)? The first command that starts a
  daemon against a blackholing collector also waits for the detach parent's
  flush (review S18).]
- [NEEDS CLARIFICATION (LOW): should the interactive attach shell get the
  attach span's `TRACEPARENT`, as exec and run do (TEL-029)?]
- [RESOLVED 2026-10-05: the spec now transcribes the stories
  from gominimal/inbox#515 (updated 2026-09-25) with the epic's numbers.
  They are Stories 1, 2, 3 and 8 and principle 8. The acceptance criteria this spec does not
  cover are each a line under Non-goals. The epic's Story 4 (sharing with
  Minimal) is out of scope.]
