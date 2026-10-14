---
id: QM
title: Architectural-health snapshots, ratcheted quality gates and a PR grading report
owner: unassigned
epic: unassigned
arch: none
arch_sha: "none"
updated: 2026-10-14
---

# QM: architectural-health snapshots, ratcheted quality gates and a PR grading report

## Context

This repository is developed by an agentic factory: coding agents open the
pull requests and a review agent reads them. Nothing measures what that
process does to the code. Lint density, test coverage, code size, module
cycles, unused dependencies and the direction of dependencies between crates
are all unmeasured. The only bar is the workspace Clippy set plus the strict
gate in `scripts/clippy-strict.sh`, which reports only the lines a branch
changed, runs only on a developer's machine, and keeps no history. Promotion
of a strict lint into the workspace set is a guess, because nobody counts
its hits across the tree. [docs/architecture.md](../../architecture.md)
groups crates into planes but no rule enforces the dependency direction
between them.

With this work in the tree, the project has a measured architectural health:
one snapshot per nightly run on the main branch, kept in git, and a static
dashboard of the trend. A change is graded against the snapshot and
thresholds of its base ref, with a verdict a person or an agent can act on.
The coding agent's gate runs the fast part of that grading, and the review
agent can cite its output as attested evidence. A strict lint is promoted
when the data says its count is zero.

**Success:** a nightly run on main adds one snapshot to the history, the
dashboard renders the trend from that history alone, a pull request that
adds an `unwrap()` on a changed line sees the strict-lint ratchet fail in
its report, the report names the files where churn meets poor quality, and
one Clippy lint moves from the strict gate into the workspace set on the
strength of a zero count in a snapshot.

**First slice:** `just metrics` on Linux writes one snapshot that validates
against the schema, with lint density, coverage, size, module cycles,
unused dependencies and layer violations filled in.

## Users and stories

**Roles:** a maintainer who decides what the quality bar is and watches the
trend. A coding agent (the factory's `implement` job) that needs to know
whether its change made the tree worse before it pushes. A review agent that
needs measured evidence before it can block a merge. A developer on a
laptop who wants the same answer the factory gets.

- AS A maintainer I WANT a snapshot of the workspace's health on every
  nightly run SO THAT I can see trends and set thresholds from data rather
  than from memory.
- AS A maintainer I WANT every strict lint counted across the whole tree
  SO THAT I promote a lint into the workspace set when its count is zero,
  not when I guess it is.
- AS A maintainer I WANT the dependency direction between crates written
  down and checked SO THAT a change that couples a core crate to a product
  crate is caught in review rather than in a later refactor.
- AS A coding agent I WANT a gate that grades my change against the base
  ref in seconds SO THAT I fix a regression in the same session that caused
  it.
- AS A review agent I WANT a declared task whose output is deterministic
  SO THAT a measured regression can be cited as attested evidence under the
  review contract.
- AS A developer I WANT one command that runs the same grading the factory
  runs SO THAT the laptop and the factory agree on what the bar is.
- AS A maintainer I WANT the files where quality is suffering ranked by how
  often they change SO THAT a refactor goes where it pays back first.

## Requirements

Requirements are `QM-NNN` in document order. `verify:` names the harness
case that checks the requirement. Cases live in `scripts/metrics_test.sh`
and run through `just test-shell`; `bash scripts/metrics_test.sh <case>`
runs one. Properties for T1 are checked by the same harness over fixture
inputs.

### The snapshot

- **QM-001** WHEN `just metrics` runs on Linux THE SYSTEM SHALL write one
  snapshot document that validates against snapshot schema version 1,
  carrying run metadata, a per-crate section, workspace totals, layer
  findings, the evaluated gates and a verdict.
  tier:     T0
  verify:   bash scripts/metrics_test.sh snapshot_validates
  - IF a collector cannot run THEN THE SYSTEM SHALL record that collector's
    metrics as not measured with the reason, and exit with a code distinct
    from a gate failure. A snapshot never reads as clean because a tool was
    missing.
    tier:   T0
    verify: bash scripts/metrics_test.sh missing_tool_is_not_measured
- **QM-002** THE SYSTEM SHALL set the verdict to the worst result among the
  evaluated gates, where fail is worse than warn and warn is worse than
  pass.
  tier:     T1
  verify:   bash scripts/metrics_test.sh verdict_is_worst_gate
  property: for all gate sets G, verdict(G) = max over g in G of result(g) under fail > warn > pass, and verdict(empty) = pass
- **QM-003** THE SYSTEM SHALL count every lint in the strict gate's list
  across the whole tree, per crate, and SHALL list each lint whose
  workspace count is zero as promotable.
  tier:     T0
  verify:   bash scripts/metrics_test.sh strict_counts_and_promotable
- **QM-004** THE SYSTEM SHALL measure line coverage through the test runner
  under a coverage profile, excluding test sources, fuzz targets, build
  scripts and generated code from the denominator.
  tier:     T0
  verify:   bash scripts/metrics_test.sh coverage_excludes_tests_and_generated
- **QM-005** WHERE experimental metrics are present in a snapshot THE SYSTEM
  SHALL record them without letting them change any gate result or the
  verdict.
  tier:     T1
  verify:   bash scripts/metrics_test.sh experimental_never_changes_verdict
  property: for all snapshots S and experimental sections E1, E2: verdict(S with E1) = verdict(S with E2)
- **QM-006** THE SYSTEM SHALL produce byte-identical snapshot and report
  documents for an identical tree, base ref and thresholds, keeping wall
  clock times and durations in a separate document.
  tier:     T1
  verify:   bash scripts/metrics_test.sh report_is_byte_stable
  property: for all inputs I, run(I) = run(I) as bytes, for the snapshot and the report

### Layers

- **QM-007** THE SYSTEM SHALL read the crate-to-layer table and the allowed
  directions from a committed rules file and SHALL report every normal
  dependency edge between workspace crates that the table forbids and no
  exception names. Development and build dependencies are not edges.
  tier:     T0
  verify:   bash scripts/metrics_test.sh forbidden_edge_is_reported
  - IF an exception names an edge THEN THE SYSTEM SHALL report that edge as
    excepted, with the exception's issue and date, and SHALL count it toward
    the exceptions ratchet rather than toward the failure gate.
    tier:   T0
    verify: bash scripts/metrics_test.sh excepted_edge_is_counted_not_failed
- **QM-008** IF a workspace member appears in no layer THEN THE SYSTEM SHALL
  list it as unassigned and fail the unassigned gate.
  tier:     T0
  verify:   bash scripts/metrics_test.sh unassigned_crate_fails

### Grading a change

- **QM-009** WHEN grading a change THE SYSTEM SHALL read the thresholds
  from the merge-base with the base ref and the baseline snapshot from the
  history ref, and SHALL evaluate each gate against the stricter of the
  base ref's thresholds and the change's own.
  tier:     T1
  verify:   bash scripts/metrics_test.sh base_thresholds_win_when_stricter
  property: for all base thresholds B and head thresholds H, effective(B, H) = stricter(B, H) per gate, so no change loosens the gate it is graded by
  - IF no baseline snapshot exists for the base ref THEN THE SYSTEM SHALL
    report every ratchet gate as not evaluated and say so in the report.
    tier:   T0
    verify: bash scripts/metrics_test.sh no_baseline_means_not_evaluated
- **QM-010** WHEN grading a change THE SYSTEM SHALL write a report in
  Markdown and the same content as JSON, carrying the head and base
  commits, the baseline's name and age, one row per gate with value,
  baseline, threshold and result, the changed crates with their deltas, the
  promotable lints, and the collectors that did not run in this mode.
  tier:     T0
  verify:   bash scripts/metrics_test.sh report_carries_every_section
- **QM-011** WHERE `GITHUB_STEP_SUMMARY` names a writable file THE SYSTEM
  SHALL append the Markdown report to it.
  tier:     T0
  verify:   bash scripts/metrics_test.sh step_summary_is_appended
- **QM-012** WHEN the quality gate task runs THE SYSTEM SHALL derive the
  base ref itself, take no parameters, invoke no compiler, and end its
  standard output with one line naming the verdict, the report path and the
  report's SHA-256.
  tier:     T0
  verify:   bash scripts/metrics_test.sh gate_runs_without_rustc
- **QM-013** WHILE running on macOS THE SYSTEM SHALL restrict the compiling
  collectors to the crates that build there, mark the snapshot as a darwin
  run that is never published, and list every changed crate the scope
  leaves out.
  tier:     T0
  verify:   bash scripts/metrics_test.sh darwin_scope_lists_uncovered_crates

### History and dashboard

- **QM-014** WHEN a nightly run on main completes THE SYSTEM SHALL add one
  snapshot named by date and short commit to the history ref and SHALL
  never write to the main branch.
  tier:     T0
  verify:   bash scripts/metrics_test.sh publish_targets_history_ref_only
- **QM-015** THE SYSTEM SHALL keep one snapshot per day for ninety days and
  the first snapshot of each month beyond that, deciding what to keep from
  the file names alone.
  tier:     T1
  verify:   bash scripts/metrics_test.sh prune_keeps_daily_then_monthly
  property: for all histories H and dates d: keep(f) iff age(f, d) <= 90 days or f is the earliest snapshot of its month
- **QM-016** THE SYSTEM SHALL render the dashboard from the history alone,
  with no network access and no package installation, and every chart SHALL
  carry a title and a data table of the values it draws.
  tier:     T0
  verify:   bash scripts/metrics_test.sh dashboard_renders_offline_with_tables

### Hotspots

- **QM-018** THE SYSTEM SHALL rank source files as hotspots by their change
  frequency over a declared window multiplied by their quality findings
  (complexity hits, strict-lint hits and uncovered lines), and SHALL carry
  the ranked list with each file's components in the snapshot and in the
  report.
  tier:     T1
  verify:   bash scripts/metrics_test.sh hotspots_rank_churn_times_findings
  property: for all files a, b with churn(a) >= churn(b) and findings(a) >= findings(b), rank(a) <= rank(b); a file with no findings or no changes in the window has score 0
  - IF coverage was not measured THEN THE SYSTEM SHALL rank on churn and
    findings alone and say so in the report.
    tier:   T0
    verify: bash scripts/metrics_test.sh hotspots_without_coverage

### Test quality

- **QM-017** WHEN grading a change THE SYSTEM SHALL mutation-test only the
  lines the change added or edited, and WHEN running nightly THE SYSTEM
  SHALL mutation-test the lines changed since the newest published snapshot
  within a declared time budget, reporting a run that reached the budget as
  partial.
  tier:     T0
  verify:   bash scripts/metrics_test.sh mutants_scope_follows_mode
  - IF the change adds a source file that is not yet tracked THEN THE
    SYSTEM SHALL list that file as outside the mutation scope.
    tier:   T0
    verify: bash scripts/metrics_test.sh untracked_file_is_listed

## Non-goals

- Performance benchmarks with criterion: a later spec. The boot latency
  harness `scripts/bench-minvmd-boot.sh` stays as it is.
- Uploading SARIF to code scanning: needs a workflow permission the frozen
  workflows do not grant; a later maintainer-owned change.
- A quality job in the pull-request lanes: a later maintainer-owned
  workflow change once the gate's noise level is known from the nightly
  data.
- Grading the review agent itself: `gominimal/foundry` `grade/`.
- Choosing which review finding may block a merge: the review contract in
  `gominimal/foundry` `review/contract/`.
- Enforcing the thresholds in the coding agent's runtime: the runtime runs
  the repository's declared gate and reports its exit; what the gate
  checks is this spec.

## Non-functional requirements

- **QM-N01** WHILE the quality gate task runs in a sandbox with a warm
  checkout and no build directory THE SYSTEM SHALL finish within 300
  seconds, the review runtime's probe budget.
  tier:   T0
  verify: bash scripts/metrics_test.sh gate_fits_probe_budget
- **QM-N02** WHILE the full nightly run executes on the standard Linux
  runner THE SYSTEM SHALL finish within 120 minutes.
  tier:   T0
  verify: bash scripts/metrics_test.sh nightly_budget_is_declared

## Design reasoning

**Snapshots in git, on a history ref, not on main.** The repository rule is
that nothing commits to main outside a reviewed pull request. A pull
request per nightly snapshot needs a token that can trigger CI and a
code-owner carve-out for the history directory, and it adds a review per
day for a file nobody reads by hand. An unprotected history ref holds the
same data, is readable by `git show`, and needs only the token every
workflow already has. The gate reads its baseline from that ref.

**The base ref owns the thresholds.** A change that is graded by thresholds
it can edit is not graded. Reading the thresholds from the merge-base and
applying the stricter of base and head means a change may tighten the bar
immediately and may loosen it only after review has merged the loosening.

**The nightly mutation scope is yesterday's change, not a workspace
shard.** A seventh of the workspace is thousands of mutants, which no
night can finish; the lines changed since the last snapshot are bounded,
and a trend over them says whether new code arrives tested. A wall-clock
budget keeps one large change from taking the run with it.

**Three run tiers, forced by two budgets.** The review runtime gives a
probe 300 seconds and delivers no arguments; the coding runtime gives the
gate 600 seconds and has lost most of it to a cold compile before. So the
gate tier compiles nothing and derives its own inputs; the diff tier adds
Clippy on the changed crates for a developer or an agent with time; the
full tier runs coverage, mutation testing and module analysis nightly, where
the budget is hours.

**Whole-tree lint counts, not just changed lines.** The strict gate already
reports changed lines. What nobody has is the total per lint, which is the
only number that tells a maintainer when a lint can move into the workspace
set. The snapshot carries both: totals for promotion, changed-line hits for
the report.

**Experimental metrics are recorded and never gate.** Coupling scores,
instability and abstractness come from young tools whose numbers move
between versions. Recording them builds the history that decides whether
they are worth gating on; gating on them now would make the verdict depend
on a tool's release notes.

**Hotspots are churn times findings, not findings alone.** A complex file
nobody touches costs nothing until someone touches it. A file that changes
every week and carries strict-lint hits and uncovered lines is where a
refactor pays back first. The window is declared in the thresholds file so
the ranking is reproducible from the tree and its history.

**No new workspace crate.** A Rust tool for collection would enter every
workspace build, every Clippy run and the coverage denominator it measures.
Stdlib Python is already a prerequisite of this repository, and the
collectors are glue over tool output.

**Generality:** the snapshot schema names metrics, not tools. A second
coverage tool or a second coupling tool fills the same fields. The layer
rules are a table over `cargo metadata`, so a second workspace needs a new
table, not new code. The grading reads two git refs and a threshold file,
so a second forge needs only a different publish step.

## Security considerations

- **Invariant:** THE SYSTEM SHALL evaluate a change only against thresholds
  and a baseline read from refs the change cannot write.
  enforced by: resolving the thresholds at the merge-base with the base ref
  and the baseline on the history ref, never from the working tree
  covered by: QM-009
- **Invariant:** THE SYSTEM SHALL write nothing to the main branch.
  enforced by: the publish step pushing to the history ref only, with a
  workflow permission that is checked by the harness
  covered by: QM-014
- **Invariant:** THE SYSTEM SHALL produce a report whose bytes depend only
  on the tree, the base ref and the thresholds, so the review runtime's
  recorded SHA-256 identifies what was measured.
  enforced by: keeping times and durations out of the report document
  covered by: QM-006

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): the unused-dependency tool is not packaged
  for the sandbox, so the gate tier reports that collector as not measured
  there until it is. Package it, or accept the gap?]
- [NEEDS CLARIFICATION (LOW): the probe output carries no pull request
  number, so a later join between the report and the review runtime's
  records uses the repository and head commit. Is that key enough?]
