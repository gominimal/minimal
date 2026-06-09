# Spikes

A spike is a bounded experiment that resolves a load-bearing assumption before
planning commits to it. A `kind:spike` sub-issue's deliverable is a written
finding — never a code change. Each spike lands one file in this directory and
nothing else.

This README is operational hygiene for spike authors. The full protocol is in
the suite's spike fragment; what follows is what you must honor when you run a
spike on this repository.

## What a spike writes

A spike writes exactly one file: `docs/spikes/<date>-<slug>.md`, where `<date>`
is the spike's open date (`YYYY-MM-DD`) and `<slug>` is a short hyphenated
subject from the spike sub-issue's title. It writes no other path. A spike
never edits source, config, or any build surface — if your experiment seems to
need one, that is a signal to park (see below), not to widen the diff.

## Branch and close convention

A spike uses the **standard** implementation branch `sdd/<spike-issue-id>-<slug>`
— the same convention every implementation pull request uses. Do not invent a
custom branch prefix for spikes; a non-standard prefix breaks the suite's
in-flight detection and produces a duplicate pull request. The pull request body
carries `Closes #<spike-issue>` so merging it closes the spike sub-issue.

## The doc

Each `docs/spikes/<date>-<slug>.md` carries YAML frontmatter followed by a fixed
set of sections.

Frontmatter:

- `id` — the spike sub-issue number.
- `title` — the spike's one-line subject.
- `status` — one of the status values below.
- `date` — the open date (`YYYY-MM-DD`).
- `authors` — who ran the experiment.
- `budget_hours` — the time box the spike was given.
- `actual_hours` — the time the experiment actually took.
- `related` — issues, pull requests, or ADRs the spike informs.
- `tags` — free-form topic tags.

Sections, in order: **Question**, **Hypothesis**, **Method**, **Findings**,
**Conclusion**, **Action items**, **Artifacts**. Findings carry their evidence
inline — the exact commands and their output, measurement tables, and links to
the sources inspected. Action items group what the finding changes downstream:
spec amendments, ADR follow-ups, risk-register entries, and follow-up spikes.

### Status values

- `proved` — the hypothesis held; the assumption is now load-bearing-safe.
- `disproved` — the hypothesis failed; the plan must change.
- `partial` — the spike resolved part of the question and queued follow-up
  spikes for the rest. This is a legitimate outcome, not a failure.
- `parked` — the experiment could not run to completion in the sandbox (see
  below).

## Honor the budget

`budget_hours` is a box, not a target. When you reach it, stop and write up what
you have: a `partial` finding with the remainder queued as follow-up spikes is
more useful than an over-budget experiment with no written outcome. Record the
real `actual_hours` so the next planner can calibrate.

## Quote denials verbatim

When the experiment needs runtime or hardware the sandbox lacks, or a guardrail
denies an action it requires, **park** the spike — never fabricate a result.
Commit a `status: parked` partial doc and, in Findings, quote the denial or the
missing-capability message **verbatim** as the evidence for why the experiment
could not finish. Do not paraphrase it, and do not invent measurements or a
conclusion the evidence does not support. Queue the remaining work as follow-up
spikes, and hand off to a human via the suite's `needs-human` contract.

A parked spike opens a normal (non-draft) pull request carrying the parked doc
plus the `needs-human` hand-off — the suite's pull-request configuration is
static and cannot mint a literal draft, so the parked doc and the `needs-human`
label together carry the "do not merge yet" signal a draft would.

## Clean up after the experiment

A spike often spins up infrastructure to take a measurement: containers, a local
server, a database, a long-running process, scratch files outside
`docs/spikes/`. Tear all of it down before you finish. Stop and remove any
container or process you started, kill background servers, and delete scratch
files so the only thing your diff lands is `docs/spikes/<date>-<slug>.md`. A
leftover container or a stray file outside `docs/spikes/` widens the diff,
trips the suite's docs-only exemption, and forces the full build/test gate to
run against a tree it should never have seen.
