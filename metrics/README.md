# Quality metrics

The architectural-health measurement of this workspace
([spec 31](../docs/specs/31-spec-quality-metrics/31-spec-quality-metrics.md)).
`just metrics` writes one snapshot of the tree; the nightly run adds its
snapshot to the `metrics-data` branch; a change is graded against the newest
snapshot and thresholds of its base ref. This directory holds what a person
edits: the thresholds and the layer table. The code is under
`scripts/metrics/`.

## Files

- `thresholds.toml`: floors, ceilings and ratchets, per-crate overrides, the
  per-function complexity thresholds, and the hotspot window. The copy at the
  merge-base with the base ref decides a change's grade when it is stricter
  than the change's own copy, so a change can tighten a gate at once and loosen
  one only after review.
- `layers.toml`: every crate's layer, the directions a layer may depend in,
  and the edges the tree still carries as dated exceptions.

## Running it

| Command | What it does |
|---|---|
| `just metrics-tools` | Installs the pinned tools (`scripts/metrics/install-tools.sh`); `scripts/metrics/install-tools.sh --experimental` adds the experimental collectors. |
| `just metrics` | Full snapshot into `.scratch/metrics/full/`: lint density, coverage, size, module cycles, unused dependencies, layers, hotspots, and the experimental coupling metrics when their tools are installed. Minutes to tens of minutes. |
| `just metrics static` | The no-compiler subset into `.scratch/metrics/static/`: size, unused dependencies, layers, hotspots by churn. Seconds. |
| `just metrics-mutants [BASE]` | The static subset plus cargo-mutants over the lines changed since the merge-base with `BASE` (default `origin/main`), into `.scratch/metrics/mutants/`. Linux only. Minutes for a small change. |
| `just metrics-layers` | The layer check alone, against `cargo metadata`. Part of `just ci`. |
| `just metrics-diff [BASE]` | Grade this branch against its base: clippy over the crates the branch touched, the static collectors, then the report in `.scratch/metrics/diff/`. Minutes. |
| `scripts/metrics/run.sh gate` | The same grade without a compiler, in seconds: what the `quality-gate` task runs. |

On macOS the compiling collectors run over the crates that build there, the
snapshot is marked `darwin`, and the crates left out are listed in `scope`.
A darwin snapshot is never published.

Exit codes of `scripts/metrics/run.sh`: `0` the verdict is pass or warn, `2`
the verdict is fail, `3` a collector could not run and the snapshot is
incomplete, `1` nothing was written. None of the non-zero ones reads as clean.
In the grading modes the verdict is the report's, not the snapshot's.

## Grading a change

`scripts/metrics/diff.py` grades a head snapshot against two things the change
cannot write: `metrics/thresholds.toml` at the merge-base with the base ref,
and the newest snapshot under `history/` on the history ref
(`origin/metrics-data`). Each gate is evaluated against the stricter of the
base's threshold and the head's (floors take the higher value, ceilings and
ratchet tolerances the lower, and a gate only one side declares is kept), with
collect.py's own gate evaluation, so a snapshot and a report never disagree on
what a gate means. With no baseline every ratchet is `not_evaluated` and the
report says so. When the thresholds file does not exist at the merge-base yet,
the head's copy is the only one and the report says that too.

### Modes

- `gate`: the no-compiler grade. Layers, size and hotspots run; clippy,
  coverage and module analysis are recorded as not measured, and so is
  cargo-shear, because it resolves the full dependency graph through a `cargo
  metadata` that probes `rustc`. The one cargo call is `cargo metadata
  --no-deps --offline`. Seconds on a warm checkout with no build directory.
- `diff`: gate plus clippy over the crates the change touched, scoped the way
  `scripts/clippy-strict.sh` scopes itself (an explicit `-p` list wins; Rust
  changes outside `crates/` widen it to the workspace; no Rust changes skip it).
  `--coverage` adds llvm-cov over the same crates. When the scope is a subset
  of the workspace, the ratchets over clippy and coverage re-sum the baseline
  over the same crates, so a partial run is never compared against a
  whole-workspace total.

Both modes take an optional base ref after the mode (`run.sh diff main`);
empty or absent means the merge-base with `origin/main`, falling back to the
local `main`, the rule `scripts/lib/changed-lines.sh` holds for both gates.
Both end stdout with one line:

```text
quality-gate: <pass|warn|fail> report=<path to report.json> sha256=<hex>
```

### The report

`report.md` is for a person or an agent, `report.json` the same content as
data (`kind: "report"`, `schema_version: 1`), `meta.json` the wall-clock data.
The two report documents carry no times, so identical inputs give identical
bytes and the sha256 on the final line identifies what was measured.

| Section | Content |
|---|---|
| Header | Head and base commits, the merge-base, the repository, where the thresholds came from, and the baseline's file name, commit and age in commits (or that there is none). |
| `Verdict` | The worst gate result, in bold. |
| `Gates` | One row per gate: value, baseline, effective threshold (marked `(base)` when the base's stricter copy set it), result. |
| `Changed crates` | Every workspace crate with changed Rust lines: strict hits new on changed lines, strict and complexity totals with their delta against the baseline, unused dependencies, layer. |
| `New strict hits on changed lines` | `path:line [code]` for every strict diagnostic on a line the change added or edited. |
| `Promotable strict lints` | The strict lints at zero across the workspace, or that a partial scope could not tell. |
| `Not measured in this mode` | Each collector that did not run, with its reason. |
| `Scope` | The snapshot's mode and scope, and every changed crate a pinned scope left out (macOS, or an explicit `-p`). |

When `GITHUB_STEP_SUMMARY` names a writable file, `report.md` is appended to
it; an unwritable path is reported on stderr and does not stop the run.

`report.json` keys: `repo`, `head_sha`, `base_ref`, `base_sha`, `merge_base`,
`baseline` (`name`, `sha7`, `age_commits`, or null), `pr` (null: the probe
carries no pull request number), `verdict`, `gates`, `changed_crates`,
`new_strict_hits`, `promotable`, `not_measured`, `scope`, `scope_uncovered`.

### The quality-gate task

`.minimal/minimal.toml` declares `quality-gate`, which runs `run.sh gate` into
`.scratch/metrics/quality-gate/`. The review runtime runs it as a probe under a
300-second budget with no arguments, and cites the sha256 of its output as
attested evidence; so the task takes no parameters, derives its own base ref,
compiles nothing and ends with the line above. `agent-verify`, the gate the
coding runtime runs after a task's tests, ends with the same run, so a
regression against the base ref fails the coder's own gate in the session that
caused it.

### Shared with clippy-strict

`scripts/lib/changed-lines.sh` resolves the base ref and writes the changed
ranges and the untracked Rust files; `scripts/metrics/changed_lines.py` parses
them. `scripts/clippy-strict.sh` and the grading modes both use them, so the
two gates agree on which lines are the change's own.

## The snapshot (schema version 1)

`snapshot.json` is written with sorted keys and no timestamps, so two runs over
the same tree, baseline and thresholds produce the same bytes. Times live in
`meta.json` beside it. `scripts/metrics/schema.py` validates the shape.

| Block | Content |
|---|---|
| `run` | `mode` (`full`, `static`, `gate`, `diff`, `darwin`, `mutants`), host OS and arch, and `not_measured`: collector name to the reason it did not run. |
| `git` | `sha`, `sha7`, `ref`, `dirty`. |
| `toolchain`, `tools` | Versions that measured the tree. |
| `scope` | `crates` the compiling collectors covered; `excluded` crates source-level tools cannot see, with the reason. |
| `crates.<name>` | `layer`, then one block per collector, each `null` when not measured: `size` (files, code, comments, blanks, test code), `clippy` (workspace lints, every strict lint's count, complexity lint counts, the two totals), `coverage` (lines, functions, regions as covered, total, pct), `modules` (acyclic, cycles, orphans), `deps` (internal, unused), `mutants` (tested, caught, missed, timeout, unviable, score_pct), `crap` (functions, over_threshold, max), `experimental` (`rustqual` and `anatomy` sub-blocks, each `null` when that tool did not run; the whole block `null` when neither did). |
| `workspace` | The same blocks summed, plus `strict_promotable`: the strict lints at zero across the whole tree, present only when clippy covered the whole workspace. `mutants` adds `scope`, `since`, `partial` and `untracked_outside_scope`; `crap` adds the `threshold` it counted against. `experimental` carries the rustqual score weighted by lines of code with the finding counts summed, and the mean distance from the main sequence with the crates in the zone of pain. |
| `layers` | Every forbidden edge with whether an exception names it, the counts `unexcepted` and `exceptions`, the `unassigned` crates, and stale exceptions. |
| `hotspots` | Files ranked by churn over `window_days` multiplied by findings, with each file's components. |
| `gates` | One entry per threshold, keyed `<kind>:<metric>` (`floor:coverage.lines_pct`, `ratchet:clippy.strict.total`): value, threshold or baseline, result (`pass`, `warn`, `fail`, `not_evaluated`). |
| `verdict` | The worst gate result. |

`summary.md` beside the snapshot is the same numbers as a page of Markdown:
the verdict, every gate, the workspace totals, the module cycles, the
promotable lints and the top hotspots. `full` and `static` runs write it and
append it to `GITHUB_STEP_SUMMARY` when that is set, so the nightly run shows
the snapshot on its summary page; the grading modes append their report
instead.

`clippy-hits.json` beside the snapshot lists every strict and complexity
diagnostic as path, line and code, for the diff grader to intersect with the
lines a change touched.

### Lint density

Clippy runs with the strict lints of `scripts/clippy-strict.sh` and the three
per-function complexity lints (`cognitive_complexity`, `too_many_lines`,
`too_many_arguments`, thresholds in `clippy.toml`). Diagnostics are
deduplicated on file, line and code, because `--all-targets` reports a site
once per compilation unit. A diagnostic with any other code counts under
`workspace_lints`, which `just clippy` already holds at zero. When a strict
lint's workspace count is zero it appears under `strict_promotable`: move it
into `[workspace.lints.clippy]` and out of the strict list.

### Coverage

`cargo llvm-cov nextest` under the `coverage` profile of
`.config/nextest.toml`. Test sources, fuzz targets, benches, examples,
`build.rs` and anything under `target/` stay out of the denominator. Tests
gated behind `#[ignore]` do not run, so the daemons' coverage is structurally
low on a host without KVM; `thresholds.toml` carries per-crate floors for them.

### Module cycles and orphans

The module graph of every target of a crate comes from `cargo modules
dependencies` with functions, traits and types filtered out, and the
collector finds the strongly connected components itself: the tool's own
cycle check runs before its filters and reports every type that owns a
method using the type. Edges touching the crate root (which re-exports its
children while they `use crate::`) or a test module are structure, not
findings. A module is an orphan only when every target of its crate orphans
it, so a binary-only module is not an orphan of the library.

### Hotspots

For each source file: commits touching it in the window, strict hits,
complexity hits and uncovered lines. The score is
`churn × (complexity + strict + uncovered_lines / 100)`. Every component is
monotone, so a file that is worse on every axis never ranks below one that is
better on every axis. With no coverage the uncovered term is dropped and
`coverage_included` is false; with no findings source at all (static mode) the
ranking is churn alone and `findings_included` is false. A hotspot is where a
refactor pays back first: a complex file nobody touches costs nothing until
someone touches it.

### Experimental coupling metrics

Two tools measure how the code is coupled, inside a crate and between
crates. Both run in `full` mode when installed, and `--no-experimental`
skips them.

- **rustqual** reads a crate's `src/` and scores it. IOSP (Integration
  Operation Segregation Principle) asks that a function either orchestrates
  calls or holds logic, never both; a function doing both is an IOSP
  violation. Per module it computes fan-in, fan-out and instability
  (`fan_out / (fan_in + fan_out)`), reports circular module dependencies
  (`CP-001`) and a stable module depending on an unstable one, the Stable
  Dependencies Principle (`CP-002`). It also counts complexity findings,
  dead code, duplicates and LCOM4-style cohesion on structs. The snapshot
  keeps the overall score, those counts and each crate's highest module
  instability; a SARIF copy per crate lands under `rustqual/` beside the
  snapshot for a viewer, and nothing reads it.
- **cargo-anatomy** reads the whole workspace through `cargo metadata` and
  computes Robert Martin's package metrics per crate: afferent and efferent
  coupling (`Ca`, `Ce`), instability `I = Ce / (Ce + Ca)`, abstractness `A`
  (the share of traits among the crate's types), the distance from the main
  sequence `D = |A + I - 1| / sqrt 2`, and relational cohesion
  `H = (R + 1) / N`. A crate that is concrete and stable sits in the zone of
  pain: everything depends on it and nothing in it can change cheaply. The
  workspace block lists the crates with `D > 0.5` on that side.

Neither feeds a gate, and `thresholds.toml` has no key for them: the tools
are young and their numbers move between releases, so a gate on them would
make the verdict depend on a tool's release notes rather than on the tree.
The snapshot records them, and the history decides whether a gate is
warranted (QM-005). `remote-proto` is left out of rustqual because its code
is generated into `OUT_DIR` and has no source to read; it stays in
cargo-anatomy, which reads the dependency graph.

Install both with `scripts/metrics/install-tools.sh --experimental`; without
the flag `--check` lists them as optional. A host without them writes a
complete snapshot with the two collectors under `run.not_measured`. The
collectors' field names were taken from the tools' published docs
(`scripts/metrics/testdata/SHAPES.md` says which were verified against a
run), and every lookup tolerates an absent key.
### Test quality

Coverage says a line ran; it does not say a test would notice the line
being wrong. Two measures do.

**Mutation score.** cargo-mutants rewrites one function at a time (returns a
default, flips an operator) and runs the suite with nextest. A mutant the
suite fails on is *caught*; one the suite passes with is *missed*; one that
runs past the timeout is *timeout*; one that does not compile is *unviable*.
The score is `caught / (caught + missed + timeout)`, in percent, and `tested`
is that denominator. An unviable mutant says nothing about the tests, so it
is counted but stays out of the score. The scope follows the mode (QM-017):

- `mutants` mode tests the lines the change added or edited, as a `git diff`
  from the merge-base with the base ref handed to `--in-diff`; `scope` is
  `in-diff`. A new file that is not yet tracked is not in that diff; it is
  listed under `untracked_outside_scope` so a reader knows what was not
  tested. With no Rust change since the base the collector is not measured
  and the list is still written.
- `full` mode (the nightly) tests the lines changed since a reference
  commit: `--since REF`, or by default the newest snapshot in the history
  directory, then the merge-base with `origin/main` on a branch. A workspace
  shard is thousands of mutants and no night is long enough for one;
  yesterday's changes are bounded and are what the history should speak to.
  `scope` is `since`, `since` records the reference, and
  `MINIMAL_METRICS_MUTANTS_BUDGET_SECS` caps the run; a run that hits the cap
  reports what it tested with `partial` set. `--no-mutants` skips it.

A crate the run generated no mutants for carries `null`, not a perfect
score. The run needs the baseline suite green, which it is only on Linux; a
darwin snapshot records the collector as not measured, and `mutants` mode
refuses to start there. Results and logs are under `<out>/mutants/mutants.out/`.

**CRAP.** Change Risk Anti-Patterns, per function:
`complexity² × (1 − coverage)³ + complexity`, with coverage as a fraction. A
complex function that is fully tested scores its complexity; an untested one
scores roughly its complexity squared. cargo-crap reads the sources and the
`lcov.info` coverage wrote, so it runs wherever coverage ran. A function over
`[crap] threshold` in `thresholds.toml` is flagged, and `crap.over_threshold`
counts them; the gate is a ratchet, because the tree carries such functions
today and a ceiling of zero would be red from the start.

### Gates

- A **floor** fails below its value, a **ceiling** above it. A floor of `0.0`
  is unseeded and passes; seed it from a snapshot in a reviewed commit.
- A **ratchet** compares to the newest snapshot of the base ref. Worse than
  the baseline but inside `tolerance` is `warn`; past it is `fail`. With no
  baseline the gate is `not_evaluated` and the report says so.
- A gate over a block that was not measured is `not_evaluated`, never `pass`.

## Dashboard and history

The nightly run appends its snapshot to the `metrics-data` branch as
`<date>-<sha7>.json`, so the file names sort chronologically and say when a
snapshot was taken without opening it. The scripts below read that directory
and nothing else.

`scripts/metrics/dashboard.py <history> <out>` writes one self-contained
`index.html`: inline SVG, a style block, no script, nothing fetched, so it
opens from a file or a static host and renders in a sandbox with no network.
It charts, over snapshot date, the workspace coverage of lines, the strict
and complexity lint totals, the unused dependencies, the lines of code, and
the layer edges carried as exceptions beside the unexcepted ones. Every chart
has a heading and a table of the values it draws directly below it, so the
numbers are reachable without the picture. A metric a snapshot did not
measure is a gap in the line, never a zero. From the newest snapshot the page
also lists the gates with their results, the top hotspots with their
components, and the strict lints at zero that are ready to promote. Files
that fail `schema.py` are skipped and named on the page. The page carries no
timestamp: the same history renders the same bytes, and it reads in light
and dark mode.

`scripts/metrics/prune.py <history>` keeps every snapshot dated within ninety
days of the newest one and, beyond that, the earliest snapshot of each
calendar month; everything else is removed, decided from the file names
alone. `--dry-run` prints what would go, `--today YYYY-MM-DD` moves the
reference date.

| Command | What it does |
|---|---|
| `just metrics-dashboard` | Renders `.scratch/metrics/history` into `.scratch/metrics/dashboard/index.html`. |
| `just metrics-prune` | Prunes `.scratch/metrics/history` in place; `just metrics-prune .scratch/metrics/history --dry-run` only lists. |

Both take the history directory as their first argument, to read another
checkout of the branch: `just metrics-dashboard path/to/history`. The fixture
history for the harness lives under `scripts/metrics/testdata/history/`.

## The nightly run

The `metrics` job in `.github/workflows/metrics.yml` runs every night,
called by `nightly-tests.yml`, and on demand by dispatching `metrics.yml`
alone. It runs `just metrics` and renders the dashboard from the fetched
history plus the new snapshot. The `metrics` artifact carries both. The job
builds the tree and runs tools from crates.io, so it runs with a read-only
token that the checkout does not persist. On main, a separate `publish` job holds
the write token. It downloads that artifact and passes the snapshot to
`scripts/metrics/publish-snapshot.sh`. That script fetches the
`metrics-data` branch (creating it as an orphan the first time), adds
`history/<date>-<sha7>.json`, prunes, commits and pushes to that branch
alone: its refspec names the branch on both sides, so it cannot reach main.
It refuses a snapshot whose mode is not `full` or whose tree was dirty. The
job is non-blocking until a week of snapshots says it is quiet.

## Writing about it

Prose here and in the spec is Vale-linted. Name the items or point at the
command that lists them (`just crates`, the lint array in
`scripts/clippy-strict.sh`) rather than stating a count.
