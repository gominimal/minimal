# Quality metrics

The architectural-health measurement of this workspace
([spec 30](../docs/specs/30-spec-quality-metrics/30-spec-quality-metrics.md)).
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
| `just metrics-tools` | Installs the pinned tools (`scripts/metrics/install-tools.sh`). |
| `just metrics` | Full snapshot into `.scratch/metrics/full/`: lint density, coverage, size, module cycles, unused dependencies, layers, hotspots. Minutes to tens of minutes. |
| `just metrics static` | The no-compiler subset into `.scratch/metrics/static/`: size, unused dependencies, layers, hotspots by churn. Seconds. |
| `just metrics-layers` | The layer check alone, against `cargo metadata`. Part of `just ci`. |

On macOS the compiling collectors run over the crates that build there, the
snapshot is marked `darwin`, and the crates left out are listed in `scope`.
A darwin snapshot is never published.

Exit codes of `scripts/metrics/run.sh`: `0` the verdict is pass or warn, `2`
the verdict is fail, `3` a collector could not run and the snapshot is
incomplete, `1` nothing was written. None of the non-zero ones reads as clean.

## The snapshot (schema version 1)

`snapshot.json` is written with sorted keys and no timestamps, so two runs over
the same tree, baseline and thresholds produce the same bytes. Times live in
`meta.json` beside it. `scripts/metrics/schema.py` validates the shape.

| Block | Content |
|---|---|
| `run` | `mode` (`full`, `static`, `gate`, `diff`, `darwin`), host OS and arch, and `not_measured`: collector name to the reason it did not run. |
| `git` | `sha`, `sha7`, `ref`, `dirty`. |
| `toolchain`, `tools` | Versions that measured the tree. |
| `scope` | `crates` the compiling collectors covered; `excluded` crates source-level tools cannot see, with the reason. |
| `crates.<name>` | `layer`, then one block per collector, each `null` when not measured: `size` (files, code, comments, blanks, test code), `clippy` (workspace lints, every strict lint's count, complexity lint counts, the two totals), `coverage` (lines, functions, regions as covered, total, pct), `modules` (acyclic, orphans), `deps` (internal, unused), `mutants`, `crap`, `experimental`. |
| `workspace` | The same blocks summed, plus `strict_promotable`: the strict lints at zero across the whole tree, present only when clippy covered the whole workspace. |
| `layers` | Every forbidden edge with whether an exception names it, the counts `unexcepted` and `exceptions`, the `unassigned` crates, and stale exceptions. |
| `hotspots` | Files ranked by churn over `window_days` multiplied by findings, with each file's components. |
| `gates` | One entry per threshold, keyed `<kind>:<metric>` (`floor:coverage.lines_pct`, `ratchet:clippy.strict.total`): value, threshold or baseline, result (`pass`, `warn`, `fail`, `not_evaluated`). |
| `verdict` | The worst gate result. |

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

### Gates

- A **floor** fails below its value, a **ceiling** above it. A floor of `0.0`
  is unseeded and passes; seed it from a snapshot in a reviewed commit.
- A **ratchet** compares to the newest snapshot of the base ref. Worse than
  the baseline but inside `tolerance` is `warn`; past it is `fail`. With no
  baseline the gate is `not_evaluated` and the report says so.
- A gate over a block that was not measured is `not_evaluated`, never `pass`.

## Writing about it

Prose here and in the spec is Vale-linted. Name the items or point at the
command that lists them (`just crates`, the lint array in
`scripts/clippy-strict.sh`) rather than stating a count.
