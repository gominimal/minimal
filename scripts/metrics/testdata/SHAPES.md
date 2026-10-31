# Fixture shapes

Where each fixture's shape comes from and how far it has been verified. JSON
carries no comments, so the provenance lives here. A fixture marked
"documentation only" was written from the tool's published docs because the
tool could not be installed where this was authored (crates.io downloads
blocked, no prebuilt binaries); the first real run should be diffed against
it and any difference fixed in `collect.py`'s `.get` chain.

| Fixture | Stands in for | Source | Verified |
|---|---|---|---|
| `cargo-metadata.json` | `cargo metadata --no-deps` over this tree | a real run | run |
| `small-metadata.json` | `cargo metadata --no-deps` over a small tree | hand-written from the real one | run (same shape) |
| `clippy.json` | `cargo clippy --message-format=json` | a real run, trimmed | run |
| `llvm-cov.json` | `cargo llvm-cov --json --summary-only` | a real run, trimmed | run |
| `tokei.json` | `tokei --output json --files` | a real run, trimmed | run |
| `modules.jsonl` | `run.sh`'s own per-crate lines | `run.sh` | run |
| `shear.json` | `cargo shear --format json` | a real run, trimmed | run |
| `rustqual/graph.json`, `rustqual/decode.json` | `rustqual crates/<c>/src --format json` | [book/reference-output-formats.md](https://github.com/SaschaOnTour/rustqual/blob/main/book/reference-output-formats.md) at 1.8.3 | documentation only |
| `anatomy.json` | `cargo anatomy` (compact JSON is its default) | [docs/output-schema.md](https://github.com/cutsea110/cargo-anatomy/blob/main/docs/output-schema.md) at 0.7.7 | documentation only |

## rustqual

The docs expand `summary` (every key the fixture carries), one `functions`
entry and one `architecture_findings` entry. `coupling.modules`,
`coupling.cycles`, `coupling.sdp_violations`, `duplicates` and `dead_code`
are shown collapsed (`[/* ... */]`), so their entries here are a guess from
the prose of
[book/coupling-quality.md](https://github.com/SaschaOnTour/rustqual/blob/main/book/coupling-quality.md),
which defines a module's instability as `fan_out / (fan_in + fan_out)`.
`collect.py` reads only the lengths of those arrays, plus a module's
`instability` when the key exists, so a different entry shape changes
`max_instability` to `null` and nothing else. `quality_score` is on the 0 to
1 scale the docs show; the CLI's `--min-quality-score` speaks of 0 to 100.
The snapshot records the number as emitted.

## cargo-anatomy

`crates[].crate_name`, `metrics.{n, r, h, ca, ce, a, i, d, d_prime}`,
`evaluation` and `warnings.dependency_cycles` follow the published schema
exactly. `details` appears only with `-a`, which `run.sh` does not pass.
