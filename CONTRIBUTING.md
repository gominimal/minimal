# Contributing

## Commit messages

This repository uses [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
See [docs/commit-conventions.md](docs/commit-conventions.md) for the full standard, types, scopes, and examples.

## Building and testing

See [README.md](README.md) for build instructions.

Before opening a PR:

```shell
cargo fmt
cargo test -- --include-ignored
cargo clippy --all-targets -- -D warnings
```

## Coding standards

Rust coding standards are documented in [docs/rust-coding-standards.md](docs/rust-coding-standards.md).

## CI and the test-extension contract

The CI layer is **frozen**: do not edit `.github/workflows/`. It is a thin
scheduler over the tests, `scripts/`, and the `justfile` — all reviewed like
any other code. `/.github/` is CODEOWNER-gated, so workflow edits need an owner
review no matter who authored them. The full rationale and the CI design are in
[docs/ci-strategy.md](docs/ci-strategy.md) (§10 is this contract).

**Adding a test never requires a CI change** — the matching lane discovers it
by where it lives and what it is named:

| Test kind | Where it goes | How CI runs it | Local command |
|---|---|---|---|
| Unit | `#[cfg(test)]` next to the code | nextest target discovery (`ci` / native lane) | `cargo nextest run --workspace` |
| Integration | `crates/<crate>/tests/*.rs` | same | `cargo nextest run --workspace` |
| Doctest | `///` examples in lib code | `cargo test --workspace --doc` | `cargo test --doc` |
| VM boot / session e2e | `crates/minvmd/tests/` (env-gated `#[ignore]` harnesses) | the KVM / macOS lanes build and run them | `just up` then run locally |
| Session scenario | driven by `scripts/session-e2e.sh` across every target | native / KVM / macOS lanes | `E2E_VM=1 E2E_MINIMAL_ARGS=--minvmd ./scripts/session-e2e.sh` |

When a genuinely new *kind* of check is needed, add it to `scripts/` or the
`justfile` (reviewed code) and let the lane call it — never by growing the YAML.

> The VM e2e harnesses are moving to a name-based convention (`*_e2e` /
> `*_root_e2e`) so a lane runs every matching harness by filterset and a new
> one needs no CI edit at all. Until that lands, a genuinely new VM harness is
> the one test kind that still needs a one-line lane change (reviewed as a
> workflow edit).
