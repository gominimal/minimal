# Contributing

## Commit messages

This repository uses [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/),
enforced in CI by **commitlint**. See [docs/commit-conventions.md](docs/commit-conventions.md)
for the full standard, types, scopes, and examples.

The most common trip-up: a commit has **one type**, and multiple scopes go
*inside* the parentheses — `type(scope-a,scope-b): summary`, **not**
`type(scope-a),scope-b:` (the latter makes commitlint read an empty type and
fails the check).

## Building and testing

See [README.md](README.md) for build instructions.

Before opening a PR:

```shell
just ci
```

which runs the same gates the PR lanes run (fmt, clippy, cargo-deny, the
test suite, doctests — plus, on Linux, the locally-runnable `#[ignore]`
tests via `just test-ignored`, which no CI lane covers), dispatched for your
OS. On macOS, `just test-cross` additionally covers the Linux-only crates
(minimald et al.) via `cross`. If your change touches the VM/daemon path,
also run `just e2e` (the session proof) and/or `just test-vm` (the VM
integration harnesses).

## Coding standards

Rust coding standards are documented in [docs/rust-coding-standards.md](docs/rust-coding-standards.md).

## CI and the test-extension contract

The CI layer is **frozen**: do not edit `.github/workflows/`. It is a thin
scheduler over the tests, `scripts/`, and the `justfile` — all reviewed like any
other code. The `.github/` tree is CODEOWNER-gated (the minimalists team owns the
repo), so workflow edits need an owner review no matter who authored them. The
full rationale and CI design are in [docs/ci-strategy.md](docs/ci-strategy.md).

**Adding a test never requires a CI change** — the matching lane discovers it by
where it lives and what it is named:

| Test kind | Where it goes | How CI runs it | Local command |
|---|---|---|---|
| Unit | `#[cfg(test)]` next to the code | every lane's core-tests suite | `just test` (macOS: `just test-cross` adds the Linux-only crates) |
| In-process integration | `crates/<crate>/tests/*.rs` | same core-tests suite | `just test` (macOS: `just test-cross` adds the Linux-only crates) |
| Doctest | `///` examples in lib code | `cargo test --workspace --doc` | `just doctest` |
| **Integration harness** — needs a real VM / kernel / netns | `crates/<crate>/tests/*_integration.rs` (add `_root` → `*_root_integration.rs` if it needs `CAP_NET_ADMIN`) | the KVM / macOS / native lanes **auto-discover it by suffix**, no CI edit: the non-root step runs `binary(/_integration$/) and not binary(/_root_integration$/)` and the `sudo` step runs `binary(/_root_integration$/)` (the `and not` matters — `_root_integration` also ends in `_integration`) | `just test-vm` (root proofs: `just test-root-integration`) — running a harness binary by hand needs `MINVMD_E2E=1`, the `MINVMD_*` artifact paths, and `--include-ignored`, or every test self-skips green |
| **End-to-end** — drives the `minimal` CLI through the whole system | a script under `scripts/` (e.g. `session-e2e.sh`) | native / KVM / macOS lanes call the script | `just e2e` (VM-backed; wraps `scripts/session-e2e.sh`) or `just e2e-native` (Linux, no VM) |

The line between the last two rows: **does the test drive the `minimal` CLI
through a full user workflow across the whole system?** If yes it is an
*end-to-end* proof and lives as a script; otherwise — even if it boots a VM — it
is an *integration* harness and lives as a `*_integration.rs` file. A new
`*_integration.rs` is picked up by every matching lane with zero workflow edit,
and a per-crate naming guard (a normal unit test) fails CI if a harness is
misnamed, so it can never silently drop out of a lane.

When a genuinely new *kind* of check is needed, add it to `scripts/` or the
`justfile` (reviewed code) and let the lane call it — never by growing the YAML.
