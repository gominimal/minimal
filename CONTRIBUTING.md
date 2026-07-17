# Contributing to Minimal (https://github.com/gominimal/minimal)

Thank you for your interest in contributing! This project is developed by **Minimal.dev Software Inc.** and released under the [Apache License 2.0](./LICENSE).

We welcome contributions of all kinds — bug reports, documentation improvements, features, and feedback. This document explains how to contribute and what you need to know about our Contributor License Agreement (CLA).

## TL;DR

1. Fork the "main" branch and commit your chanages to your fork
4. Submit your PR as normal
2. Before we can accept your pull request, you'll need to sign our **Contributor License Agreement (CLA)**.
3. This happens automatically on your first PR — a bot will comment with a link. It takes about 30 seconds.

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
cargo fmt
cargo test -- --include-ignored
cargo clippy --all-targets -- -D warnings
```

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
| Unit | `#[cfg(test)]` next to the code | every lane's core-tests suite | `cargo nextest run --workspace` |
| In-process integration | `crates/<crate>/tests/*.rs` | same core-tests suite | `cargo nextest run --workspace` |
| Doctest | `///` examples in lib code | `cargo test --workspace --doc` | `cargo test --workspace --doc` |
| **Integration harness** — needs a real VM / kernel / netns | `crates/<crate>/tests/*_integration.rs` (add `_root` → `*_root_integration.rs` if it needs `CAP_NET_ADMIN`) | the KVM / macOS / native lanes **auto-discover it by suffix**, no CI edit: the non-root step runs `binary(/_integration$/) and not binary(/_root_integration$/)` and the `sudo` step runs `binary(/_root_integration$/)` (the `and not` matters — `_root_integration` also ends in `_integration`) | `just up`, then run the harness binary |
| **End-to-end** — drives the `minimal` CLI through the whole system | a script under `scripts/` (e.g. `session-e2e.sh`) | native / KVM / macOS lanes call the script | `E2E_VM=1 E2E_MINIMAL_ARGS=--minvmd ./scripts/session-e2e.sh` |

The line between the last two rows: **does the test drive the `minimal` CLI
through a full user workflow across the whole system?** If yes it is an
*end-to-end* proof and lives as a script; otherwise — even if it boots a VM — it
is an *integration* harness and lives as a `*_integration.rs` file. A new
`*_integration.rs` is picked up by every matching lane with zero workflow edit,
and a per-crate naming guard (a normal unit test) fails CI if a harness is
misnamed, so it can never silently drop out of a lane.

When a genuinely new *kind* of check is needed, add it to `scripts/` or the
`justfile` (reviewed code) and let the lane call it — never by growing the YAML.

## Why do we require a CLA?

A CLA is a standard instrument in many large open source projects (the Apache Software Foundation, Google, Microsoft, the CNCF, and many others all require one). It clearly defines the terms under which intellectual property has been contributed. By having these instruments in place, it supports the growth and  sustainability of this open source project.

Full text: [ICLA](./legal/ICLA.md) · [CCLA](./legal/CCLA.md)

## Individual vs. Corporate

- **Contributing as yourself, on your own time, with code you own?** Sign the **Individual CLA (ICLA)**. The bot will walk you through it.
- **Contributing as part of your job, or with code your employer might own?** Your employer needs to sign the **Corporate CLA (CCLA)** and list you as an authorized contributor. Then you'll also sign the ICLA. If you're unsure whether your employer has rights to your contribution, it's worth a conversation with them before contributing. Email **security@minimal.dev** if you need help getting a CCLA in place.

## How signing works

We use [CLA Assistant](https://cla-assistant.io/). When you open your first pull request:

1. A bot will comment with a link to the CLA.
2. Click the link, review the document, and click "I Agree" after signing in with your GitHub account.
3. The bot will re-check your PR and mark the CLA status as satisfied.
4. Once signed, you're covered for all future contributions to any of our repositories.

Your signature record (GitHub username, email, timestamp, CLA version) is stored and available for your records.

## Development workflow

1. Fork the repository.
2. Create a feature branch: `git checkout -b your-feature-name`.
3. Make your changes. Add tests where appropriate.
4. Ensure the existing tests still pass.
5. Commit with a clear message. We don't require a specific commit format, but "why" is more useful than "what."
6. Push to your fork and open a pull request against `main`.
7. Sign the CLA if prompted.

## What we look for in contributions

- **Small, focused PRs.** Easier to review, faster to merge.
- **Tests.** New behavior needs tests. Bug fixes should include a regression test.
- **Discuss before large changes.** For anything substantial, please open an issue first so we can align on design.

## Reporting security issues

Please do **not** file security issues as public GitHub issues. Email **security@minimal.dev** instead. We'll respond within 5 business days.

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you agree to uphold it.

## Questions?

Open a discussion, file an issue, or email **security@minimal.dev**.
