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
