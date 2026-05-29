# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

When iterating on code changes, frequently run `cargo test -p <crate name>` to spot compilation errors, issues,
and test failures.

When you are done making code changes, or you want to check your code for compatibility across other crates,
finish off by running `cargo fmt && cargo test -- --include-ignored` to catch any test failures, as well as
`cargo clippy --allow-dirty --fix --all-targets -- -D warnings` to catch any code smells.

## Commit Messages

This repository follows Conventional Commits. Every commit message must conform.

@docs/commit-conventions.md

## Architecture

@docs/architecture.md

## Rust Coding Standards

@docs/rust-coding-standards.md
