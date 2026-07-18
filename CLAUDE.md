# CLAUDE.md

@AGENTS.md

## Claude-specific notes

- When iterating on code changes, frequently run `cargo test -p <crate name>`
  to spot compilation errors, issues, and test failures.
- When you are done making code changes, run the canonical pre-PR gate
  `just ci` (see the "Pre-PR verification" section of AGENTS.md; canonical
  block in CONTRIBUTING.md). During tight iteration loops you may also use
  the auto-fixing clippy variant
  (`cargo clippy --allow-dirty --fix --all-targets -- -D warnings`), but it
  complements `just ci` — it does not replace it.
