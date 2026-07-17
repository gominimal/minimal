# CLAUDE.md

@AGENTS.md

## Claude-specific notes

- When iterating on code changes, frequently run `cargo test -p <crate name>`
  to spot compilation errors, issues, and test failures.
- When you are done making code changes, run the pre-PR verification commands
  for your platform — see the "Pre-PR verification" section of AGENTS.md
  (canonical block in CONTRIBUTING.md; on Linux prefer the auto-fixing
  clippy variant listed there).
