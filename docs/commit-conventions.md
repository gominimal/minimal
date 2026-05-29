# Commit Conventions

This repository uses [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Every commit message MUST follow this format.

## Format

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

- `<description>` is a short summary in the imperative mood, lower-case, no trailing period.
- Separate body and footers from the subject with one blank line.
- Wrap the body at 72 columns.

## Types

| Type       | Use for                                                        | SemVer  |
|------------|----------------------------------------------------------------|---------|
| `feat`     | A new feature                                                  | minor   |
| `fix`      | A bug fix                                                       | patch   |
| `docs`     | Documentation only                                             | —       |
| `style`    | Formatting, no code-meaning change                             | —       |
| `refactor` | Code change that neither fixes a bug nor adds a feature        | —       |
| `perf`     | Performance improvement                                        | patch   |
| `test`     | Adding or correcting tests                                     | —       |
| `build`    | Build system or dependency changes (`Cargo.toml`, lockfile)    | —       |
| `ci`       | CI configuration (`.github/workflows`, actions)                | —       |
| `chore`    | Maintenance that fits no other type                            | —       |
| `revert`   | Reverts a previous commit                                      | —       |

## Scope

The scope is the affected crate or subsystem, in parentheses. Use crate names.

```
feat(sessions): add CWD-relative path types
fix(lcache): handle concurrent rename on the same key
```

Multiple crates: `feat(sessions,minimald): ...`.

## Breaking changes

A `!` before the colon flags a breaking change (major bump). State the break in a `BREAKING CHANGE:` footer.

```
feat(graph)!: replace planner ordering API

BREAKING CHANGE: Planner::order now returns Result instead of panicking.
```

## Footers

- `BREAKING CHANGE: <description>` — required for any breaking change.
- `Refs: #123`, `Closes: #123` — link issues.
- `Co-Authored-By: Name <email>` — additional authors.

## Examples

```
feat(orchestrator): kick off dependent builds as deps resolve
fix(mfile): avoid panic when state dir is missing
docs: document commit conventions
refactor(minimald): move ssh RPC handler out of russh::Handler impl
build(deps): bump the cargo group across 1 directory with 4 updates
test(decode): cover recursive upstream layer chains
```

## Agent rules

- One logical change per commit. Do not bundle unrelated edits.
- Pick the type from the dominant change; a feature commit that adds tests is `feat`, not `test`.
- Never commit or push unless the user asks.
