# Copilot Instructions: minimal

<!-- Provenance: sourced from norrietaylor/minimal-vm-mac (PoC fork, MIT). Repo-specific bits stripped and parameterized for installation by scripts/quick-setup.sh. -->

## Repository Context

This is **minimal**, a Rust project in the Minimal monorepo ecosystem. Agentic workflows for this repo are orchestrated via `gh-aw` and pull shared context from `gominimal/min-aw/gh-aw-fragments/`.

## Fragment Import Pattern

Agent prompts are composed from shared fragments using `gh aw compile`. Each fragment is stored in `gominimal/min-aw/gh-aw-fragments/`. When writing or reviewing agent prompts for this repo, import fragments by reference:

```yaml
# In a .github/agents/*.md agent definition:
# gh aw compile imports these fragments automatically:
#   - gh-aw-fragments/rigor.md
#   - gh-aw-fragments/formatting.md
#   - gh-aw-fragments/safe-output-create-issue.md
#   - gh-aw-fragments/repo-conventions.md
#   - gh-aw-fragments/minimal-tools.md
#   - gh-aw-fragments/runtime-setup.md
```

Do not copy fragment content into agent definitions. Edit fragments upstream.

## Code Conventions

- Primary language: **Rust**
- Follow conventions documented in any `CLAUDE.md` at the repo root or in relevant subdirectories. `CLAUDE.md` is the canonical doc surface for agent context.
- Prefer existing patterns over introducing new ones.
- Shell scripts use `set -euo pipefail` and `bash`.

## Agent Contract

Active agents, their permitted actions, and the label taxonomy are documented in `AGENTS.md` at the repo root. Agents do not gate merges; branch protection depends only on Minimal CI.

## Not a Merge Gate

`gh-aw` workflows are **not** required CI checks. No agent failure can block a PR merge. See `gominimal/min-aw/decisions/0001-not-gating.md` for the full ADR.
