# .github/agents/

<!-- Provenance: sourced from norrietaylor/minimal-vm-mac (PoC fork, MIT). -->

This directory holds agent definition files (`.md`) for `gh-aw` chores running in this repo.

## Adding an Agent

1. Create a new `.md` file in this directory (e.g., `doc-drift.md`).
2. Use `gh aw compile` to compose the prompt from fragments in `gominimal/min-aw/gh-aw-fragments/`.
3. Reference the agent from the corresponding workflow in `.github/workflows/`.

## Fragment Pattern

Agent definitions import shared fragments by reference. Do not copy fragment content here. Edit fragments upstream in `gominimal/min-aw/gh-aw-fragments/` and let `gh aw compile` resolve them at runtime.

## Active Agents

See `AGENTS.md` at the repo root for the full list of active agents, their triggers, and permitted actions.
