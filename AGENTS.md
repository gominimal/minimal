# Agent Contract: minimal

<!-- Provenance: sourced from norrietaylor/minimal-vm-mac (PoC fork, MIT). Repo-specific bits stripped and parameterized for installation by scripts/quick-setup.sh. -->

## Overview

This document defines the agentic workflow contract for **minimal**. It lists which agents are active, what they are permitted to do, and which issues they own.

Primary language: **rust**

## Active Agents

| Agent | Trigger | Permitted actions |
|---|---|---|
| `agent:doc-drift` | Weekly schedule | Read source files; create or update one issue |
| `agent:coverage` | Weekly schedule | Read test files; create or update one issue |
| `agent:dep-drift` | Weekly schedule | Read `Cargo.lock` / `package.json`; create or update one issue |
| `agent:auto-merge` | PR labeled `agent:auto-merge` | Approve and merge PRs that pass all CI checks |

## Constraints (All Agents)

- Agents do NOT gate merges. Branch protection depends only on Minimal CI.
- Each agent may open at most one issue per run. Older open issues from the same agent are closed before a new one is filed.
- Agents write no code directly to `main`. They file issues or pull requests and stop.
- Issue bodies are capped at 10 `@mentions` and 50 links maximum.
- Only the HTML tags listed in `gh-aw-fragments/safe-output-create-issue.md` are permitted in issue bodies.

## Label Taxonomy

Agent-owned labels are prefixed `agent:`. The full set is defined in `.github/labels.yml`.

| Label | Meaning |
|---|---|
| `agent:doc-drift` | Opened or updated by the doc-drift agent |
| `agent:coverage` | Opened or updated by the coverage agent |
| `agent:dep-drift` | Opened or updated by the dep-drift agent |
| `agent:auto-merge` | Marks a PR eligible for agent-assisted auto-merge |

## Fragment Imports

Agent prompts in `.github/agents/` import shared fragments from `gominimal/min-aw/gh-aw-fragments/` via `gh aw compile`. Edit fragments in the source-of-truth repo; do not copy them here.

## Updating This Document

This file is managed by `scripts/quick-setup.sh` from `gominimal/min-aw`. To change the contract, open a PR against the source repo; changes propagate to all instrumented repos via the weekly sync workflow.
