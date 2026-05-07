# Agent Contract: minimal

## Overview

This document defines the agentic workflow contract for **minimal**. It lists which chore workflows are active, what they are permitted to do, what labels they emit, and the constraints all of them honor.

Primary language: **Rust**. Source-of-truth: [`gominimal/min-aw`](https://github.com/gominimal/min-aw).

## Active chore workflows

The bootstrap install adds three workflow files to `.github/workflows/` directly:

- **`sync-from-source-of-truth.yml`** — pulls compiled chore `.lock.yml` files from `gominimal/min-aw` on a weekly schedule. First scheduled run lands the rest of the chore set.
- **`worker-fix.yml`** — caller wrapper for the chore-issue worker (mints an App token, fetches the worker prompt at the pinned `WORKER_SOURCE_REF`).
- **`worker-iterate.yml`** — caller wrapper for the worker-iterate chore (mints an App token, fetches the worker-iterate prompt at the pinned `WORKER_ITERATE_SOURCE_REF`). Triggers on `pull_request_review` events for bot-authored `[worker:` PRs.

After the sync workflow's first run, the language-applicable chores below land as `.lock.yml` files alongside the wrappers. The chore matrix is governed by the per-language policy in [ADR 0003](https://github.com/gominimal/min-aw/blob/main/docs/decisions/0003-language-portability.md):

| Workflow | Output | Trigger | Applies to LANGUAGE |
|---|---|---|---|
| `docs-patrol` | One issue per drift, label `agent:doc-drift` | Fuzzy weekly Monday + `push` to main on doc paths | all |
| `worker-fix` | Draft PR fixing one open `agent:*` issue | Fuzzy daily + `workflow_dispatch` | all |
| `worker-iterate` | Pushes commits to existing worker-fix PR branches addressing CodeRabbit review feedback; replies inline per the saved-memory rule | `pull_request_review: types: [submitted]` on bot-authored `[worker:` PRs | all |
| `dependency-review` | One issue per advisory or semver concern, label `agent:dep-drift` | `pull_request` on lockfile + fuzzy twice-weekly | rust (today); go / node next |
| `api-surface-drift` | One issue per surface change, label `agent:api-drift` | Fuzzy weekly Tuesday + `pull_request` on source | rust (today); go / node next |
| `test-coverage-detector` | Up to 3 issues for untested high-complexity paths, label `agent:coverage` | Fuzzy weekly Tuesday + `pull_request: closed` | rust (today); go / node next |
| `trivial-dep-bump` | One auto-merge-labeled PR with patch-level lockfile bumps | Fuzzy daily | rust (today); go / node next |

The Cargo-coupled chores at the bottom of the table install on Rust targets only today. Per [ADR 0003](https://github.com/gominimal/min-aw/blob/main/docs/decisions/0003-language-portability.md), a planned per-language refactor generalizes them to Go, Node/TS, and Nickel. Until that refactor lands, non-Rust targets receive only `docs-patrol` + `worker-fix`.

A separate `not-gating-audit` chore runs only on `gominimal/min-aw` (not synced to target repos) and watches branch-protection drift across the install set. If any `gh-aw`-emitted check appears in this repo's `required_status_checks` after install, that chore files an issue against `gominimal/min-aw` (not against this repo) so the operator can remediate without local action here.

## Constraints (every chore)

- **Not-gating.** No chore output appears in `required_status_checks`. Branch protection depends only on the existing CI. Per [ADR 0001](https://github.com/gominimal/min-aw/blob/main/decisions/0001-not-gating.md). The `not-gating-audit` chore on `gominimal/min-aw` actively defends this and files an issue if drift is detected on any target.
- **Caps.** Audit chores cap at 1 issue per run (3 for `test-coverage-detector`); fix chores cap at 1 PR per run. Older open issues with the same `agent:*` label are closed in-place when a new one is filed (`close-older-issues: true`).
- **No direct `main` push.** All chore output flows through gh-aw safe outputs (issues, draft PRs). No chore runs `git push` or `gh pr merge` directly.
- **Issue caps.** Each issue body is capped at 10 `@mentions` and 50 links; only the HTML tags listed in [`gh-aw-fragments/safe-output-create-issue.md`](https://github.com/gominimal/min-aw/blob/main/gh-aw-fragments/safe-output-create-issue.md) are permitted.

## Label taxonomy

Defined in [`.github/labels.yml`](.github/labels.yml). Two prefixes; meanings differ:

**`agent:*` — chore-output labels (issues opened by audit chores).** A chore opens an issue and applies its label. The label identifies which chore filed the issue and what kind of follow-up the worker is allowed to draft (per its switch table).

| Label | Filed by | What it means |
|---|---|---|
| `agent:doc-drift` | `docs-patrol` | Documentation has drifted from the implementation |
| `agent:coverage` | `test-coverage-detector` | A high-complexity function lacks test coverage |
| `agent:dep-drift` | `dependency-review` | A dependency advisory or semver concern needs review |
| `agent:api-drift` | `api-surface-drift` | An external API surface this repo depends on has changed |
| `agent:not-gating-audit` | `not-gating-audit` | Branch-protection drift on a target repo (filed against `gominimal/min-aw`) |

**`agent:auto-merge` is *not* an issue label.** It's a **PR-output label** the worker (and `trivial-dep-bump`) apply to draft PRs that satisfy the trivial-scope criteria (patch-level lockfile only, etc.). Branch-protection rules consume the label to enable auto-merge once CI is green. The label is in `.github/labels.yml` for completeness but is *applied to PRs, not issues*; nothing about its presence implies an "agent" actively approves and merges. The merge happens through GitHub's standard auto-merge flow once required checks pass.

| Label | Applied to | What it means |
|---|---|---|
| `agent:auto-merge` | Draft PRs | This PR is eligible for GitHub auto-merge once CI is green. Applied by `worker-fix` on `agent:dep-drift` fixes that pass the trivial-scope check, and by `trivial-dep-bump` on its scheduled patch-bump PRs. |
| `worker-tuning` | Issues opened against `gominimal/min-aw` | The worker failed to produce a PR within 72h on an `agent:*` issue; meta-feedback for tuning the worker prompt. Not an `agent:*` label because it's a worker self-feedback signal, not a chore output. |

## Fragment imports

Chore prompts in `.github/workflows/<chore>.lock.yml` import shared fragments from `gominimal/min-aw/gh-aw-fragments/` at compile time. Edit fragments in the source-of-truth repo; the next sync run lands the new compiled lock file.

## Updating this document

This file is managed by `scripts/quick-setup.sh` from `gominimal/min-aw`. To change the contract, open a PR against the source-of-truth repo; changes propagate to instrumented repos via the weekly sync workflow.
