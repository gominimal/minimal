---
name: Specification (from Claude plan)
about: Hand a Claude plan document to the pipeline to translate into a spec and build.
title: "feature: "
labels:
  - sdd:spec
  - kind:feature
  - plan:provided
---

## Plan

Paste the full Claude plan document here. The plan is the authoritative
input: `sdd-spec` translates it into a structured spec and `sdd-triage`
translates its architecture/design section into the architecture record,
rather than authoring either from scratch. Keep the plan's own structure —
context, design, the implementation steps, and a verification section.

## Verification

If your plan already has a verification section, leave it above and remove
this one. Otherwise list, per step, how a person could observe the behavior
the step produces. `sdd-spec` lifts these into proof artifacts (one to three
per demoable unit), so prefer behavioral checks over health checks: a plan
verification that only says "tests pass" or "build succeeds" is dropped, and
if no step yields a behavioral artifact the agent hands off via `needs-human`.

## Scope notes

Anything in or out of scope, constraints, or related work the agents should
know. Leave blank if there is nothing to add.

---

<!-- SDD command vocabulary. Do not edit this footer. -->

This issue is the tracking issue for the feature. It carries the `sdd:spec`
lifecycle label, so `sdd-spec` will draft a spec PR from it automatically.
The `plan:provided` marker puts `sdd-spec` and `sdd-triage` into translation
mode: `sdd-spec` translates the plan above into a structured spec, and
`sdd-triage` translates the plan's architecture/design section into
`architecture.md`. The marker is cleared once the architecture PR opens (or,
on the fast path, once the stub spec PR opens).

Steer the pipeline with these comment commands. Each is gated to commenters
with write access to the repository.

| Command | Where | Effect |
|---|---|---|
| `/spec` | this tracking issue | re-run `sdd-spec` to draft the spec. To change an **open** spec PR, comment `/revise <note>` on that PR — `/spec` never opens a second spec |
| `/fastpath` | this tracking issue | confirm a single-session change; `sdd-spec` produces a stub spec PR and an execution plan comment in one run (ADR 0012) |
| `/triage` | this tracking issue, after the spec PR is merged | start `sdd-triage` phase A (architecture) |
| `/approve` | this tracking issue | full path: confirm the proposed plan so `sdd-triage` creates the Unit and task sub-issues. Fast path: dispatch the execution plan against `sdd-execute-{tier}` |
| `/dispatch` | this tracking issue (full path only) | arm the cascade across the task tree |
| `/revise <note>` | a spec, architecture, or implementation PR, or this tracking issue | re-run the owning agent with the note as an added instruction |
| `/execute` | a task sub-issue | run `sdd-execute` for that task ahead of the schedule |

Merging the spec PR advances to the architecture phase; merging the
architecture PR advances to a plan-comment phase, where `sdd-triage` posts
the proposed plan as one comment on this tracking issue. When an agent needs
a human decision it applies the `needs-human` label and posts one comment;
clear the label once you have answered and the agent resumes.
