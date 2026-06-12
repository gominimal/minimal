---
name: Bug
about: Report defective behavior for the SDD pipeline to spec a fix and build it.
title: "bug: "
labels:
  - kind:bug
  - sdd:spec
---

## Summary

One or two sentences describing the defect.

## Expected behavior

What should happen.

## Actual behavior

What happens instead. Include error output or a `file:line` reference where
you can.

## Reproduction

The smallest set of steps that reliably reproduces the defect.

## Scope notes

Anything in or out of scope, constraints, or related work the agents should
know. Leave blank if there is nothing to add.

## One-session fix? (optional)

If this looks like a one-file bugfix, a typo, or similarly small,
comment `/fastpath` on this issue after opening it. The agent will
compress spec, architecture, and plan into one short run and gate
execution on a single `/approve`. The full pipeline runs by default;
`/fastpath` is opt-in. The agent will also propose fast-path on its
own when the issue body looks like a single-session change.

---

<!-- SDD command vocabulary. Do not edit this footer. -->

This issue is the tracking issue for the fix. It carries the `sdd:spec`
lifecycle label, so `sdd-spec` will draft a spec PR from it automatically.

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
