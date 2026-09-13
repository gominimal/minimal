# Specs

## What a spec is for

A spec is the durable statement of how something is **supposed to behave** — the
thing you read when the code tells you what it does but not what it was meant to
do. It is written before the work, and it stays true after it.

That definition does not hold today. Asked where they last looked to find out how
Minimal was supposed to behave, three people asked a colleague, two read the code,
and one inferred it by pointing an agent at the repo. One said the spec. Specs
earning that lookup is the outcome this format is aimed at.

## When you need one

**Specs are for epics. An epic is defined by its complexity** — if the work is
big or interlocking enough to be an epic, it is big enough to be worth stating
before you build it.

**Everything below that takes the fast path: no spec.** Bug fixes, paper cuts,
iterative UI work, a page here and a design tweak there — open an issue and go.
Requiring a spec for everything is the fastest way to get the process abandoned,
and two people named exactly that as their refusal condition.

## The format

One file, [`TEMPLATE.md`](TEMPLATE.md). Copy it, delete the guidance comments,
fill it in.

Two rules run through it:

- **Be succinct, and work hard not to dictate implementation.** State what must
  be true, not how to build it. This is the most common complaint on this team
  about the specs we have already written.
- **Every requirement must be verifiable.** If a line cannot be checked against a
  running system, it is background, not a requirement.

Behaviour is written in Given/When/Then, because it reads to non-engineers and
maps one-to-one onto the test suite. A prose-paragraph requirement was proposed
and rejected on the second rule: a paragraph is not testable. Each behaviour
carries a failure line and names the test that proves it. There are no
requirement IDs — the proof name is the anchor — and there is no line limit.

## Lifecycle

    draft -> PR -> review -> merge

**A merged PR is binding.** There is no separate vote, no change cut-off, and no
frozen state. If a spec needs to change, open a PR against it.

## Review

**The author presents the spec to the team.** Six of seven respondents wanted a
presentation in some form, and it is the step that makes "binding" mean
something. Async review on the PR runs alongside it — read it before the meeting,
leave comments on the PR, use the meeting for what comments cannot resolve.

For a small spec where everyone agrees the meeting adds nothing, skip it and
review async. That is the exception, not the default.

## Ownership

**The code owner owns the spec** and keeps it aligned with the code. Ownership
does not lapse when the feature ships.

In practice the person who keeps it true is **whoever last changed the
behaviour** — if you change how it works, you update the spec in the same
breath.

## When the implementation diverges

**Update the spec in the same PR that diverges from it.** Not a follow-up issue,
not a later cleanup pass — the change and the statement of intent land together.

## Specs for code that already exists

Do not backfill wholesale. Write one **only for an area you are about to
change**, where the spec is about to do work.

## The lint

`scripts/lint-specs.py` runs on PRs that touch this directory and posts what it
finds as a comment. **It never blocks a merge and is not a required check.** It
points at missing sections, behaviours with no failure line or no proof, proofs
naming a test that does not exist, unmeasured adjectives, unresolved CRITICAL
open questions, missing ownership, and content that belongs somewhere else.

Run it yourself:

```sh
python3 scripts/lint-specs.py docs/specs/NN-spec-name/NN-spec-name.md
```

## What lives elsewhere

| | |
|---|---|
| Work decomposition | GitHub issues. |
| Repository and coding standards | `CONTRIBUTING.md`, `AGENTS.md`. |
| System architecture | [`gominimal/arch`](https://github.com/gominimal/arch), referenced from the spec. |
| The proofs themselves | The test suite. The spec names them. |

## Where this came from

The format is the result of a team questionnaire run in August 2026 — seven of
eight engineers responded — not one person's preference.

The post-launch retro had proposed a vote gate before tasking, a change cut-off
after which specs freeze, and a CI-enforced document length cap. All three were
put to the team and rejected: **no respondent wanted the vote gate or the
cut-off, and six of seven rejected the length cap.** That is why none of them
appear above.
