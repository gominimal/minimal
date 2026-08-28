---
id: XXX
title: <feature name>
status: draft
owner: <github-handle>
epic: <org/repo#N>
arch: <gominimal/arch link, or: none>
updated: <YYYY-MM-DD>
---

# XXX — <feature name>

<!--
SOURCE  gominimal/foundry spec/template.md @ d7227512d2577e2396f5a097c2fe50d5ffe08f14
  This file is a copy. Edit it in foundry and open a PR here; a change made
  only in this repo is lost the next time the template is updated. The SOURCE
  line is what a drift check reads to tell whether this copy is behind.
  Delete this whole comment block when you start a spec from it.

WHAT A SPEC IS FOR
  A spec settles what a change must do, and why, before the argument happens in
  a diff. It is the durable record of the rationale and the agreed behaviour.

WHAT IT IS NOT
  Not the work breakdown (GitHub issues). Not the coding standards (AGENTS.md).
  Not the architecture of record (gominimal/arch). There is no architecture
  section in a spec, and specs do not nest. The spec links; it never restates.

WHEN TO WRITE ONE
  Every epic gets one. Anything carrying kind:epic, no exceptions. The filter is
  upstream: work that does not warrant a spec should not have been an epic.
  Everything below that takes the fast path with no spec.
  Net new work only. A spec for code that already exists is discretionary,
  written when a behaviour change warrants one.
  A merged PR makes the spec binding. No vote, no change cut-off. When the
  implementation diverges, fix the spec in the same PR that diverged.

WHERE IT LIVES
  In the repo where the code is going to be written, at
  docs/specs/NN-spec-<slug>/NN-spec-<slug>.md.

OWNERSHIP
  Whoever touches the code owns the spec. Own the epic, own the spec; change the
  behaviour later and you own updating the spec that describes it. `owner` names
  who that is today. Specs are living documents.

SIZE
  No line cap on this document. Succinctness is the goal, and complexity rather
  than length decides when work should split. The caps that exist sit on the
  epic and the legendary, not here. If a section has nothing true to say, delete
  it: an empty section is worse than a missing one.

WRITING
  A requirement does not dictate implementation. Name the observable behaviour,
  not the mechanism that produces it.
  Every behaviour must be verifiable. If a behaviour cannot be checked against a
  running system it is background, not a requirement — so an adjective with no
  bound is not a requirement either: "fast" becomes "p95 under 200 ms".
  The lint comments on the PR. It never blocks a merge.
-->

## Context

<!-- ~10 lines. The problem, why now, what is true after this ships, and the
     success criteria. Close with the first slice: the smallest increment that
     runs end to end, so a reader has an intermediate step, not just an endpoint.
     No solution content, no file names, no API shapes. -->

<problem, why now, what is true after this ships>

**Success:** <the observable condition that means this worked>

**First slice:** <the smallest thing that runs end to end>

## Users and stories

<!-- Name the roles being targeted. Transcribe the stories from the epic rather
     than linking to it: the epic copy is transient, because issues get edited
     and deleted, and once a story is bound into a merged spec, changing it
     takes a review. -->

**Roles:** <who this is for, specifically>

- AS A <role> I WANT <capability> SO THAT <outcome>

## Requirements

<!--
ONE BULLET PER REQUIREMENT. ID is XXX-NNN, stable, never reused. The ID is the
join key that verify: and the property link point at. If nothing consumes it,
delete it.

WRITE REQUIREMENTS AS EARS.

  Ubiquitous     THE SYSTEM SHALL <observable>
  Event-driven   WHEN <trigger> THE SYSTEM SHALL <observable>
  State-driven   WHILE <state> THE SYSTEM SHALL <observable>
  Optional       WHERE <feature is present> THE SYSTEM SHALL <observable>
  Unwanted       IF <condition> THEN THE SYSTEM SHALL <observable>

EARS states a property over the whole input space. That is what a property test,
a Kani harness or a Lean proof consumes, and it is what the Security
considerations section is made of.

PROSE IS THE AUTHORING INPUT, NEVER THE REQUIREMENT. Draft the behaviour in
English, convert it to EARS, and review the translation.

VERIFICATION TIERS — T0 is the default and nothing above it is mandated.
Escalating a requirement is a per-item call made during review.
  T0  verify:   <command>            an example test. The default.
  T1  property: <universal>          a proptest over generated input.
  T2  property: + a Kani harness     exhaustive to a bound.
  T3  proof:    <file>#<theorem>     machine-checked in Lean 4.
  A requirement that cannot be verified yet says
  verify: none, <reason and issue link>.

FAILURE AND EDGE BEHAVIOUR is an indented sub-bullet under the requirement it
qualifies. Encouraged, not required.
-->

- **XXX-001** WHEN <trigger> THE SYSTEM SHALL <observable behaviour>.
  verify: just test-one <test_name>
  - IF <the failure condition> THEN THE SYSTEM SHALL <defined behaviour>.
    verify: just test-one <test_name_failure>

- **XXX-002** THE SYSTEM SHALL <observable behaviour that holds universally>.
  verify:   just test-one <test_name>
  property: <the universal, in whatever notation reads clearly>

- **XXX-003** THE SYSTEM SHALL <a security-critical universal>.
  verify:   just test-one <test_name>
  property: <the universal>
  proof:    proofs/<Area>/<File>.lean#<theorem_name>

- **XXX-004** WHERE <an optional feature is enabled> THE SYSTEM SHALL
  <observable behaviour>.
  verify: none, <why not yet, and the issue link>

## Non-goals

<!-- What this deliberately does not cover, and where each one lives instead.
     A non-goal with no destination is an omission, not a decision. -->

- <thing>: <where it lives instead>

## Non-functional requirements

<!-- Optional. Delete this section if nothing here belongs to this epic.
     Performance, scalability, concurrency limits, resource ceilings. An NFR is
     usually a property of the system rather than of one epic, so state it here
     only when it is genuinely scoped to this work, and link it out when it is
     not. Same rules as above: EARS, measurable, no unmeasured adjective. -->

- **XXX-N01** WHILE <load condition> THE SYSTEM SHALL <measurable bound>.
  verify: <the benchmark or load test that measures it>

## Design reasoning

<!-- Why this shape and not the alternatives a reviewer would reach for. This is
     the section that survives the feature: it is the original rationale, and it
     is what makes the spec worth reading a year later.
     Include the generality check: would this hold for a second implementation,
     a second provider, a second platform? If not, say so and say why that is
     acceptable.
     A cross-cutting decision belongs in gominimal/arch. Link it; do not restate
     it here, or the two will drift. -->

<why this shape>

**Generality:** <would a second implementation fit this? what breaks if not?>

## Security considerations

<!-- The invariants this feature must hold, and what enforces each one. State
     them as universals, so T1-T3 can consume them directly. A prose paragraph
     asserting that something is safe is the least checkable text in the
     document; an invariant with a property test is not. -->

- **Invariant:** THE SYSTEM SHALL <universal that must never be violated>.
  enforced by: <the mechanism>
  covered by: <XXX-NNN>

## Rollout

<!-- Infrastructure specs only. Delete this section otherwise. -->

- **Deploy:** <steps>
- **Rollback:** <how, and how long it takes>
- **Blast radius:** <who is affected if this is wrong>

## Open questions

<!-- Required. Write "None." rather than deleting the section: an empty Open
     questions section is a claim, and a useful one.
     [NEEDS CLARIFICATION (CRITICAL|HIGH|MEDIUM|LOW): <question>]
     The marker is for readers and reviewers. Nothing here blocks a merge; the
     lint comments and the review decides. -->

- [NEEDS CLARIFICATION (HIGH): <question>]
