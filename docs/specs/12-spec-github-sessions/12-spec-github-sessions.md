---
id: GHS
title: GitHub sign-in and credential-free repository access from sessions
status: draft
owner: norrietaylor
epic: gominimal/inbox#512
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-03
---

# GHS — GitHub sign-in and credential-free repository access from sessions

## Context

A developer cannot do real work in a Minimal session today. There is no way to
authenticate to git from inside one short of pasting a token in, no single
sign-in path, no per-session credential, and no defined behaviour for what a
session spawned by another session may inherit. With the open-source launch
this is the gap between "installed it" and "used it for real work this week",
and the sign-in itself is the event that proves adoption.

After this ships a developer signs in once with their GitHub.com account in a
browser, starts a session, and clones, commits and pushes their project from
inside it as themselves, whether they or an agent typed the command. No token
is entered, copied, or left on the session. A session spawned by a workflow
inherits no more access than its parent, and nobody is prompted for it.

This document covers the CLI, the session daemon and the credential path
inside a session. Signing the developer in, minting and renewing tokens, and
enforcing attenuation at issuance are the identity plane's, in
[the GitHub identity spec](https://github.com/gominimal/gatehouse/blob/main/docs/specs/01-spec-github-identity/01-spec-github-identity.md).
The browser page that approves a sign-in is in
[the CLI sign-in page spec](https://github.com/gominimal/webapp/blob/main/docs/specs/03-spec-cli-signin-page/03-spec-cli-signin-page.md).

**Success:** A developer with no prior Minimal account signs in with GitHub,
starts a remote session, and a push to their project from inside it lands on
GitHub attributed to them, with no token typed, copied, or present on the
session's filesystem or environment.

**First slice:** The sign-in command, the browser approval, one remote session,
and a push to the workbench project from inside it with unmodified git.

## Users and stories

**Roles:** developer who uses the open-source version of Minimal, developer using remote sessions, developer who deploys agentic workflow that spawns new sessions

- AS A developer who uses the open-source version of Minimal, I WANT to sign into Minimal with the `min` CLI and authenticate using my Github.com account in the browser, SO THAT I don't need to manage another credential.
  <!-- Acceptance criteria, for the EARS step:
       - Session tokens are automatically refreshed via background refresh token rotation without requiring a secondary browser redirect or terminal prompt. Users do not need to repeatedly authenticate and authorize access.
       - The minted session token only grants git read/write permission to the project in the workbench. Attempts to clone, push to other repositories inside the workbench, or change repository or organizational settings will return a 403 error.
       - The only way to log in to Minimal is with a Github.com account.
  -->
- AS A developer using remote sessions, I WANT to clone, commit and push changes to my project without being asked to provide login information, SO THAT I don't need to worry about my credentials being leaked.
  <!-- Acceptance criteria, for the EARS step:
       - Commits and PRs created from inside a session are attributed to the developer, regardless of if an AI agent was used to create the change.
       - No personal access tokens or static private SSH keys are stored on the box.
  -->
- AS A developer who deploys agentic workflow that spawns new sessions, I WANT the child sessions to complete successfully using access scope that's no wider than its parent, SO THAT my workflow can achieve its objective autonomously.
  <!-- Acceptance criteria, for the EARS step:
       - Child sessions inherit access scope strictly equal to or narrower than that of the parent session, without the need to prompt the attached human developer.
  -->


## Requirements

- **GHS-001** WHILE a session is running THE SYSTEM SHALL keep GitHub
  operations inside it working across a token renewal.
  tier:     T0
  verify:   cargo nextest run -p minimal git_op_succeeds_across_token_renewal

- **GHS-002** WHILE a session is running THE SYSTEM SHALL renew the token a
  GitHub operation uses without prompting the developer or the agent.
  tier:     T0
  verify:   cargo nextest run -p minimal token_renewal_never_prompts

- **GHS-003** WHERE a session declares no additional repositories THE SYSTEM
  SHALL bound its GitHub access to the project in its workbench.
  tier:     T2
  verify:   cargo nextest run -p sessions reach_default_is_workbench_only
  property: for every session whose declared set is empty, the set of repositories a git operation may target is exactly the workbench project
  harness:  kani_reach_is_workbench_plus_declared, exhaustive to 8 declared repositories modelled as bounded identifiers (unwind bound 9); requires the reach decision to be a pure function over owned repository identifiers, separate from the transport that carries the git operation

- **GHS-004** WHERE a session declares additional repositories before it starts
  THE SYSTEM SHALL bound its GitHub access to the workbench project and the
  declared repositories, and nothing else.
  tier:     T2
  verify:   cargo nextest run -p sessions reach_is_workbench_plus_declared
  property: for every declared set D, the set of repositories a git operation may target is exactly the workbench project together with D
  harness:  kani_reach_is_workbench_plus_declared, exhaustive to 8 declared repositories modelled as bounded identifiers (unwind bound 9); the same pure reach decision as GHS-003

- **GHS-005** IF a git operation inside a session targets a repository outside
  the session's declared set THEN THE SYSTEM SHALL supply no credential for it.
  tier:     T2
  verify:   cargo nextest run -p minimal git_op_outside_declared_set_gets_no_credential
  property: for every declared set and every target repository outside it, the reach decision is a refusal, and no credential is supplied for the operation
  harness:  kani_outside_reach_is_refused, exhaustive to 8 declared repositories (unwind bound 9); requires the reach decision to be a pure function over owned repository identifiers, consulted by the credential path before any credential is supplied

- **GHS-006** WHEN a developer runs the sign-in command THE SYSTEM SHALL show
  the address of a browser page and a short code with which the developer
  authenticates using their GitHub.com account.
  tier:     T0
  verify:   cargo nextest run -p minimal signin_shows_page_address_and_code

- **GHS-007** THE SYSTEM SHALL offer no sign-in method other than GitHub.com.
  tier:     T0
  verify:   cargo nextest run -p minimal signin_offers_github_only

- **GHS-008** IF a developer starts or attaches to a remote session without a
  valid sign-in THEN THE SYSTEM SHALL require them to sign in before the
  session starts or attaches.
  tier:     T0
  verify:   cargo nextest run -p minimal remote_session_requires_signin

- **GHS-009** WHEN a developer starts a local session THE SYSTEM SHALL start it
  without requiring sign-in.
  tier:     T0
  verify:   cargo nextest run -p minimal local_session_starts_without_signin

- **GHS-010** IF a process inside a local session attempts a GitHub operation
  while the developer has no valid sign-in THEN THE SYSTEM SHALL prompt the
  developer to sign in from inside the session before completing the
  operation.
  tier:     T0
  verify:   cargo nextest run -p minimal local_github_op_prompts_for_signin

- **GHS-011** WHILE a developer is signed in THE SYSTEM SHALL let standard git
  and gh commands inside a session clone, push and open pull requests without
  prompting for login information.
  tier:     T0
  verify:   cargo nextest run -p minimal raw_git_and_gh_work_without_login_prompt

- **GHS-012** THE SYSTEM SHALL attribute every commit pushed and every pull
  request opened from inside a session, or from inside any box a developer's
  workflow spawns, to the developer who signed in.
  tier:     T0
  verify:   cargo nextest run -p minimal session_commits_and_prs_attributed_to_developer

- **GHS-013** THE SYSTEM SHALL write no personal access token and no static
  private SSH key to a session's filesystem or environment.
  tier:     T0
  verify:   cargo nextest run -p minimal session_fs_and_env_hold_no_pat_or_static_key

- **GHS-014** WHEN a git operation inside a session needs a credential THE
  SYSTEM SHALL obtain one that expires within 8 hours, at the time of the
  operation.
  tier:     T0
  verify:   cargo nextest run -p minimal git_credential_is_fetched_per_op_and_expires_within_8h

- **GHS-015** WHEN a session spawns a child session THE SYSTEM SHALL grant the
  child a GitHub access scope that is a subset of the parent's.
  tier:     T2
  verify:   cargo nextest run -p sessions child_reach_is_subset_of_parent
  property: for every parent reach set P and every child declaration, the child's reach set is a subset of P
  harness:  kani_child_reach_subset_of_parent, exhaustive to 8 repositories per set (unwind bound 9); requires the child-reach decision to be a pure function over the two owned sets, separate from session creation

- **GHS-016** WHEN a session spawns a child session THE SYSTEM SHALL complete
  the spawn without prompting the attached developer.
  tier:     T0
  verify:   cargo nextest run -p minimal child_session_spawn_needs_no_prompt

- **GHS-017** WHEN a parent session ends THE SYSTEM SHALL end its child
  sessions' GitHub access.
  tier:     T0
  verify:   cargo nextest run -p minimal parent_end_ends_child_github_access

## Non-goals

- Signing the developer in, minting and renewing tokens, and enforcing
  attenuation at issuance:
  [the GitHub identity spec](https://github.com/gominimal/gatehouse/blob/main/docs/specs/01-spec-github-identity/01-spec-github-identity.md).
- The browser page that approves a CLI sign-in:
  [the CLI sign-in page spec](https://github.com/gominimal/webapp/blob/main/docs/specs/03-spec-cli-signin-page/03-spec-cli-signin-page.md).
- Sign-in through any provider other than GitHub.com, including enterprise
  OIDC: Gatehouse §6.1.3 (F2), a later phase of the identity plane.
- A forced in-session facade for git: retired on 2026-08-20. Standard git and
  gh are the path (GHS-011).
- Branch-aware activation, repository pre-priming, and a pull-request prompt
  on session exit: the earlier GitHub-sessions PRD carries them as a
  reference; none is in this epic's criteria.
- The Actions workflow permission: excluded from the App's permissions
  (GHI-004 in the GitHub identity spec).
- Ending a session's own GitHub access when the session ends: bounded by token
  expiry (GHS-014) and by revocation (Gatehouse F13); whether a live grant
  must end with the session is an open question below. A parent's end ending
  its children's access is GHS-017.
- Refusing an out-of-set clone of a public repository: it needs no credential,
  so nothing but egress enforcement can refuse it; the networking spec.
- Sharing a session with another developer or an agent: the session-sharing
  spike in the inbox.
- A typed control plane for agents over sessions: the sessions MCP proposal in
  the inbox.
- Secrets beyond GitHub: out of scope for the initiative this epic belongs to.
- Counting the sign-in event for adoption telemetry: the telemetry epic under
  the same initiative.

## Design reasoning

**Three documents.** One spec per surface owner, decided 2026-09-03: this one
for the CLI, the daemon and the in-session credential path; the identity
plane's for sign-in, minting, renewal and attenuation; the website's for the
approval page. A single document here with the identity behaviours as open
questions was the cheaper alternative and would have left the identity half
unspecified; two documents without the page would only be right if GitHub's
own device page were the browser step, which was not chosen.

**Sign-in gates remote sessions and is optional for local ones** (decided
2026-09-03; mandatory sign-in for remote sessions was reconfirmed on
2026-08-20). A local session starts with no account, and a GitHub operation
inside one prompts for sign-in there (GHS-010). The alternatives were sign-in
for every session including local, which gives one path and counts every
user but removes the account-free local path today's users have, and remote
only with local left undecided. The cost accepted is two paths to test and
document. Prompting inside the session was chosen over refusing with
instructions because it keeps a developer in flow; the cost is that an agent
or script inside a local session blocks on a prompt it cannot answer, so such
workflows sign in before they start.

**Token reach is the workbench by default and wider when declared** (decided
2026-09-03). This reconciles the epic's criterion, which bounds a token to the
workbench project, with the 2026-08-20 ask that workbench-only be an option
rather than a rule. "Whatever the App installation grants" was set aside
because it does not meet the per-project bound at all. The bound is enforced
in two places: the identity plane mints the session's token narrowed to the
declared set where GitHub can express it (the GitHub identity spec), and the
credential path inside the session supplies no credential for a repository
outside the set (GHS-005). The 2026-08-20 record that a user-attributed token
cannot be narrowed per repository holds for renewal from a refresh token and
not for minting: GitHub narrows a user access token to named repositories and
permissions at mint, and the narrowed token stays attributed to the developer.
The reach decision being pure and separable from the credential path is what
the T2 harnesses require.

**The epic's 403 is not met literally, and that is recorded rather than
hidden.** With the token delivered into the session per operation (the custody
decision below), an out-of-set request that reaches GitHub gets GitHub's own
answer: a 404 for a private repository the narrowed token cannot see, and
success for a public repository, which needs no credential at all. Only a
Minimal-owned point between the session and GitHub could answer a 403, and the
architecture of record has none. GHS-005 binds what Minimal controls,
supplying no credential; whether the epic's criterion is amended or a refusal
point is added to the architecture is an open question below.

**A child session gets a subset of its parent's scope, never more** (GHS-015).
Whether a child may declare a narrower set, or a running session's set may
change without a fresh sign-in, was left on 2026-08-20 as something to test
against GitHub and stays open. The alternatives were letting a child declare
a narrower set, which needs the same non-token enforcement as GHS-004, and
giving every child exactly its parent's scope, which never exercises the
"narrower" the criterion allows.

**The browser step is the device flow with a code-entry page on the website**
(decided 2026-09-03). It works on a headless host and matches the identity
plane's reference profile (Gatehouse §6.1.2). An auth-code flow with a
loopback listener has no code to type but needs a browser on the same machine
as the CLI; GitHub's own device page needs no page of ours but leaves nowhere
to show what is being approved.

**A credential must never reach the session's filesystem or environment**
(GHS-013, decided 2026-09-03). The epic says "stored on the box". Reading that
as anywhere on the host machine would forbid the daemon beside the session
from holding short-lived material; reading it as the filesystem only would
allow a token materialised in the environment, which a captured environment
carries for its lifetime.

**The session's short-lived token is delivered into the session per
operation, as the architecture of record describes** (decided 2026-09-03,
with the daemon's placement in front of the decision: on macOS and on Linux
with hardware virtualisation the session daemon and the broker beside it run
inside a guest virtual machine, and on native Linux on the host). Three other
placements were offered and declined: never in the session, with the holder's
placement left open; never in the guest, held on the host, which is the
strongest against a sandbox escape or a guest snapshot but commits to a
component the architecture lacks; and beside the daemon, never in the
session, which needs no new component but forecloses the host-side design.
The cost accepted is the one the architecture states itself (Gatehouse §6.4):
a process in the session holds a bearer credential for up to 8 hours against
every repository the token reaches, so the bounds are the narrowed mint, the
8-hour expiry (GHS-014) and the audit of every mint, not custody.

**A session's credential expires within 8 hours**, GitHub's own user-token
expiry (decided 2026-09-03), rather than an open question or a shorter ceiling
set here at the cost of more renewals. It depends on the App's
token-expiration setting staying on (Gatehouse §6.4.1).

**Work is attributed to the developer, from a session and from any box a
workflow spawns** (GHS-012, decided 2026-09-03). This extends the 2026-08-20
decision to use GitHub App user access tokens rather than installation
tokens, taken so that actions are attributed to a real person rather than to
a bot, with the tradeoff accepted then that user tokens give no per-repository
narrowing out of the gate (Gatehouse §6.4 states the asymmetry). Covering
sessions only and leaving agent boxes open, or leaving agent boxes
bot-attributed, were the alternatives. The consequence is that the
architecture's per-type default, installation mode for every root other than
session, has to move; that is an open question below.

**Standard git and gh, no forced interface** (decided 2026-08-20). Once a
developer is signed in, the token a session uses works with unmodified git and
gh as the developer (GHS-011). The earlier PRD's design, in which a facade was
the only route to GitHub, is retired by this.

**Permissions are repository contents, pull requests and issues read and
write, and metadata read; Actions workflows are excluded** (decided
2026-09-03). Push and pull requests alone, the criteria read literally, would
deny an agent the issue triage it does from inside a session; adding workflows
was excluded by the earlier PRD and by the architecture's manifest ceiling and
has the widest blast radius for a compromised session. The chosen set widens
the architecture's v1 manifest, which §6.4.1 treats as a security-review
event; the GitHub identity spec carries that as an open question.

**Tiers.** The reach and child-subset decisions (GHS-003, GHS-004, GHS-005,
GHS-015) are at T2: each is a pure decision over bounded repository
identifiers, and the Kani lane that already proves the path-decision lattice
runs the harnesses today. What the tier buys is the split each harness line
names: the decision is a pure function over owned values, separate from the
credential path that acts on it, and it has to be written that way from the
start. T0 would leave the decision free to interleave with that path;
T1 would add a property-testing dependency this tree does not carry.
Everything else stays at T0 because it passes through GitHub, a PTY or a
socket, and there is no decision to extract. GHS-013 is a universal and stays
at T0 on purpose: sessions are not a domain a test can generate, so the
filesystem-and-environment scan the architecture asks for under INV-1 runs as
one named test, and the universal is stated in Security considerations. No
requirement is at T3: every behaviour reaches a socket or GitHub, and there is
no Lean project to hold a proof.

**Egress is only half covered.** The initiative's constraint that nothing
enters or leaves a box undeclared is met on the credential side (GHS-013,
GHS-014). The network side, egress declared before it happens and enforced at
the relay, is allow-all in running code today, and the design for enforcing
it belongs to the networking spec. Whether it is a prerequisite for this work
is open.

**Generality:** GitHub.com is the sole provider by decision (GHS-007), and
GHS-011, GHS-012 and GHS-014 assume GitHub App token semantics; a second
provider would enter through the identity plane (Gatehouse F2) and need its
own reach and attribution requirements. Across hosts the behaviours are
general as stated, with one dependency named: where the session daemon runs
decides where the session's token is held between operations, inside a guest
on macOS and Linux with hardware virtualisation and on the host on native
Linux; and a local session on a daemon not enrolled with the identity plane
has no broker to mint from (open question below). A local and a remote
session otherwise differ only in whether sign-in is required to start
(GHS-008, GHS-009).

## Security considerations

- **Invariant:** THE SYSTEM SHALL keep every long-lived credential, meaning a
  personal access token, a static private SSH key or a refresh token, off a
  session's filesystem and environment.
  enforced by: the credential path obtaining an expiring token at the time of
  each operation, and the scan of the session filesystem and process
  environments the architecture requires (Gatehouse INV-1, T3, T15).
  covered by: GHS-013, GHS-014
- **Invariant:** THE SYSTEM SHALL supply a session no credential for a
  repository outside its declared set.
  enforced by: the reach decision, a pure function over owned repository
  identifiers checked exhaustively to the stated bound and consulted before
  any credential is supplied, and the narrowed mint in the identity plane
  (architecture AT12).
  covered by: GHS-003, GHS-004, GHS-005
- **Invariant:** THE SYSTEM SHALL grant a child session a GitHub access scope
  that is a subset of its parent's.
  enforced by: the child-reach decision here and attenuation at issuance in
  the identity plane (Gatehouse INV-2, §6.5; architecture AT16).
  covered by: GHS-015
- **Invariant:** THE SYSTEM SHALL start or attach no remote session for a
  developer without a valid sign-in.
  enforced by: the sign-in gate in the CLI before any session request is sent.
  covered by: GHS-008

## Open questions

- [NEEDS CLARIFICATION (HIGH): Is declared-egress enforcement a prerequisite
  for credential-free GitHub access, or its own epic? Egress is allow-all in
  running code, the relay-layer enforcement design was closed without being
  planned, and the initiative's hard constraint says nothing leaves a box
  undeclared. It is also the only way to refuse an out-of-set clone of a
  public repository, which needs no credential.]
- [NEEDS CLARIFICATION (HIGH): The epic's criterion that an out-of-set
  operation returns a 403 cannot be met with the token delivered into the
  session: GitHub answers 404 for a private repository outside a narrowed
  token's reach and serves a public repository with no credential at all.
  Either the criterion is amended to what GHS-005 binds, or a Minimal-owned
  refusal point between the session and GitHub is added to the architecture
  of record, where a host-side credential facade has been proposed.]
- [NEEDS CLARIFICATION (HIGH): GHS-012 attributes work from every box a
  developer's workflow spawns to the developer, decided and reconfirmed on
  2026-09-03, while Gatehouse §6.4 defaults every root other than session to
  installation mode. The architecture's per-type default has to move; does
  the agent type give up per-mint narrowing when it does?]
- [NEEDS CLARIFICATION (HIGH): A session on a daemon not enrolled with the
  identity plane has no broker and no identity socket, so GHS-010 and GHS-011
  have no mechanism for a local session until client-mediated local
  enrollment (Gatehouse F16) exists. Is enrollment a prerequisite for local
  GitHub access, or does an un-enrolled daemon get a stated weaker path?]
- [NEEDS CLARIFICATION (MEDIUM): May a child session declare a repository set
  narrower than its parent's, and may a running session's set change without
  signing in again? Left on 2026-08-20 as something to test against GitHub. A
  narrowed token cannot be narrowed again, so widening means a fresh mint
  from the refresh token.]
- [NEEDS CLARIFICATION (MEDIUM): How are the requested repositories and
  permissions shown to the developer before a session starts, and does a
  second session reuse the existing sign-in or mint a separately scoped token
  by default? Both carried from the earlier PRD; neither is in this epic's
  criteria.]
- [NEEDS CLARIFICATION (MEDIUM): Must a session's live GitHub grant end when
  the session ends, by destroy or otherwise, rather than run out at expiry?
  The credential-leak motive behind the second story argues for it; the epic
  does not state it.]
- [NEEDS CLARIFICATION (LOW): The existing hidden sign-in command mints a
  client certificate for the HTTPS reverse proxy under the name the
  architecture's command tree gives to identity sign-in. What is the
  proxy-certificate command renamed to?]
- [NEEDS CLARIFICATION (LOW): Should tooling that adds a Co-authored-by
  trailer on an agent's behalf ask first? Recorded as a preference on
  2026-08-20 with no resolution.]
