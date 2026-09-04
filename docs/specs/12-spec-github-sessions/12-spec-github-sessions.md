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

This document covers the CLI, the session daemon and the host-side credential
facade that fronts GitHub for every session. Signing the developer in, minting and renewing tokens, and
enforcing attenuation at issuance are the identity plane's, in
[the GitHub identity spec](https://github.com/gominimal/gatehouse/blob/main/docs/specs/01-spec-github-identity/01-spec-github-identity.md).
The browser page that approves a sign-in is in
[the CLI sign-in page spec](https://github.com/gominimal/webapp/blob/main/docs/specs/03-spec-cli-signin-page/03-spec-cli-signin-page.md).

**Success:** A developer with no prior Minimal account signs in with GitHub,
starts a remote session, and a push to their project from inside it lands on
GitHub attributed to them, with no credential typed, copied, or present in
the session or in the guest that hosts it.

**First slice:** The sign-in command, the browser approval, one remote session,
and a push to the workbench project from inside it with unmodified git through
the facade, with no credential in the session.

## Users and stories

**Roles:** developer who uses the open-source version of Minimal, developer using remote sessions, developer who deploys agentic workflow that spawns new sessions

- AS A developer who uses the open-source version of Minimal, I WANT to sign into Minimal with the `min` CLI and authenticate using my Github.com account in the browser, SO THAT I don't need to manage another credential.
- AS A developer using remote sessions, I WANT to clone, commit and push changes to my project without being asked to provide login information, SO THAT I don't need to worry about my credentials being leaked.
- AS A developer who deploys agentic workflow that spawns new sessions, I WANT the child sessions to complete successfully using access scope that's no wider than its parent, SO THAT my workflow can achieve its objective autonomously.


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

- **GHS-005** IF a git or GitHub request from a session targets a repository
  outside the session's repository set, meaning the workbench project and the
  repositories it declared, THEN THE SYSTEM SHALL refuse it with a 403 before
  the request reaches GitHub.
  tier:     T2
  verify:   cargo nextest run -p minimal request_outside_repository_set_is_403_before_github
  property: for every repository set, the workbench project plus the declared repositories, and every target repository outside it, the reach decision is a refusal, and the refusal reaches the caller as a 403 with nothing forwarded to GitHub
  harness:  kani_outside_reach_is_refused, exhaustive to 8 declared repositories (unwind bound 9); requires the reach decision to be a pure function over owned repository identifiers, evaluated by the facade before any request is forwarded
  - IF the repository a request targets cannot be resolved to one identifier
    THEN THE SYSTEM SHALL refuse the request with a 403 before it reaches
    GitHub.
    tier:   T0
    verify: cargo nextest run -p minimal unresolvable_target_is_refused_before_github

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

- **GHS-013** THE SYSTEM SHALL keep every GitHub credential, including any
  personal access token, any refresh token and any static private SSH key,
  out of a session's filesystem and environment.
  tier:     T0
  verify:   cargo nextest run -p minimal session_fs_and_env_hold_no_github_credential

- **GHS-014** WHEN a session is created for a signed-in developer THE SYSTEM
  SHALL hand it addresses for git over HTTPS and the GitHub programming
  interface that carry no credential.
  tier:     T0
  verify:   cargo nextest run -p minimal session_receives_credential_free_github_addresses

- **GHS-015** WHEN a session spawns a child session THE SYSTEM SHALL grant the
  child a repository set that is a subset of the parent's repository set.
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

- **GHS-018** THE SYSTEM SHALL hold a session's GitHub credential on the host,
  outside the guest virtual machine and outside every session.
  tier:     T0
  verify:   cargo nextest run -p minimal facade_holds_credential_outside_guest_and_session

- **GHS-019** WHEN a session ends, by destroy or otherwise, THE SYSTEM SHALL
  stop answering the session's GitHub addresses and discard every credential
  held for it.
  tier:     T0
  verify:   cargo nextest run -p minimal session_end_stops_addresses_and_discards_credentials
  - IF a session has ended THEN THE SYSTEM SHALL forward no further request on
    its behalf, admitted before the end or not.
    tier:   T0
    verify: cargo nextest run -p minimal session_end_wins_race_with_forwarding

- **GHS-020** WHILE a session is live THE SYSTEM SHALL hold its GitHub access
  credential for at most 8 hours before renewing or discarding it.
  tier:     T0
  verify:   cargo nextest run -p minimal facade_credential_held_at_most_8h

- **GHS-021** WHEN a GitHub request from a session is admitted or refused THE
  SYSTEM SHALL record the decision with the session and the developer
  identity, and never the credential or the request body.
  tier:     T0
  verify:   cargo nextest run -p minimal facade_decisions_are_audited_without_secrets

- **GHS-022** WHERE a session's declared egress excludes github.com THE SYSTEM
  SHALL complete git and gh operations from it through the facade.
  tier:     T0
  verify:   cargo nextest run -p minimal github_work_needs_no_github_egress

- **GHS-023** WHEN a request arrives at the facade THE SYSTEM SHALL attribute
  it to exactly one live session and that session's developer before deciding
  it.
  tier:     T0
  verify:   cargo nextest run -p minimal facade_request_bound_to_one_live_session
  - IF a request cannot be attributed to a live session, or presents another
    session's address, THEN THE SYSTEM SHALL refuse it with a 403.
    tier:   T0
    verify: cargo nextest run -p minimal cross_session_address_reuse_is_refused

- **GHS-024** THE SYSTEM SHALL hold in the facade only a session's access
  credential, and never the developer's refresh token.
  tier:     T0
  verify:   cargo nextest run -p minimal facade_holds_no_refresh_token

## Non-goals

- Signing the developer in, minting and renewing tokens, and enforcing
  attenuation at issuance:
  [the GitHub identity spec](https://github.com/gominimal/gatehouse/blob/main/docs/specs/01-spec-github-identity/01-spec-github-identity.md).
- The browser page that approves a CLI sign-in:
  [the CLI sign-in page spec](https://github.com/gominimal/webapp/blob/main/docs/specs/03-spec-cli-signin-page/03-spec-cli-signin-page.md).
- Sign-in through any provider other than GitHub.com, including enterprise
  OIDC: Gatehouse §6.1.3 (F2), a later phase of the identity plane.
- A forced in-session command for git: retired on 2026-08-20. Standard git and
  gh are the path (GHS-011); the facade is transparent to them.
- Branch-aware activation, repository pre-priming, and a pull-request prompt
  on session exit: the earlier GitHub-sessions PRD carries them as a
  reference; none is in this epic's criteria.
- The Actions workflow permission: excluded from the App's permissions
  (GHI-004 in the GitHub identity spec).
- Revoking an already-delivered credential at GitHub: TTL-bounded (Gatehouse
  §12.9); here a session's end discards what the facade holds (GHS-019).
- The same facade shape for upstreams other than GitHub, such as the Claude
  programming interface or model-context servers: a separate credential-broker
  epic in the inbox proposes it; nothing here binds it.
- The mechanics that route a session's git remotes and gh requests to the
  facade: the git rewrite is an implementation choice; gh is an open question
  below.
- Sharing a session with another developer or an agent: the session-sharing
  spike in the inbox.
- A typed control plane for agents over sessions: the sessions MCP proposal in
  the inbox.
- Secrets beyond GitHub: out of scope for the initiative this epic belongs to.
- Counting the sign-in event for adoption telemetry: the telemetry epic under
  the same initiative.

## Design reasoning

**Three documents.** One spec per surface owner, decided 2026-09-03: this one
for the CLI, the daemon and the host-side credential facade; the identity
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
by the facade on every request (GHS-005), which is what makes the epic's 403
Minimal's own behaviour rather than a status relayed from GitHub, which
answers 404 for a private repository outside a token's reach and serves a
public one with no credential at all. The identity plane additionally mints
the session's token narrowed to the declared set where GitHub can express it
(the GitHub identity spec); with the facade enforcing the set, that narrowing
is defence in depth rather than the bound. The 2026-08-20 record that a
user-attributed token cannot be narrowed per repository holds for renewal from
a refresh token and not for minting. "The session's repository set" means
the workbench project plus the declared repositories throughout this
document. Renewal (GHS-001) re-mints against that same set: the set is the
facade's grant, fixed when the session is created, not a property the token
has to carry across a refresh. Every session and every box a developer's
workflow spawns uses a developer-attributed token; a child's set is a subset
of its parent's (GHS-015) and its token is minted for that subset. The reach
decision being pure and separable from the proxy is what the T2 harnesses
require.

**What a request targets, and who it belongs to.** A request's target is the
repository GitHub would resolve it to: owner and name compared the way GitHub
compares them, with or without a trailing `.git`, in any of the address forms
git and gh emit. A target the facade cannot resolve is refused, not forwarded
(the failure edge of GHS-005); requests that name no repository at all, such
as an identity lookup, are an open question below. Every request is attributed
to exactly one live session before it is decided (GHS-023), so an address
handed to one session buys nothing in another; the mechanism that binds a
request to its session, a per-session address, a per-session placeholder the
facade recognises, or the source the switch attributes, is part of the
facade's design and belongs with the architecture question below. The point
of no return at session end is forwarding: a request already sent to GitHub
completes, and one admitted but not yet forwarded is refused (the failure edge
of GHS-019).

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

**No GitHub credential exists in the session or in the guest; a host-side
facade holds it and attaches it on the way out** (GHS-013, GHS-014, GHS-018,
decided 2026-09-03, revising a same-day choice). Four placements were on the
table, with the daemon's placement in front of the decision: on macOS and on
Linux with hardware virtualisation the session daemon and the broker beside it
run inside a guest virtual machine, and on native Linux on the host.
Delivering the token into the session per operation, as the architecture of
record describes, was chosen first and withdrawn: the architecture itself says
the token is then a bearer credential any process in the session can reuse for
its lifetime, which is exactly what a prompt-injected agent would do, and under
it the epic's 403 cannot be Minimal's own answer. Holding the token beside the
daemon, never in the session, needs no new component but leaves an 8-hour
credential inside the guest to a sandbox escape or a guest snapshot. Leaving
the holder's placement open was declined because the planning step cannot
decompose the reach requirements without it. The facade on the host is the
strongest of the four and the only one under which the session never holds a
credential, the guest never holds one, a request outside the set is refused
before it leaves, and access ends with the session (GHS-019). It costs a
component the architecture of record does not have, a path by which the guest
daemon reaches it for a child's grant, and the in-session routing of gh, whose
only host override treats its target as an enterprise server; the first two
are the architecture question below, the third an open question here. The facade is
transparent to git and gh: standard commands work (GHS-011), which is what the
2026-08-20 decision required, and the earlier design of a forced in-session
command stays retired.

**A session's credential expires within 8 hours**, GitHub's own user-token
expiry (decided 2026-09-03), rather than an open question or a shorter ceiling
set here at the cost of more renewals. It depends on the App's
token-expiration setting staying on (Gatehouse §6.4.1). That bound is the
access credential's. The developer's refresh token never reaches the facade
(GHS-024): it stays in the identity plane, which rotates it on every renewal,
refuses a reused one, and mints each renewed token narrowed to the same
repository set as the one it replaces (the GitHub identity spec).

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
proxy that acts on it, and it has to be written that way from the start. T0
would leave the decision free to interleave with the proxy;
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
GHS-018). The network side, egress declared before it happens and enforced at
the relay, is allow-all in running code today, and the design for enforcing
it belongs to the networking spec. GHS-022 states what the facade makes
possible: a session with a GitHub grant needs no github.com egress at all, so
an enforcing policy can deny it. Until egress is enforced the facade removes
the need for a credential in the session, not the ability of a session to
reach GitHub with one pasted in. Whether enforcement is a prerequisite for
this work is open.

**Generality:** GitHub.com is the sole provider by decision (GHS-007). The
facade's shape, a credential-free address per upstream, a credential held
outside the guest, a per-request reach decision, would fit a second upstream
such as the Claude programming interface, and a separate epic proposes exactly
that; every bound stated here, the 403, the permission ceiling, the 8-hour
lifetime, is GitHub's own model and does not carry. Across hosts the
behaviours are general: the facade sits on the host on every platform, so
where the daemon runs, inside a guest on macOS and Linux with hardware
virtualisation or on the host on native Linux, changes how the daemon reaches
it and nothing a session observes. A local and a remote session differ only
in whether sign-in is required to start (GHS-008, GHS-009); a local session on
a daemon not enrolled with the identity plane depends on the facade acting
under the developer's own sign-in, an open question below.

## Security considerations

- **Invariant:** THE SYSTEM SHALL keep every GitHub credential and every
  private key out of a session's filesystem and environment and out of the
  guest virtual machine, and hand a session nothing that carries one.
  enforced by: the facade holding credentials on the host outside the guest
  and handing sessions only credential-free addresses, and the scan of the
  session filesystem and process environments the architecture requires
  (Gatehouse INV-1, T3, T15).
  covered by: GHS-013, GHS-014, GHS-018, GHS-024
- **Invariant:** THE SYSTEM SHALL decide no request at the facade without
  first attributing it to one live session.
  enforced by: the facade's per-request session binding, refusing anything it
  cannot attribute (Gatehouse T15).
  covered by: GHS-023
- **Invariant:** THE SYSTEM SHALL admit through the facade no request for a
  repository outside the session's repository set.
  enforced by: the reach decision, a pure function over owned repository
  identifiers checked exhaustively to the stated bound and evaluated before
  any request is forwarded, with the narrowed mint in the identity plane as
  defence in depth (architecture AT12; Gatehouse T4, T9).
  covered by: GHS-003, GHS-004, GHS-005
- **Invariant:** THE SYSTEM SHALL leave no live GitHub grant for a session
  that has ended.
  enforced by: the facade observing session end from the daemon and
  discarding the session's credentials and addresses (Gatehouse T23).
  covered by: GHS-017, GHS-019
- **Invariant:** THE SYSTEM SHALL hold no session credential longer than 8
  hours without renewing or discarding it.
  enforced by: the facade's renewal against the identity plane's 8-hour token
  lifetime (Gatehouse §5.7, T3).
  covered by: GHS-020
- **Invariant:** THE SYSTEM SHALL write no credential and no request body to
  the audit record.
  enforced by: the facade recording only the session, the developer identity,
  the target and the decision (Gatehouse T18, INV-4).
  covered by: GHS-021
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

- [NEEDS CLARIFICATION (HIGH): The credential facade is not in the
  architecture of record, whose §6.4 and §8.3 deliver the token into the box;
  a proposal for it has been filed against the architecture. Its placement
  outside the guest, its identity toward the identity plane, how it binds a
  request to the session that sent it, and how a child session created inside
  the guest obtains its grant from it are decided there, and GHS-014, GHS-018,
  GHS-019 and GHS-023 are not implementable until they are.]
- [NEEDS CLARIFICATION (HIGH): Is declared-egress enforcement a prerequisite
  for credential-free GitHub access, or its own epic? Egress is allow-all in
  running code, the relay-layer enforcement design was closed without being
  planned, and the initiative's hard constraint says nothing leaves a box
  undeclared. Until it is enforced, the facade removes the need for a
  credential in a session and not a session's ability to reach GitHub with
  one pasted in.]
- [NEEDS CLARIFICATION (HIGH): GHS-012 attributes work from every box a
  developer's workflow spawns to the developer, decided and reconfirmed on
  2026-09-03, while Gatehouse §6.4 defaults every root other than session to
  installation mode. The architecture's per-type default has to move; does
  the agent type give up per-mint narrowing when it does?]
- [NEEDS CLARIFICATION (HIGH): On a daemon not enrolled with the identity
  plane, does the facade obtain a session's credential under the developer's
  own sign-in rather than a box identity, so that local sessions (GHS-009 to
  GHS-011) work without enrollment? Client-mediated local enrollment
  (Gatehouse F16) is the alternative.]
- [NEEDS CLARIFICATION (MEDIUM): gh has no base-address override for
  github.com; it does honour a host override that treats any other host as a
  GitHub Enterprise Server and sends requests to that host's enterprise-shaped
  paths. Pointing that override at the facade, which serves those paths
  against github.com, is the candidate mechanism for GHS-011. Which gh
  behaviours differ under a non-github.com host, and whether any matter for
  clone, push and pull requests, is undecided.]
- [NEEDS CLARIFICATION (MEDIUM): Which GitHub requests that name no
  repository, such as the identity lookup gh makes at start, does the facade
  admit? GHS-005 bounds repository targets; a request with no repository is
  neither in nor out of the set.]
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
- [NEEDS CLARIFICATION (LOW): The existing hidden sign-in command mints a
  client certificate for the HTTPS reverse proxy under the name the
  architecture's command tree gives to identity sign-in. What is the
  proxy-certificate command renamed to?]
- [NEEDS CLARIFICATION (LOW): Should tooling that adds a Co-authored-by
  trailer on an agent's behalf ask first? Recorded as a preference on
  2026-08-20 with no resolution.]
