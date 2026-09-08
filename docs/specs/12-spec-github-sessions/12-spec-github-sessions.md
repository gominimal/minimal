---
id: GHS
title: GitHub sign-in and credential-free repository access from sessions
status: draft
owner: norrietaylor
epic: gominimal/inbox#512
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-08
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
inside it as themselves, whether they or an agent typed the command. The
session never holds a raw credential: what it holds is a sealed value only the
egress proxy can open, and only for that session, on that node, for GitHub. A
session spawned by a workflow inherits no more access than its parent, and
nobody is prompted for it.

This document covers the CLI, the session daemon and the session's side of the
sealed-credential path: what a session receives, what it can reach, what it
never holds in the raw, and what its spec must declare. Signing the developer
in, minting and sealing tokens, the egress proxy that redeems sealed values,
and the browser pages of the sign-in are the identity plane's, in
[the GitHub identity spec](https://github.com/gominimal/gatehouse/blob/main/docs/specs/01-spec-github-identity/01-spec-github-identity.md).
The website's own sign-in is in
[the website sign-in spec](https://github.com/gominimal/webapp/blob/main/docs/specs/03-spec-website-signin/03-spec-website-signin.md).

**Success:** A developer with no prior Minimal account signs in with GitHub,
starts a remote session, and a push to their project from inside it lands on
GitHub attributed to them, with no raw credential typed, copied, or present
anywhere in the session.

**First slice:** The sign-in command, the browser approval, one remote session,
and a push to the workbench project from inside it with unmodified git through
the sealed-credential path.

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
  harness:  kani_reach_is_workbench_plus_declared, exhaustive to 8 declared repositories modelled as bounded identifiers (unwind bound 9); requires the reach decision to be a pure function over owned repository identifiers, separate from spec expansion

- **GHS-004** WHERE a session declares additional repositories before it starts
  THE SYSTEM SHALL bound its GitHub access to the workbench project and the
  declared repositories, and nothing else.
  tier:     T2
  verify:   cargo nextest run -p sessions reach_is_workbench_plus_declared
  property: for every declared set D, the set of repositories a git operation may target is exactly the workbench project together with D
  harness:  kani_reach_is_workbench_plus_declared, exhaustive to 8 declared repositories modelled as bounded identifiers (unwind bound 9); the same pure reach decision as GHS-003

- **GHS-005** IF a git or gh request from a session carries the session's
  sealed GitHub value and targets a repository outside the session's
  repository set, meaning the workbench project and the repositories it
  declared, THEN THE SYSTEM SHALL refuse it with a 403 before the request
  reaches GitHub.
  tier:     T0
  verify:   cargo nextest run -p minimal request_outside_repository_set_is_403_before_github

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

- **GHS-009** WHEN a developer starts a local session whose spec declares no
  GitHub grant THE SYSTEM SHALL start it without requiring sign-in.
  tier:     T0
  verify:   cargo nextest run -p minimal local_session_without_grant_starts_without_signin

- **GHS-010** IF a developer starts a local session whose spec declares a
  GitHub grant while they have no valid sign-in THEN THE SYSTEM SHALL require
  them to sign in before the session starts.
  tier:     T0
  verify:   cargo nextest run -p minimal local_session_with_grant_requires_signin
  - IF a process inside a session that declares no GitHub grant attempts a
    GitHub operation that needs a credential THEN THE SYSTEM SHALL tell it the
    session declares no GitHub grant, rather than asking for a password.
    tier:   T0
    verify: cargo nextest run -p minimal github_op_without_grant_names_the_missing_grant

- **GHS-011** WHILE a developer is signed in THE SYSTEM SHALL let standard git
  and gh commands inside a session clone, push and open pull requests without
  prompting for login information.
  tier:     T0
  verify:   cargo nextest run -p minimal raw_git_and_gh_work_without_login_prompt

- **GHS-012** THE SYSTEM SHALL attribute every commit pushed and every pull
  request opened from inside a session, or from inside any agent or task box
  a developer's workflow spawns, to the developer who signed in.
  tier:     T0
  verify:   cargo nextest run -p minimal session_commits_and_prs_attributed_to_developer
  - IF tenant policy forbids developer attribution for the box's type THEN
    THE SYSTEM SHALL attribute the work to the App and record the downgrade.
    tier:   T0
    verify: cargo nextest run -p minimal tenant_policy_downgrade_is_recorded

- **GHS-013** THE SYSTEM SHALL keep every raw GitHub credential, including any
  personal access token, any refresh token and any static private SSH key,
  out of a session's filesystem and environment.
  tier:     T0
  verify:   cargo nextest run -p minimal session_fs_and_env_hold_no_raw_github_credential

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

- **GHS-019** WHEN a session ends, by destroy or otherwise, THE SYSTEM SHALL
  revoke the session's identity, so that no further sealed value is minted for
  it and its existing sealed values stop being redeemable within 60 seconds.
  tier:     T0
  verify:   cargo nextest run -p minimal session_end_revokes_identity_and_sealed_values

- **GHS-020** WHILE a session is live THE SYSTEM SHALL renew its sealed GitHub
  value before it expires and hold none older than 8 hours.
  tier:     T0
  verify:   cargo nextest run -p minimal sealed_value_renewed_before_expiry_within_8h

- **GHS-022** IF a session's spec declares a runtime GitHub grant and its
  declared egress does not admit every host in the GitHub host set, github.com
  and api.github.com, THEN THE SYSTEM SHALL refuse the spec as invalid.
  tier:     T0
  verify:   cargo nextest run -p minimal github_grant_without_egress_entry_is_rejected

- **GHS-025** WHEN a signed-in developer starts a session that declares a
  GitHub grant on a local daemon that is not enrolled with the identity plane
  THE SYSTEM SHALL enroll that daemon under the developer's sign-in before the
  session is created, without a further prompt.
  tier:     T0
  verify:   cargo nextest run -p minimal local_daemon_enrolls_before_first_github_session

- **GHS-026** WHEN a session that declares a GitHub grant is created THE
  SYSTEM SHALL install the tenant's egress-interception certificate authority
  in the session's trust store.
  tier:     T0
  verify:   cargo nextest run -p minimal github_grant_installs_interception_authority
  - IF a session declares no credentialed upstream THEN THE SYSTEM SHALL
    install no interception authority in it.
    tier:   T0
    verify: cargo nextest run -p minimal no_grant_no_interception_authority

- **GHS-027** THE SYSTEM SHALL hand a session its brokered GitHub credential
  only as a sealed value that no process in the session can open.
  tier:     T0
  verify:   cargo nextest run -p minimal session_receives_sealed_value_only

- **GHS-028** WHILE a session is live THE SYSTEM SHALL steer its connections
  to its declared credentialed hosts, for a GitHub grant github.com and
  api.github.com, to the egress proxy.
  tier:     T0
  verify:   cargo nextest run -p minimal credentialed_host_connections_terminate_at_egress_proxy

- **GHS-029** THE SYSTEM SHALL block QUIC from a session to its declared
  credentialed hosts.
  tier:     T0
  verify:   cargo nextest run -p minimal quic_to_credentialed_hosts_is_blocked

- **GHS-030** IF a session's spec sets its network mode to none and declares a
  runtime GitHub grant THEN THE SYSTEM SHALL refuse the spec as invalid.
  tier:     T0
  verify:   cargo nextest run -p minimal network_none_with_github_grant_is_rejected

- **GHS-031** WHERE a session's spec declares a GitHub grant and sets no
  network mode THE SYSTEM SHALL give the session its own network address.
  tier:     T0
  verify:   cargo nextest run -p minimal github_grant_defaults_to_own_address

## Non-goals

- Signing the developer in, the browser pages of the sign-in, minting and
  sealing tokens, the egress proxy and its GitHub policy module, and
  attenuation at issuance:
  [the GitHub identity spec](https://github.com/gominimal/gatehouse/blob/main/docs/specs/01-spec-github-identity/01-spec-github-identity.md).
- The website's own sign-in and product pages:
  [the website sign-in spec](https://github.com/gominimal/webapp/blob/main/docs/specs/03-spec-website-signin/03-spec-website-signin.md).
- Sign-in through any provider other than GitHub.com, including enterprise
  OIDC: Gatehouse §6.1.3 (F2), a later phase of the identity plane.
- A forced in-session command for git: retired on 2026-08-20. Standard git and
  gh are the path (GHS-011), and since the sealed-credential design they need
  no configuration at all.
- Branch-aware activation, repository pre-priming, and a pull-request prompt
  on session exit: the earlier GitHub-sessions PRD carries them as a
  reference; none is in this epic's criteria.
- The Actions workflow permission: excluded from the App's permissions
  (GHI-004 in the GitHub identity spec).
- Revoking an already-delivered credential at GitHub: TTL-bounded (Gatehouse
  §12.9); here a session's end revokes its identity (GHS-019), which stops
  redemption of its sealed values.
- Enforcing the egress list for uncredentialed traffic, and whether a node's
  fabric can pin its egress: the egress gateway design in the architecture.
  This document binds only that credentialed reach rides the egress path.
- One narrowed token per owner for a repository set that spans owners: later
  work; such a set is refused at mint (the GitHub identity spec).
- The same egress-proxy shape for upstreams other than GitHub, such as the
  Claude programming interface or model-context servers: a separate
  credential-broker epic in the inbox; the architecture names the proxy as
  their shape too (D6).
- Sharing a session with another developer or an agent: the session-sharing
  spike in the inbox.
- A typed control plane for agents over sessions: the sessions MCP proposal in
  the inbox.
- Secrets beyond GitHub: out of scope for the initiative this epic belongs to.
- Counting the sign-in event for adoption telemetry: the telemetry epic under
  the same initiative.

## Design reasoning

**Three documents.** One spec per surface owner, decided 2026-09-03: this one
for the CLI, the daemon and the session's side of the credential path; the
identity plane's for sign-in, its browser pages, minting, sealing, the egress
proxy and attenuation; the website's for its own sign-in as a client of the
identity plane. A single document here with the identity behaviours as open
questions was the cheaper alternative and would have left the identity half
unspecified.

**Sign-in gates remote sessions, and local ones that declare a GitHub
grant** (decided 2026-09-03, revised 2026-09-08; mandatory sign-in for
remote sessions was reconfirmed on 2026-08-20). A local session with no
GitHub grant starts with no account (GHS-009); one whose spec declares a
grant asks for sign-in before it starts (GHS-010), and the grant is explicit
locally, so local stays opt-in. The 2026-09-03 cut prompted for sign-in
inside a running local session at its first GitHub operation; it was set
aside because the architecture makes box identity, the interception
authority and the sealed value creation-time, and a daemon not yet enrolled
cannot create a session with a grant at all, so the prompt could not be
honoured without re-creating the session. The alternatives kept from the
first decision were sign-in for every session including local, which removes
the account-free local path today's users have, and remote only with local
undecided. The cost accepted is that a running local session gains GitHub
access only by restarting with the grant, and that a GitHub operation in a
grant-less session is answered with what is missing rather than with a
credential (GHS-010's edge).

**A local daemon enrolls itself before its first session with a GitHub grant**
(GHS-025, decided 2026-09-08 from the architecture). A daemon not enrolled
with the identity plane has no broker and no identity socket, so no sealed
value can be minted for a session on it (Gatehouse §8.3); the architecture's
answer is client-mediated local enrollment, in which a signed-in developer
mints an enrollment token for their own laptop daemon (F16). Requiring the
developer to enroll by hand, and leaving local sessions without GitHub access,
were the alternatives; the first adds a step the epic's first story is written
to avoid, the second contradicts the decision above.

**Token reach is the workbench by default and wider when declared** (decided
2026-09-03). This reconciles the epic's criterion, which bounds a token to the
workbench project, with the 2026-08-20 ask that workbench-only be an option
rather than a rule. "Whatever the App installation grants" was set aside
because it does not meet the per-project bound at all. "The session's
repository set" means the workbench project plus the declared repositories
throughout this document. The set is computed here, at spec expansion, and
carried digest-bound into the session's creation; two things then bound the
token to it. The identity plane mints the session's token narrowed to the set
where GitHub can express it, and its egress proxy refuses, per request and
before GitHub, anything the sealed value's scope does not cover (GHS-005 is
the behaviour a session observes; the decision is the identity plane's).
GHS-005 binds requests that carry the session's sealed value: a request
without one is anonymous and passes egress-checked, which is what dependency
fetches from public repositories need and what the epic's criterion, written
about the minted token, asks; requests that name no repository, GraphQL among
them, ride the narrowed token's own bound at GitHub; and what a request
targets is the identity plane's mapping of path and method to a repository,
defined in the GitHub identity spec and not here (decided 2026-09-08). A set
spanning more than one owner is refused at mint there, since the un-narrowed
fallback the architecture allows would carry the developer's whole reach into
the session; per-owner tokens are later work. The
2026-08-20 record that a user-attributed token cannot be narrowed per
repository holds for renewal from a refresh token and not for minting;
renewal re-mints against the same set. Every session and every box a
developer's workflow spawns uses a developer-attributed token; a child's set
is a subset of its parent's (GHS-015). The reach decisions computed here
being pure and separable from expansion is what the T2 harnesses require.

**Custody: the session holds a sealed value, never a raw credential**
(GHS-013, GHS-027; decided 2026-09-03, revised 2026-09-06 in the architecture
of record and accepted here 2026-09-08). Four placements were considered on
2026-09-03. Delivering the raw token into the session per operation, the
architecture's model at the time, was withdrawn because the architecture
itself said the token was then a bearer any process in the session could
reuse for its lifetime, which is what a prompt-injected agent would do.
Holding it beside the daemon inside the guest left an 8-hour credential
exposed to a sandbox escape or a guest snapshot. The choice taken that day, a
host-side facade handing the session credential-free addresses, was itself
superseded three days later by the architecture's ruling: reachability as
authorization breaks under a shared network namespace, and a box whose egress
denied github.com could still reach it through such an address, fragmenting
the egress model. The shape adopted, and bound here on the session side, is
the architecture's sealed secret (Gatehouse §6.10): the token is delivered
exactly where a token was delivered before, the creation-time environment,
the identity socket and the git credential helper, but encrypted to the
tenant's egress proxy and bound to this session, its node, the upstream host,
the minted scope and an expiry. The session presents it as an opaque bearer;
the egress proxy, which terminates TLS for github.com with a per-tenant,
name-constrained interception authority installed in the session's trust
store (GHS-026), checks node, box, egress declaration and scope, substitutes
the real credential, and forwards. Sessions talk to the real hostnames, so
git and gh need no configuration, which is what the 2026-08-20 decision
required and what dissolves the earlier question about routing gh. GitHub is
two hosts to a session, github.com for git and api.github.com for gh; a
grant covers both (GHS-022, GHS-028) and the authority's constraint covers
both. The cost
is an interception authority inside the session, accepted as the smaller
change on ephemeral Minimal-built boxes, and a dependency on the identity
plane's fifth build phase, where the proxy lands.

**What the session side does for that path** (GHS-022, GHS-026, GHS-028,
GHS-029, GHS-030, GHS-031). The egress list is the single reachability
authority: a runtime GitHub grant whose upstream is absent from the declared
egress is a validation error rather than a second path beside it, and a
session with no networking cannot hold a runtime grant. Connections to
declared credentialed hosts are steered to the proxy at the node, and QUIC to
those hosts is blocked so the interceptable path is the only one. On a session
with its own network address the proxy can attribute a request to the box that
sent it and a stolen sealed value is dead across boxes; on a shared network
namespace that attribution is impossible, and the architecture accepts the
residual, a co-resident thief gets only the session's scoped, audited reach
until expiry or revocation, as the tier the chooser of that mode accepted. A
session with a GitHub grant therefore defaults to its own address (GHS-031,
decided 2026-09-08); a spec that sets the shared address explicitly keeps the
grant with that residual. The architecture's egress gateway design, in its
issues at the time of writing, moves egress enforcement outside the node and
proposes that grants require a node the fabric can pin; a laptop cannot be,
and this document keeps GitHub grants on local daemons (decided 2026-09-08):
the sealed value is dead off-node, so an escape on a laptop gains only the
developer's own scoped, audited reach on the developer's own machine, the tier
the local chooser accepts.

**A session's credential expires within 8 hours**, GitHub's own user-token
expiry (decided 2026-09-03), rather than an open question or a shorter ceiling
set here at the cost of more renewals. It depends on the App's
token-expiration setting staying on (Gatehouse §6.4.1). That bound is the
access credential's, and the sealed value carries it as its expiry. The
developer's refresh token never enters a session: it stays in the identity
plane, which rotates it on every renewal, refuses a reused one, and mints each
renewed token narrowed to the same repository set (the GitHub identity spec).

**Every end of a session ends its grant** (GHS-017, GHS-019, decided
2026-09-03 and restated 2026-09-08 in the architecture's terms). A session's
end revokes its identity; the identity plane stops minting for it within a
minute and its egress proxy consults the revocation feed, so a sealed value
outlives its session by at most 60 seconds (GHS-019). A child's access ends
with its parent's.

**Work is attributed to the developer, from a session and from any box a
workflow spawns** (GHS-012, decided 2026-09-03 and adopted by the architecture
on 2026-09-05). GHS-012 binds session, agent and task boxes, the types a
developer's workflow spawns, which default to developer-attributed tokens
through a type-supplied attribute; service and build boxes default to App
attribution and are outside the epic's criterion, a service outliving the
workflow that spawned it; a tenant may forbid developer attribution per type,
with a defaulted grant downgraded and recorded rather than silently kept
(GHS-012's edge) and an explicit request refused.

**Standard git and gh, no forced interface** (decided 2026-08-20). Once a
developer is signed in, git and gh inside a session work as the developer
against the real hostnames (GHS-011). The earlier PRD's forced facade command
stays retired.

**Permissions are repository contents, pull requests and issues read and
write, and metadata read; Actions workflows are excluded** (decided
2026-09-03, recorded in the architecture's manifest on 2026-09-05). Push and
pull requests alone would deny an agent the issue triage it does from inside
a session; adding workflows has the widest blast radius for a compromised
session. Each App installation's administrator must approve the widened
permissions before tokens for that installation carry them.

**Tiers.** The reach and child-subset decisions computed here (GHS-003,
GHS-004, GHS-015) are at T2: each is a pure decision over bounded repository
identifiers, and the Kani lane that already proves the path-decision lattice
runs the harnesses today. What the tier buys is the split each harness line
names: the decision is a pure function over owned values, separate from spec
expansion, and it has to be written that way from the start. The refusal a
session observes (GHS-005) is at T0 here: the decision that produces it lives
in the identity plane's GitHub policy module and is proved there. Everything
else stays at T0 because it passes through GitHub, a PTY or the network, and
there is no decision to extract. GHS-013 is a universal and stays at T0 on
purpose: sessions are not a domain a test can generate, so the
filesystem-and-environment scan the architecture asks for under INV-1 runs as
one named test, and the universal is stated in Security considerations. No
requirement is at T3: there is no Lean project to hold a proof. Requirements
GHS-014, GHS-018, GHS-021, GHS-023 and GHS-024 belonged to the superseded
facade and were withdrawn on 2026-09-08; their identifiers are not reused.
GHS-005's earlier edge for a target that could not be resolved moved to the
identity spec's rule for requests its module cannot map.

**Egress enforcement is the gateway's, not this epic's prerequisite**
(decided 2026-09-08). The initiative's constraint that nothing enters or
leaves a box undeclared is met on the credential side (GHS-013, GHS-027) and,
for credentialed reach, on the network side too: such reach rides the egress
path and is re-checked at the proxy (GHS-022, GHS-028). Enforcement of the
egress list for everything else is allow-all in running code today and has
its own design chain in the architecture, the egress gateway; it is not a
prerequisite here because the credential's reach is bounded by the token and
the proxy whether or not anonymous traffic is filtered.

**Generality:** GitHub.com is the sole provider by decision (GHS-007). The
sealed-credential path is general by the architecture's design: the same
proxy takes further upstreams as policy modules, and a separate epic proposes
the Claude programming interface and model-context servers as the next ones;
every bound stated here, the 403, the permission ceiling, the 8-hour lifetime,
is GitHub's own model and does not carry. Across hosts the behaviours are
general: the session-to-proxy TLS session is the encryption in transit on a
laptop guest, a cloud instance or a cluster pod alike, with no same-machine
assumption; a session's network mode changes how strongly a sealed value is
bound, not whether the path works. A local and a remote session differ only
in when sign-in is required, always for remote and with a GitHub grant for
local (GHS-008 to GHS-010), and in the local daemon's self-enrollment
(GHS-025).

## Security considerations

- **Invariant:** THE SYSTEM SHALL keep every raw GitHub credential and every
  private key out of a session, and hand a session brokered credentials only
  as sealed values it cannot open.
  enforced by: sealed delivery bound to the session's node and box, the
  proxy's refusal of a value presented off its node, from another box, for
  another host or outside its scope (GHI-021 to GHI-025 in the GitHub
  identity spec), and the scan of the session filesystem and process
  environments the architecture requires (Gatehouse INV-1, §6.10, T3, T28).
  covered by: GHS-013, GHS-027
- **Invariant:** THE SYSTEM SHALL admit no request carrying a session's
  sealed value for a repository outside the session's repository set.
  enforced by: the reach set computed here as a pure function over owned
  repository identifiers, checked exhaustively to the stated bound, and the
  identity plane's egress proxy refusing per request before GitHub
  (architecture AT12; Gatehouse T4, T9).
  covered by: GHS-003, GHS-004, GHS-005
- **Invariant:** THE SYSTEM SHALL grant a child session a repository set that
  is a subset of its parent's.
  enforced by: the child-reach decision here and attenuation at issuance in
  the identity plane (Gatehouse INV-2, §6.5; architecture AT16).
  covered by: GHS-015
- **Invariant:** THE SYSTEM SHALL reach a credentialed host from a session
  only along the path its declared egress admits, through the egress proxy.
  enforced by: validation at expansion, steering at the node, the QUIC block,
  and the proxy's own re-check of the declaration (architecture D6).
  covered by: GHS-022, GHS-028, GHS-029, GHS-030, GHS-031
- **Invariant:** THE SYSTEM SHALL install an interception authority in no
  session that declares no credentialed upstream.
  enforced by: creation-time injection conditioned on the session's spec
  (Gatehouse T27).
  covered by: GHS-026
- **Invariant:** THE SYSTEM SHALL start or attach no remote session, and
  start no session that declares a GitHub grant, for a developer without a
  valid sign-in.
  enforced by: the sign-in gate in the CLI before any session request is sent.
  covered by: GHS-008, GHS-010
- **Invariant:** THE SYSTEM SHALL leave no redeemable grant for a session that
  has ended beyond 60 seconds.
  enforced by: revocation of the session's identity at its end, which stops
  minting within a minute and reaches the proxy's revocation feed (Gatehouse
  F13, T23).
  covered by: GHS-017, GHS-019

## Open questions

- [NEEDS CLARIFICATION (HIGH): The egress proxy and sealed delivery land with
  the identity plane's fifth build phase, and sign-in with its second. What
  ships for sessions in between, and does any interim credential path exist
  before the proxy does?]
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
