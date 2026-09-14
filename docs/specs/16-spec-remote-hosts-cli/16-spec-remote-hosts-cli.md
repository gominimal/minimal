---
id: RHC
title: Remote hosts from the CLI
owner: mitodrummer
epic: gominimal/inbox#669
arch: https://github.com/gominimal/arch/blob/main/specs/box-provider/box-provider-api.md
updated: 2026-09-14
---

# RHC — Remote hosts from the CLI

## Context

A developer can run sessions only on the machine the CLI runs on. The pieces
around a remote session are designed: the Box Provider API says what a
provider owes its caller, from host inventory to host creation, pause and
limits; the identity plane mints a host's enrolment token and the grant a
session is created under; the box data path says that one listing and one
grammar cover every provider; and the certificate attach
([CRA](https://github.com/gominimal/minimal/pull/1374)) reaches a session
once it exists. Nothing states the CLI as a provider's client: choosing a
provider and a host, having a host created and enrolled, knowing the
developer's limits before anything is created, and listing, releasing and
resuming the hosts a provider made for them.

This spec states that client, in the CLI, for any provider that conforms to
the Box Provider API. Minimal's hosted compute is the first. What happens to
a session once its host is chosen, creating it, attaching to it, stopping it,
is the certificate attach's and the daemon's, and is a non-goal here.

After this ships, starting a session on remote compute is one flag on the
command a developer already uses, the host it needs appears without a
separate step, and the developer can see and release what they are paying
for.

**Success:** a developer signed in with GitHub, holding the hosted provider's
admin scope, runs `min session activate --provider <hosted>` in a project
with no host of their own yet, watches a host created and enrolled for them,
and the session is placed on it; `min session list` shows the session beside
their local ones; `min host list` shows the host, `min host rm` releases it
once it is empty, and after the provider pauses it, attaching to a session on
it brings the host back.

**First slice:** one provider with a fixed host it already lists, and no
host creation. `min provider show` reports the developer's limits and usage,
`min host list` shows the host and the sessions on it, and `min session list`
includes those sessions beside local ones. Placing a session on that host
follows once the daemon admits a session created over a certificate
connection (gominimal/arch#65); creating hosts, resuming them and refusing
over-limit starts follow without changing the slice.

## Users and stories

**Roles:** developer signed in with GitHub, developer with boxes on my laptop and on hosted compute, developer done with a remote box, developer returning to a remote box whose host was paused or restored while I was away, developer on Minimal's hosted compute

- AS A developer signed in with GitHub, I WANT to start a session on Minimal's hosted compute the same way I start one locally, naming only where it runs, SO THAT taking a workflow off my laptop is one choice, not a new tool.
  <!-- Acceptance criteria, for the EARS step:
       - Starting a session with the hosted provider named creates it on a Box Host of that provider and attaches, resolving the session from `minimal.toml` exactly as a local start does.
       - When none of the developer's hosts on that provider can take the box, the provider creates one: the CLI mints the host's enrolment token (#648 S1) and passes it to the provider's host creation; when one can, it is reused.
       - The box is created only under a grant the CLI requests with the developer's credential (#648 S2).
       - While a host is created and enrolled, the CLI shows each stage; when a stage fails, it names the stage and exits non-zero with the architecture's code for that failure (provider or host unreachable, or not permitted).
       - The developer can make the hosted provider their default, so starting a session without naming a provider starts it remotely.
       - Slices: reuse an existing host; create and enrol a host on demand.
  -->
- AS A developer with boxes on my laptop and on hosted compute, I WANT the list of my boxes to show remote ones alongside local ones, each with where it runs and its state, SO THAT one list tells me everything I have running.
  <!-- Acceptance criteria, for the EARS step:
       - Boxes on the machine the CLI runs on always appear, whether or not the developer is signed in, exactly as they do today.
       - When the developer is signed in, the list also shows boxes on hosted compute, from the provider's inventory (BPA-005), and boxes on the developer's other enrolled machines, from the identity plane's host list (#648 S3a). When they are not signed in, the list shows local boxes only and says that remote boxes need sign-in.
       - Each entry names its provider and host, and a box can be addressed by its name, or by provider, host and name when a name is ambiguous. A box reachable through more than one source, such as this machine when it is also enrolled, is listed once, keyed by its host's identity.
       - A host that does not answer shows its boxes as unreachable instead of dropping them from the list.
  -->
- AS A developer done with a remote box, I WANT to stop it, and later remove it, with the commands I use locally, SO THAT I'm not paying for compute I no longer need.
  <!-- Acceptance criteria, for the EARS step:
       - Stopping a remote box ends its processes and keeps its record, as it does locally.
       - Removing a remote box asks for a confirmation that names the box and its host, which a non-interactive run can skip explicitly.
       - The developer can list the hosts the provider created for them, with the boxes on each, and release a host that holds no boxes.
       - A removed box no longer appears in the list of boxes.
  -->
- AS A developer returning to a remote box whose host was paused or restored while I was away, I WANT my next use of the box (attaching, starting it, or running a command in it) to bring it back, SO THAT I never recreate a box because its host was paused overnight.
  <!-- Acceptance criteria, for the EARS step:
       - On a box whose host is paused, attaching, starting it, or running a command in it asks the provider to resume the host, then re-establishes the box's identity (#648 S7), showing each stage.
       - The developer can also bring a box back without attaching to it.
       - A host that cannot be resumed is reported with the reason and a non-zero exit, and the box is left as it was.
  -->
- AS A developer on Minimal's hosted compute, I WANT to see my limits and current usage, and have a start that would exceed them refused before anything is created, SO THAT a start never fails halfway through creating a host.
  <!-- Acceptance criteria, for the EARS step:
       - The developer can see their effective limits and current consumption on the hosted provider (BPA-016, BPA-017).
       - A start that would exceed a limit is refused before any host or box is created, naming the dimension, the limit and current usage (BPA-019), with a non-zero exit.
  -->

## Requirements

Terms the requirements depend on. A session is a box of the session type;
the stories say box, the commands say session (Gatehouse §7.4: sessions are
boxes). A provider is an entry in the developer's Box Provider List
([architecture](https://github.com/gominimal/arch/blob/main/architecture.md)),
and a remote host is a host reached through one other than the well-known
local providers. A provider can create hosts when it advertises host
creation, the Box Provider API's dynamic and multi-tenant profiles
([§2](https://github.com/gominimal/arch/blob/main/specs/box-provider/box-provider-api.md));
one on its static profile, a fixed set of hosts, cannot. Placing a session is
choosing the host its creation is sent to; the creation itself, over a
certificate connection to that host's daemon, is CRA's once the daemon admits
it (gominimal/arch#65). The developer is signed in while they hold a valid
sign-in ([GHS-006](https://github.com/gominimal/minimal/pull/1351)). Host
states are the API's §6 and exit statuses the architecture's
[Exit codes](https://github.com/gominimal/arch/blob/main/architecture.md#exit-codes);
the requirements cite them rather than restate them.

### Choosing the provider and the host

- **RHC-001** THE SYSTEM SHALL take the target provider from `--provider` when
  it is given, otherwise from `MIN_PROVIDER` when it is set, otherwise from
  the default recorded in the client config.
  tier:     T2
  verify:   cargo nextest run -p minimal-client provider_precedence_flag_env_config
  property: for every combination of flag, environment variable and recorded
            default, each present or absent, the target is the first present
            of the three in that order, and none present leaves today's
            local default
  harness:  kani_provider_precedence, exhaustive over every presence
            combination with symbolic provider identifiers; loop-free, so no
            unwind bound applies. Requires target selection to be a pure
            function over the three values, separate from reading them

- **RHC-002** WHEN the developer runs `min provider use <name>` THE SYSTEM
  SHALL record that provider as the default in the client config.
  tier:     T0
  verify:   cargo nextest run -p minimal provider_use_records_default

- **RHC-003** WHERE `MIN_PROVIDER` is set, WHEN the developer runs
  `min session activate` without `--provider` THE SYSTEM SHALL place the
  session on the provider it names.
  tier:     T0
  verify:   cargo nextest run -p minimal activate_uses_min_provider

- **RHC-004** WHERE a default provider is recorded in the client config, WHEN
  the developer runs `min session activate` without `--provider` or
  `MIN_PROVIDER` THE SYSTEM SHALL place the session on that provider.
  tier:     T0
  verify:   cargo nextest run -p minimal activate_uses_configured_default_provider

- **RHC-005** THE SYSTEM SHALL take the target host from `--host` when it is
  given, otherwise from `MIN_HOST` when it is set.
  tier:     T2
  verify:   cargo nextest run -p minimal-client host_precedence_flag_env
  property: for every combination of flag and environment variable, each
            present or absent, the named host is the first present of the two
            in that order, and none present names no host
  harness:  kani_host_precedence, exhaustive over every presence combination
            with symbolic host identifiers; loop-free, so no unwind bound
            applies. Requires the same pure selection function as RHC-001

- **RHC-006** WHEN the developer runs `min session activate --provider <p>`
  THE SYSTEM SHALL place the session on a host of provider p.
  tier:     T0
  verify:   cargo nextest run -p minimal-client activate_with_provider_places_on_that_provider

- **RHC-007** WHEN the developer runs `min session activate --provider <p>`
  THE SYSTEM SHALL resolve the same session definition from the project that
  a local activation of that project resolves.
  tier:     T0
  verify:   cargo nextest run -p minimal-client remote_activation_resolves_same_definition_as_local

- **RHC-008** WHEN the developer starts a session naming a host THE SYSTEM
  SHALL place the session on that host.
  tier:     T2
  verify:   cargo nextest run -p minimal-client named_host_receives_session
  property: for every provider, whether or not it can create hosts, and every
            inventory of up to three hosts containing the named host, the
            placement is the named host
  harness:  kani_named_host_is_placement, exhaustive to an unwind bound of 4,
            which covers every inventory of at most three hosts. Requires
            placement to be a pure function over the named host, the
            provider's ability to create hosts and a snapshot of its
            inventory, returning use-host, create-host or refuse, separate
            from every call to the provider
  - IF the named host is not in the provider's inventory THEN THE SYSTEM
    SHALL refuse to start the session and exit with status 4, or with status
    5 when the provider answers permission denied (Box Provider API §8).
    tier:   T0
    verify: cargo nextest run -p minimal unknown_named_host_exits_4_or_5

- **RHC-009** WHERE the target provider cannot create hosts and has exactly
  one host, WHEN the developer starts a session without naming a host THE
  SYSTEM SHALL place the session on that host.
  tier:     T2
  verify:   cargo nextest run -p minimal-client static_single_host_receives_session
  property: for every single-host inventory on a provider that cannot create
            hosts, with no host named, the placement is that host
  harness:  kani_static_single_host_is_placement, exhaustive to an unwind
            bound of 4. Requires the placement function of RHC-008

- **RHC-010** WHERE the target provider cannot create hosts, IF it has more
  than one host and the developer names none THEN THE SYSTEM SHALL refuse to
  start the session, listing the provider's hosts, and exit with status 2.
  tier:     T2
  verify:   cargo nextest run -p minimal static_ambiguous_host_refused_exits_2
  property: for every inventory of two or three hosts on a provider that
            cannot create hosts, with no host named, the placement is a
            refusal listing every host in the inventory
  harness:  kani_static_ambiguous_host_refused, exhaustive to an unwind bound
            of 4. Requires the placement function of RHC-008

- **RHC-011** WHERE the target provider cannot create hosts THE SYSTEM SHALL
  place sessions on it without asking it for a new host.
  tier:     T2
  verify:   cargo nextest run -p minimal-client static_provider_never_asked_to_create_host
  property: for every named host or none, and every inventory of up to three
            hosts, on a provider that cannot create hosts the placement is
            never create-host
  harness:  kani_static_provider_never_creates, exhaustive to an unwind bound
            of 4. Requires the placement function of RHC-008

### Creating a host

- **RHC-012** WHERE the target provider can create hosts, WHEN the developer
  starts a session without naming a host THE SYSTEM SHALL pre-register a new
  host with the identity plane before asking the provider to create it (the
  enrolment hand-off, Box Provider API §4.4; Gatehouse §8.2).
  tier:     T0
  verify:   cargo nextest run -p minimal-client unnamed_host_preregisters_before_create

- **RHC-013** IF the developer's credential for the provider lacks its admin
  scope THEN THE SYSTEM SHALL refuse to create a host before asking the
  provider, naming the missing scope, and exit with status 5 (Box Provider
  API §4.1).
  tier:     T0
  verify:   cargo nextest run -p minimal create_host_without_admin_scope_refused_exits_5

- **RHC-014** IF the identity plane refuses to mint the host's enrolment
  token THEN THE SYSTEM SHALL refuse to create the host before asking the
  provider, reporting the identity plane's reason, and exit with status 5.
  tier:     T0
  verify:   cargo nextest run -p minimal mint_refused_stops_create_exits_5

- **RHC-015** WHEN the CLI asks a provider to create a host THE SYSTEM SHALL
  request the standard host class.
  tier:     T0
  verify:   cargo nextest run -p minimal-client create_host_requests_standard_class

- **RHC-016** WHERE the target provider can create hosts and does not
  advertise attested enrolment, WHEN the CLI asks it to create a host THE
  SYSTEM SHALL send the host's enrolment token with the request (Box Provider
  API §4.4).
  tier:     T0
  verify:   cargo nextest run -p minimal-client create_host_carries_enrolment_token

- **RHC-017** WHERE the target provider advertises attested enrolment, WHEN
  the CLI asks it to create a host THE SYSTEM SHALL pre-register the host in
  the identity plane's tokenless mode and send the request without an
  enrolment token (Box Provider API §4.4).
  tier:     T0
  verify:   cargo nextest run -p minimal-client attested_provider_preregisters_tokenless

- **RHC-018** WHEN a host the CLI asked a provider to create reaches READY THE
  SYSTEM SHALL place the waiting session on it.
  tier:     T0
  verify:   cargo nextest run -p minimal-client session_placed_when_new_host_ready

- **RHC-019** WHEN a host the CLI asked a provider to create enters a new state
  THE SYSTEM SHALL show the state's name: REQUESTED, PROVISIONING, ENROLLING
  or READY.
  tier:     T0
  verify:   cargo nextest run -p minimal host_creation_shows_each_state

- **RHC-020** IF a host the CLI asked a provider to create ends FAILED THEN THE
  SYSTEM SHALL name the state the host failed in and exit with status 7.
  tier:     T0
  verify:   cargo nextest run -p minimal failed_host_names_state_exits_7

- **RHC-021** IF the provider becomes unreachable while the CLI is creating a
  host THEN THE SYSTEM SHALL name the last state the host reached, if any, and
  exit with status 7.
  tier:     T0
  verify:   cargo nextest run -p minimal unreachable_provider_during_create_exits_7

### Where the listing's remote entries come from

The listing itself, one list and one grammar for every provider, is the box
data path's (BDP-005, BDP-006 in gominimal/arch#45). These requirements say
where its remote entries come from.

- **RHC-022** WHILE the developer is signed in THE SYSTEM SHALL draw the
  listing's remote entries from the sessions on the hosts of each provider in
  the developer's provider list, the hosts taken from that provider's
  inventory.
  tier:     T0
  verify:   cargo nextest run -p minimal-client listing_includes_provider_hosts

- **RHC-023** WHILE the developer is signed in THE SYSTEM SHALL draw the
  listing's remote entries also from the sessions on the developer's other
  enrolled machines, the machines taken from the identity plane's node
  listing (Gatehouse §8.2).
  tier:     T0
  verify:   cargo nextest run -p minimal-client listing_includes_enrolled_machines

- **RHC-024** WHILE the developer is not signed in THE SYSTEM SHALL draw the
  listing's entries from the local providers only.
  tier:     T0
  verify:   cargo nextest run -p minimal listing_signed_out_is_local_only

- **RHC-025** WHILE the developer is not signed in THE SYSTEM SHALL state in
  the listing that remote sessions need sign-in.
  tier:     T0
  verify:   cargo nextest run -p minimal listing_signed_out_says_sign_in_needed

- **RHC-026** THE SYSTEM SHALL list a session reachable through more than one
  source once, keyed by the identity-plane node ID of its host.
  tier:     T0
  verify:   cargo nextest run -p minimal-client listing_dedupes_by_host_node_id

- **RHC-027** IF a host does not answer the listing THEN THE SYSTEM SHALL show
  that host's sessions as unreachable instead of omitting them. How "does not
  answer" is decided, and where those sessions are learned, are open
  questions.
  tier:     T0
  verify:   cargo nextest run -p minimal-client unanswering_host_sessions_shown_unreachable

### Listing, releasing and resuming hosts

- **RHC-028** WHEN the developer runs `min host list` THE SYSTEM SHALL list the
  hosts the developer's providers created for them, with the sessions on each.
  tier:     T0
  verify:   cargo nextest run -p minimal host_list_shows_created_hosts_with_sessions

- **RHC-029** WHEN the developer runs `min host rm <host>` on a host that holds
  no sessions THE SYSTEM SHALL ask the host's provider to release it.
  tier:     T0
  verify:   cargo nextest run -p minimal-client host_rm_releases_empty_host

- **RHC-030** IF the developer runs `min host rm <host>` without `--force` on a
  host that holds sessions THEN THE SYSTEM SHALL refuse, naming those
  sessions, and exit with status 2.
  tier:     T0
  verify:   cargo nextest run -p minimal host_rm_occupied_refused_exits_2

- **RHC-031** WHEN the developer runs `min host rm --force <host>` on a host
  that holds sessions THE SYSTEM SHALL ask the host's provider to release it.
  tier:     T0
  verify:   cargo nextest run -p minimal-client host_rm_force_releases_occupied_host

- **RHC-032** WHILE a session's host is PAUSED, WHEN the developer attaches to
  the session THE SYSTEM SHALL ask the provider to resume the host and wait
  for READY before the attach proceeds.
  tier:     T0
  verify:   cargo nextest run -p minimal-client attach_to_paused_host_resumes_it_first

- **RHC-033** WHEN the developer runs `min host resume <host>` on a PAUSED host
  THE SYSTEM SHALL ask the host's provider to resume it.
  tier:     T0
  verify:   cargo nextest run -p minimal-client host_resume_requests_provider_resume

- **RHC-034** WHILE the CLI is resuming a host THE SYSTEM SHALL show each
  stage: resume requested, host READY.
  tier:     T0
  verify:   cargo nextest run -p minimal resume_shows_each_stage

- **RHC-035** IF a host cannot be resumed THEN THE SYSTEM SHALL leave the
  record and state of each session on it unchanged.
  tier:     T0
  verify:   cargo nextest run -p minimal-client failed_resume_leaves_sessions_unchanged

- **RHC-036** IF a provider refuses or fails a request THEN THE SYSTEM SHALL
  report the provider's reason and exit with the status the Box Provider API's
  error model (§8) assigns to it.
  tier:     T0
  verify:   cargo nextest run -p minimal provider_errors_map_to_exit_statuses

### Limits

- **RHC-037** WHEN the developer runs `min provider show <name>` THE SYSTEM
  SHALL show the developer's effective limits and current usage on that
  provider (Box Provider API §5).
  tier:     T0
  verify:   cargo nextest run -p minimal provider_show_lists_limits_and_usage

- **RHC-038** IF a host or session the CLI is about to request would exceed one
  of the developer's limits on the provider THEN THE SYSTEM SHALL refuse it
  before asking the provider to create anything.
  tier:     T2
  verify:   cargo nextest run -p minimal-client over_limit_refused_before_any_create
  property: for every limit, usage and request value in every quota dimension
            the Box Provider API defines, the check never overflows and
            refuses exactly when some dimension's usage plus request exceeds
            its limit, where an absent limit never refuses and a limit of
            zero refuses any request on that dimension
  harness:  kani_limit_check_refuses_iff_exceeded, exhaustive over all 64-bit
            values to an unwind bound of 7, which covers the API's six
            dimensions. Requires the check to be a pure function over limits,
            usage and request with checked arithmetic, separate from the calls
            that fetch limits and usage

- **RHC-039** IF the CLI refuses a request for exceeding a limit THEN THE
  SYSTEM SHALL name the dimension, the limit and current usage, and exit with
  status 5.
  tier:     T2
  verify:   cargo nextest run -p minimal over_limit_refusal_names_dimension_exits_5
  property: every refusal the check returns names a dimension that the request
            does exceed, with that dimension's limit and current usage
  harness:  kani_limit_refusal_names_exceeded_dimension, exhaustive over all
            64-bit values to an unwind bound of 7. Requires the check of
            RHC-038 to return the refusal's dimension, limit and usage

- **RHC-040** IF a provider refuses a host or a session for exceeding a limit
  THEN THE SYSTEM SHALL name the dimension, the limit and current usage from
  the provider's refusal, and exit with status 5.
  tier:     T0
  verify:   cargo nextest run -p minimal provider_quota_refusal_names_dimension_exits_5

## Non-goals

- Creating the session on the host this spec places it on, over a
  certificate connection to that host's daemon, and the grant it is created
  under, which names the host chosen here (Gatehouse §6.3): CRA, once the
  daemon admits a session created that way (gominimal/arch#65).
- Attaching to, stopping and destroying a remote session:
  [CRA](https://github.com/gominimal/minimal/pull/1374). CRA-009 names the
  commands admitted over a certificate connection in v1; destroying a remote
  session waits on gominimal/arch#65.
- One listing and one grammar across providers, the listing's columns, and
  how a session is addressed when a name is ambiguous: the box data path
  (BDP-005, BDP-006 and its open question on bare names, gominimal/arch#45).
- Re-establishing a session's identity after its host is resumed, which the
  identity plane decides per session for its owner (`ResumeBox`, Gatehouse
  §6.3.3; `min box resume <box>` in the architecture): CRA, on the next
  attach, once the daemon admits it. `min host resume` (RHC-033) brings back
  the host only.
- What the CLI's automatic re-attach does when a host is paused under it:
  CRA-034.
- Minting enrolment tokens, issuing grants, listing enrolled machines, and
  which principals may mint a standard-class token: gominimal/inbox#648 and
  the identity plane's spec. Whether a developer holds the hosted provider's
  admin scope: the hosted provider, which has no epic yet.
- Host creation, pause and resume, limit enforcement and inventory on a
  provider's side: the Box Provider abstraction (gominimal/arch#45). For
  Minimal's hosted compute, the hosted provider, which has no epic yet.
- When an emptied host is released without the developer asking, the hosted
  provider's name, and whether a fresh sign-in makes it the default: the
  hosted provider, which has no epic yet.
- Stopping a local session: the change to the CLI's command structure, which
  no issue owns yet.
- Declaring and managing providers beyond choosing a default and seeing its
  limits: parked by the epic under its Negotiable heading; the architecture's
  Box Provider List describes it.
- Choosing a host's size, region or architecture, and placing a session by
  its declared resources: Box Spec story 5 in gominimal/inbox#570, with the
  provider's half in the Box Provider abstraction.
- Pushing a running local session to a remote host: parked by the epic under
  its Negotiable heading.
- Copying files into or out of a remote session: the box data path
  (BDP-009 to BDP-017, gominimal/arch#45).
- The network path to a host: the networking work (gominimal/inbox#646).
- Operating providers other than Minimal's hosted one this cycle
  (gominimal/inbox#494). The requirements hold for any provider that conforms
  to the Box Provider API.
- Two developers in one session: out of scope per gominimal/inbox#494.

## Design reasoning

**A hosts spec, not a sessions spec.** The first draft carried the whole of
the epic: placing a session, creating it, listing, stopping, destroying and
resuming it, and limits. A review against the architecture of record found
that the daemon's v1 remote command set admits list, show, attach, rename and
stop, and keeps create, destroy and exec local-only (Gatehouse §7.4, ratified
by MMI-027), and that the box data path already claims one listing and one
grammar for every provider (BDP-005, BDP-006). So the spec was split: this
one keeps the CLI as a provider's client, choosing a provider and a host,
having a host created, listing, releasing and resuming hosts, limits, and
where the listing's remote entries come from; session operations belong to
CRA as the architecture admits them, and the listing and grammar to the box
data path. Keeping one spec and opening it as a draft blocked on those
decisions, and holding it until the architecture answered, were the
alternatives (2026-09-12).

**One spec, in the CLI's home, for any conforming provider.** Everything the
epic asks of the caller happens in the CLI, so the spec sits beside CRA. A
sibling spec for the hosted provider was considered and not written: that
provider has no epic, so its stories would have been invented. The
requirements hold for any provider the Box Provider API describes, with
Minimal's hosted compute as the first, rather than for the hosted provider
only; that is what makes a fixed pool of hosts, a provider that cannot create
them, fit the same rules.

**Today's command names, and the architecture's for the rest.** The spec
names the CLI's commands as they are today (`min session activate`,
`min session list`), and updates with the change that alters the grammar.
Naming only behaviours, as the epic does, and naming the grammar expected
after the Box Spec work were the alternatives. Where today has no command,
the spec uses the architecture's: `min host list`, `min host rm`,
`min provider use` and `min host resume`. Limits show in `min provider show`
(RHC-037), because a developer with no host yet could otherwise not check a
start before making it; `min host show`, where the architecture's mapping
puts usage, and showing limits only in the refusal were the alternatives. The
Box Provider API's Appendix A already returns limits from provider
information; its mapping of usage needs the matching one-line change.

**Where a session runs.** On a provider that cannot create hosts, a new
session goes on an existing host, because hardware cannot be made on demand
(RHC-009, RHC-011). With several hosts and none named, the CLI refuses and
lists them (RHC-010), the architecture's rule for an ambiguous name, over
picking any host with room or leaving it open. On a provider that can create
hosts, a session reuses a host only when the developer names it (RHC-008),
and otherwise gets a new one (RHC-012). Reusing any ready host with room,
which is cheaper, and always creating a host, which isolates sessions, were
the alternatives; automatic reuse stays an open question. Because a reused
host has to outlive its first box, and an ephemeral-class host terminates
when that box completes (Box Provider API §6), the CLI requests standard-class
hosts (RHC-015).

**Host creation needs rights, so the CLI says so.** Creating, releasing and
resuming a host need the provider's admin scope (Box Provider API §4.1), and
a standard-class enrolment token is minted by an org admin or a principal a
tenant delegates by policy (§4.4). Rather than assume a developer holds
both, the CLI checks and refuses before asking the provider, naming the
missing right (RHC-013, RHC-014). Taking implicit host creation out of this
cycle, so that an admin creates hosts explicitly and sessions start on
existing ones, and asking the architecture to let any developer create a
host implicitly, were the alternatives. A developer in a personal tenant is
its admin, so the first-run case works as written.

**Choosing the provider.** `min provider use`, the client config and
`MIN_PROVIDER` all set it, and `--provider` beats `MIN_PROVIDER`, which beats
the recorded default (RHC-001): this spec's rule, consistent with the
architecture's flag table. Passing `--provider` every time was the
alternative. `MIN_HOST` pairs with `--host` the same way (RHC-005).

**Every provider by default.** The listing draws from every provider in the
developer's list rather than one provider at a time, as the box data path's
one listing does (BDP-005).

**Resuming a host brings back the host.** `min host resume` asks the provider
to resume the host and stops there (RHC-033); each session's identity is
re-established per session, for its owner, by the identity plane's resume
decision, which the CLI drives on the next attach. Having the command also
re-establish the developer's own sessions and report the others as skipped
was the alternative; it is a session operation, and it belongs with the
attach. Attaching to a session on a paused host resumes the host first
(RHC-032); the epic's "running a command in it" is not admitted remotely in
v1, and "starting it" has no command today.

**Exit statuses.** A host that ends FAILED exits 7, provider or host
unreachable, the closest existing code; 1, unspecified, was the alternative.
The refusals a developer fixes by saying more, an ambiguous host and removing
a host that holds sessions, exit 2, usage error, over 1 or leaving them
open. `--force` on `min host rm` overrides a refusal, as the architecture's
global flag does.

**Unreachable hosts left open.** A host that does not answer cannot say which
sessions it holds, and the provider's inventory lists hosts, not sessions.
Showing the host as one row with its sessions unknown, and keeping a local
record of last-known sessions, were both offered and neither taken, so that
the identity plane's liveness states, which arrive with its node listing,
can be weighed first.

**Custody left to the identity plane.** The CLI holds the host's enrolment
token and the candidate WireGuard key it generated between minting and the
provider's answer, and the Box Provider API's custody rules cover the
provider's side only. Requiring the CLI to hold both in memory only and
discard them once the provider answers, with or without re-sending them on a
retry within the token's lifetime, were offered; the identity plane, which
mints the token, decides (open question).

**Two decisions exhausted, the rest at T0.** Choosing where a session runs
(RHC-001, RHC-005, RHC-008 to RHC-011) and the limit check (RHC-038,
RHC-039) are pure decisions over small inputs, so each gets Kani harnesses in
the lane the repository already runs, at the cost of writing each as a pure
function and adding its crate and harness count to that lane. Named tests
alone were the alternative for each. The limit check is not a security
control, since the provider enforces limits itself, but its arithmetic can
overflow. Merging the listing's sources (RHC-022 to RHC-026) stays at T0: a
mistake shows a duplicate row, a Kani harness would need a merge written
without hashing, and a property test would add a dependency the repository
does not have. Exit statuses stay at T0 with one table-driven test over the
provider's error conditions (RHC-036). T3 was ruled out: anything that calls
a provider runs on an async runtime, outside the sequential subset Aeneas
takes, and the repository has no Lean project for the pure decisions.

**Generality:** any provider that conforms to the Box Provider API is chosen,
asked for hosts, listed, released and resumed the same way; what differs is
only whether it can create hosts, whether it advertises attested enrolment
and whether it can pause and resume, each of which the API advertises and a
requirement here keys on. A developer's other enrolled machine is listed
through the identity plane, not a provider, and starting a session on one is
an open question.

## Security considerations

- **Invariant:** THE SYSTEM SHALL ask a provider to create, release or resume
  a host only with the developer's own credential for that provider.
  enforced by: the provider's verification of the caller's token and scope
  (Box Provider API §4.1, §4.2)
  covered by: RHC-012, RHC-013, RHC-029, RHC-033

- **Invariant:** THE SYSTEM SHALL have every host it asks a provider to create
  pre-registered with the developer's identity plane before the request.
  enforced by: the enrolment hand-off, under which a host not pre-registered
  cannot enrol (Box Provider API §4.4; Gatehouse §6.2, §8.2)
  covered by: RHC-012, RHC-016, RHC-017

## Open questions

- [NEEDS CLARIFICATION (HIGH): when a host does not answer the listing, how is
  "does not answer" decided, and where do the sessions RHC-027 shows as
  unreachable come from?] Survives because it was left open on 2026-09-11:
  the host cannot say which sessions it holds and the provider's inventory
  lists only hosts. For a machine in the identity plane's node listing, its
  liveness state (Gatehouse §8.2; gominimal/inbox#648 S3b) may decide the
  first half without a timeout.

- [NEEDS CLARIFICATION (HIGH): how does the CLI hold the host's enrolment
  token and the candidate WireGuard key it generated, between minting and the
  provider's answer?] Survives because it was handed to the identity plane's
  work on 2026-09-14: gominimal/inbox#648 mints the token, and the Box
  Provider API's custody rules cover the provider's side only.

- [NEEDS CLARIFICATION (MEDIUM): how long does the CLI wait for a new host to
  reach READY before it gives up, and with which exit status?] Survives
  because it depends on the hosted provider's provisioning time, and that
  provider has no epic or measurements yet.

- [NEEDS CLARIFICATION (MEDIUM): should a new session on a provider that can
  create hosts reuse one of the developer's hosts automatically when it has
  room, instead of only when the developer names it?] Survives because it
  was asked on 2026-09-11 and deliberately kept open: reuse by name ships
  first, and automatic reuse, the cheaper option, lets sessions share a host.

- [NEEDS CLARIFICATION (MEDIUM): how does a developer start a session on
  another of their own enrolled machines?] Survives because such a machine
  appears in the identity plane's node listing and in no provider's
  inventory, and nothing serves the Box Provider API for it; the epic's first
  story asks only for hosted compute.
