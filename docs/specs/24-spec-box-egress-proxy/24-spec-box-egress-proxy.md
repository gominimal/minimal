---
id: BEP
title: Local Box Egress Proxy — sealed GitHub credentials and host-store secrets without Gatehouse
owner: norrietaylor
epic: gominimal/inbox#625
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-17
---

# BEP — Local Box Egress Proxy — sealed GitHub credentials and host-store secrets without Gatehouse

## Context

A developer working in a box today gives an agent a credential by pasting it
in, passing it through from the client environment, or running the Python
reference broker. Each puts a bearer in the box, where a prompt-injected agent
can read it and use it from anywhere for its full lifetime. The architecture
ruled on 2026-09-06 that brokered secrets enter a box only as sealed values
redeemed at a Box Egress Proxy ([architecture D6](https://github.com/gominimal/arch/blob/main/architecture.md),
[Gatehouse §6.10](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md)),
and on 2026-09-17 that on a laptop the proxy runs node-local, on the host OS
outside the VM (Gatehouse F19, v1.19; [networking design §7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).
The Gatehouse-hosted path lands with the identity plane's fifth phase
([GHI](https://github.com/gominimal/gatehouse/pull/1)); until then an
un-enrolled laptop has no credential path. The local-first ordering decided on
2026-09-15 puts that laptop first.

This document binds the un-enrolled form: a host-side proxy beside gvproxy that
terminates TLS only for a box's declared credentialed upstream hosts under a
host-generated, name-constrained CA the box can see in its spec; substitutes
sealed GitHub values minted by a local sign-in and Keychain secrets referenced
by identifier; re-checks the box's declared egress; and audits every decision
to a local log. The surfaces are the `min` CLI (sign-in, `min secret`, box spec review,
audit), the box spec (`[network]`, `[network.bep]`, `[secrets]`, the client's
`[secret-store-rules]`), the box host's session creation, and the proxy itself.

**Success:** in a box that holds no plaintext credential anywhere in its
environment, files or volumes, `git clone`, `git push` and `gh api` against a
private repository of the signed-in account succeed; the same sealed value
copied to the host shell or into another box is refused; and every admit and
refuse is readable per box.

**First slice:** `proxy_env` steering, the GitHub v1 host set as the one
module, a sealed member minted by `min auth login`, redemption with every check,
the local audit log, and `min box spec` showing the CA and the upstream set.
Keychain references with `min secret`, `dns` steering, signing-CA rotation,
the PAC recipe and `host_ip` cohort handling are later slices.

## Users and stories

**Roles:** developer using Minimal on a laptop with no Gatehouse, developer working in a box, developer with an API key in my macOS Keychain, developer with a third-party API key, such as a Claude OAuth token or an MCP server credential, developer, developer reviewing what a box may reach

- AS A developer using Minimal on a laptop with no Gatehouse, I WANT to sign in to GitHub once with `min`, SO THAT every box I start afterwards can reach my repositories without me handling a token.
- AS A developer working in a box, I WANT `git clone`, `git push` and `gh` to work against my repositories, SO THAT I do real work without configuring any tool.
- AS A developer with an API key in my macOS Keychain, I WANT to reference it by identifier in a box spec, SO THAT requests from the box to that key's upstream carry it without the key entering the box.
- AS A developer with a third-party API key, such as a Claude OAuth token or an MCP server credential, I WANT to store it once with `min secret`, SO THAT box specs reference it by identifier and its value never appears in `min` output, a spec, or a box.
- AS A developer, I WANT the proxy to refuse any use of a sealed or referenced secret outside its declared authority, SO THAT a compromised workload cannot redirect my credential.
- AS A developer, I WANT a sealed value copied out of a box to be worthless anywhere else, SO THAT exfiltration of the box environment yields nothing usable.
- AS A developer reviewing what a box may reach, I WANT the expanded box spec to show the interception CA and the derived credentialed upstream set, SO THAT interception is declared, not discovered.
- AS A developer, I WANT to read what the proxy admitted and refused, SO THAT I can see what my agents did with my credentials.
- AS A developer, I WANT to revoke a session's credentials, SO THAT a value already delivered stops working.

## Requirements

Sign-in

- **BEP-001** WHERE no Gatehouse is configured, WHEN `min auth login` is run THE SYSTEM SHALL complete the GitHub device flow and report the signed-in account.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_login_completes_device_flow_and_reports_account

- **BEP-002** WHEN a GitHub sign-in completes THE SYSTEM SHALL store the token and refresh material in the host keychain and in no file under the project or the box.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_login_stores_material_in_keychain_only

- **BEP-003** WHILE a GitHub sign-in is held, WHEN a box declaring a GitHub grant is created THE SYSTEM SHALL create it without prompting for sign-in.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_second_box_needs_no_sign_in

- **BEP-004** WHEN `min auth status` is run THE SYSTEM SHALL report whether a GitHub sign-in is held and its expiry, and output no token value.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_status_reports_expiry_without_token

Minting and sealing

- **BEP-005** WHERE the host is not enrolled, WHEN a box declaring a `source = "broker"` GitHub grant is created THE SYSTEM SHALL mint a member from the held sign-in with an expiry no later than 8 hours after creation.
  tier:     T0
  verify:   cargo nextest run -p bep local_mint_expiry_is_at_most_8h

- **BEP-006** WHEN a GitHub member is minted THE SYSTEM SHALL seal it to this host's proxy key with the box, the host, the module identifier, the host-set version and the expiry bound in the authenticated context.
  tier:     T0
  verify:   cargo nextest run -p bep sealed_context_binds_box_host_module_version_expiry

- **BEP-007** WHEN a sealed member is delivered THE SYSTEM SHALL place the sealed value, and no plaintext token, in the grant's environment variable in the box.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_box_env_holds_sealed_value_only

- **BEP-008** IF a box spec declares a GitHub grant and its `egress.allow_dns_hosts` does not admit every host in the module's host set THEN THE SYSTEM SHALL refuse expansion with exit 3 naming each missing host.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_grant_host_set_outside_egress_is_exit_3
  property: for every box spec and every module host set, expansion refuses with exit 3 iff some host of the set is absent from `egress.allow_dns_hosts`, and the refusal names exactly the absent hosts

- **BEP-009** IF a box spec declares `network.mode = "none"` and a GitHub grant THEN THE SYSTEM SHALL refuse expansion with exit 3.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_none_mode_with_grant_is_exit_3
  property: for every box spec, expansion refuses iff `network.mode` is `none` and at least one runtime grant is declared

- **BEP-010** IF a box spec declares `steering = "off"` and a GitHub grant THEN THE SYSTEM SHALL create the box with no interception CA injected and emit a validation warning naming the grant.
  tier:     T0
  verify:   cargo nextest run -p sessions steering_off_with_grant_warns_and_injects_no_ca

Steering and the interception CA

- **BEP-011** WHERE a box declares a credentialed upstream and its steering is not `off`, WHEN the box is created THE SYSTEM SHALL inject the host root CA certificate into the box trust store.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_root_ca_present_in_box_trust_store

- **BEP-012** WHERE a box's steering is `proxy_env` or `both`, WHEN the box is created THE SYSTEM SHALL set `HTTPS_PROXY` and `HTTP_PROXY` in the box environment to the proxy's address and set `NO_PROXY` to `.min.internal`, `host.min.internal`, `localhost`, `127.0.0.1` and the box's `[network.bep] no_proxy` entries.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_proxy_env_and_no_proxy_are_set

- **BEP-013** WHEN a box connects to an admitted credentialed hostname through the proxy THE SYSTEM SHALL present a leaf certificate for that hostname that chains to the host root CA through a signing CA whose name constraints equal the box's declared credentialed upstream set.
  tier:     T1
  verify:   cargo nextest run -p bep prop_signing_ca_constraints_equal_declared_set
  property: for every declared credentialed upstream set, the signing CA's permitted-names constraint equals the set, a leaf for a name in the set validates against the root, and a leaf for any name outside the set fails validation

- **BEP-014** THE SYSTEM SHALL hold the signing CA private key in the host keychain as a non-exportable key and write it to no file.
  tier:     T0
  verify:   cargo nextest run -p bep signing_key_is_non_exportable_and_has_no_file

- **BEP-015** WHILE a box with steering `proxy_env` holds a sealed GitHub member THE SYSTEM SHALL complete `git clone`, `git push` and `gh api` against a private repository of the signed-in account with no tool configuration in the box beyond what the box carries at creation.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_git_and_gh_against_private_repo

- **BEP-016** WHERE a box spec declares a credentialed upstream and no `steering` THE SYSTEM SHALL resolve `steering` to `dns`.
  tier:     T0
  verify:   cargo nextest run -p sessions steering_defaults_to_dns

- **BEP-017** WHILE the host has no box-zone resolver, IF a box spec's resolved steering is `dns` or `both` and it declares a credentialed upstream THEN THE SYSTEM SHALL refuse expansion with exit 3 naming the missing resolver.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_dns_steering_without_resolver_is_exit_3
  property: for every box spec declaring a credentialed upstream, on a host with no box-zone resolver, expansion refuses iff the resolved steering is `dns` or `both`

- **BEP-018** WHILE a box holds a credentialed upstream and its `quic443` resolves to `auto` or `block`, IF the box sends UDP to port 443 THEN THE SYSTEM SHALL drop the datagram.
  tier:     T0
  verify:   cargo nextest run -p minimald quic443_auto_drops_udp_443_for_credentialed_box

Redemption

- **BEP-019** IF a request carries a sealed value that does not decrypt under this host's proxy key THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_off_host_sealed_value_is_refused
  property: for every sealed value and every host key, redemption admits only when the value decrypts under that host's key; a value sealed to any other key is refused
  harness:  kani_redeem_refuses_undecryptable, exhaustive to host sets of at most 4 authorities and 2 members with authorities interned as u8 ids; requires the redemption decision to be a pure function over owned values, separate from the TLS and socket shell

- **BEP-020** IF a request's connection source address resolves to no live box, or to an `own_ip` box other than the one the sealed value names THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_cross_box_sealed_value_is_refused
  property: for every attribution result and every sealed value, redemption admits only when the attribution names a live box equal to the value's box (own_ip) or a live `host_ip` box of this host (host_ip)
  harness:  kani_redeem_refuses_misattributed, same bound and purity constraint as BEP-019

- **BEP-021** IF the connection authority of a request carrying a sealed value is outside the value's bound host set or outside the module's current host set THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_authority_outside_bound_or_current_set_is_refused
  property: for every bound set, every current set and every authority, redemption admits only when the authority is a member of both sets
  harness:  kani_redeem_requires_authority_in_both_sets, same bound and purity constraint as BEP-019

- **BEP-022** IF a request at the proxy, with or without a sealed value, targets an authority the sending box's declared egress does not admit THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_undeclared_egress_authority_is_refused
  property: for every egress declaration and every authority, the proxy admits only when the declaration admits the authority, whether or not the request carries a sealed value
  harness:  kani_redeem_requires_egress_admission, same bound and purity constraint as BEP-019

- **BEP-023** IF a request's `Host` header differs from the connection authority it arrived on THEN THE SYSTEM SHALL refuse the request before substitution.
  tier:     T2
  verify:   cargo nextest run -p bep prop_host_header_mismatch_is_refused
  property: for every connection authority and every `Host` value, substitution happens only when the two are equal
  harness:  kani_redeem_pins_request_authority, same bound and purity constraint as BEP-019

- **BEP-024** IF a sealed value's expiry has passed, or the value has been revoked THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_expired_or_revoked_value_is_refused
  property: for every sealed value, every clock reading and every revocation set, redemption admits only when the clock is before the value's expiry and the value is not in the set
  harness:  kani_redeem_refuses_expired_or_revoked, same bound and purity constraint as BEP-019

- **BEP-025** WHEN a request carrying a sealed value passes every redemption check THE SYSTEM SHALL replace the sealed value with the member's credential and forward the request to the connection authority.
  tier:     T2
  verify:   cargo nextest run -p bep prop_admit_iff_every_check_passes
  property: for every redemption input, the decision is Admit exactly when every check of BEP-019 to BEP-024 passes, and Refuse naming the first failing check otherwise
  harness:  kani_redeem_admits_iff_all_checks_pass, same bound and purity constraint as BEP-019

- **BEP-026** IF a request carrying a sealed value arrives from a connection that is not a box attachment on this host THEN THE SYSTEM SHALL refuse the request.
  tier:     T0
  verify:   cargo nextest run -p bep host_shell_connection_is_refused

- **BEP-027** THE SYSTEM SHALL deliver sealed values that `api.github.com` rejects as a credential when presented directly.
  tier:     T0
  verify:   cargo nextest run -p bep --run-ignored ignored-only sealed_value_rejected_by_github

- **BEP-028** WHERE the sending box is `host_ip`, WHEN a request carrying a sealed value that names a live `host_ip` box of this host passes the remaining checks THE SYSTEM SHALL admit it and mark its audit record `cohort_attributed`.
  tier:     T0
  verify:   cargo nextest run -p bep host_ip_redemption_is_cohort_attributed

- **BEP-029** IF a CONNECT names an authority outside the union of the configured modules' host sets and the registered store authorities THEN THE SYSTEM SHALL refuse it and record an audit event marked `off_module`.
  tier:     T0
  verify:   cargo nextest run -p bep connect_outside_modules_is_refused_off_module

- **BEP-030** WHEN a request to a credentialed host carries no sealed value and its authority is admitted by the box's egress THE SYSTEM SHALL forward it unmodified and record an audit event, marked `foreign_credential` when the request carries a credential of its own.
  tier:     T0
  verify:   cargo nextest run -p bep unsealed_request_passes_through_and_is_audited

- **BEP-031** IF a connection arrives for a credentialed hostname on a port outside the module's declared authorities THEN THE SYSTEM SHALL refuse the connection.
  tier:     T2
  verify:   cargo nextest run -p bep prop_off_port_connection_is_refused
  property: for every credentialed hostname, every port and every module authority set, the connection is admitted only when `host:port` is a declared authority
  harness:  kani_redeem_enforces_port_discipline, same bound and purity constraint as BEP-019

Store references

- **BEP-032** WHERE a box declares a `source = "store"` reference matched by a `[secret-store-rules]` rule, WHEN a request from that box to the rule's registered upstream passes the redemption checks THE SYSTEM SHALL inject the referenced Keychain value in the rule's injection form.
  tier:     T0
  verify:   cargo nextest run -p bep store_reference_injects_in_registered_form

- **BEP-033** WHEN a store reference is redeemed THE SYSTEM SHALL read the value from the Keychain for that request and write it to no file.
  tier:     T0
  verify:   cargo nextest run -p bep store_value_read_per_request_never_written

- **BEP-034** IF a `[secret-store-rules]` rule names a deep module's host, Minimal's own infrastructure, or an injection header among `Host`, `Cookie`, `Proxy-*`, `Transfer-Encoding`, `Connection` and `Upgrade` THEN THE SYSTEM SHALL refuse the rule when reading configuration and name it.
  tier:     T0
  verify:   cargo nextest run -p sessions store_rule_in_deny_set_is_refused

- **BEP-035** WHERE the client has no TTY, IF a store reference matches a rule with `action = "ask"` THEN THE SYSTEM SHALL deny the reference.
  tier:     T0
  verify:   cargo nextest run -p sessions ask_rule_without_tty_denies

- **BEP-036** IF a box spec declares a store reference whose registered upstream is not admitted by the box's egress THEN THE SYSTEM SHALL refuse expansion with exit 3 naming the missing host.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_store_upstream_outside_egress_is_exit_3
  property: for every box spec and every registered upstream set, expansion refuses with exit 3 iff some registered upstream is absent from the egress declaration, naming exactly the absent hosts

- **BEP-037** IF a project `minimal.toml` contains a `[secret-store-rules]` section THEN THE SYSTEM SHALL ignore it and emit a warning.
  tier:     T0
  verify:   cargo nextest run -p sessions project_store_rules_are_ignored_with_warning

Setting secrets

- **BEP-050** WHEN `min secret set <id>` is run THE SYSTEM SHALL read the value from the terminal or standard input, store it in the host keychain under `<id>`, and output the identifier and no value.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_set_stores_in_keychain_and_prints_id_only
  - IF the value is supplied as a command-line argument THEN THE SYSTEM SHALL refuse the command and name the terminal and standard input as the accepted sources.
    tier:   T0
    verify: cargo nextest run -p minimal secret_set_refuses_value_argument

- **BEP-051** WHEN `min secret set` stores an item THE SYSTEM SHALL set the item's access control so that the proxy process reads it without a prompt and any other application prompts.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_item_acl_admits_proxy_only

- **BEP-052** WHEN `min secret list` is run THE SYSTEM SHALL output, for each stored identifier, its store, the upstream a `[secret-store-rules]` rule registers for it or that none does, and whether the item is readable, and output no value.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_list_shows_metadata_without_values

- **BEP-053** WHEN `min secret rm <id>` completes THE SYSTEM SHALL have removed the item from the host keychain.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_rm_removes_item

- **BEP-054** WHEN `min secret set <id>` replaces an existing item THE SYSTEM SHALL inject the new value in the next request that redeems a reference to `<id>`, with no restart of the proxy or the box.
  tier:     T0
  verify:   cargo nextest run -p bep replaced_secret_is_injected_on_next_request

Review, audit and revocation

- **BEP-038** WHEN `min box spec` is run for an entry declaring a credentialed upstream THE SYSTEM SHALL render the root CA fingerprint, the derived upstream set for each grant, the resolved steering mode, and each store reference with its registered authorities.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_ca_upstreams_steering_and_references

- **BEP-039** WHEN the proxy admits or refuses a request THE SYSTEM SHALL append one record to the local audit log carrying the box, the authority, the member or store identifier, the mapped resource or `module_unmapped`, the decision and any marker.
  tier:     T0
  verify:   cargo nextest run -p bep every_decision_appends_one_audit_record

- **BEP-040** THE SYSTEM SHALL write no credential, injected header value, or request body to the audit log.
  tier:     T1
  verify:   cargo nextest run -p bep prop_audit_records_never_contain_secrets
  property: for every request carrying a member credential or store value S and every audit record it produces, S is not a substring of the record, and no byte of the request body is

- **BEP-041** THE SYSTEM SHALL open the audit log for append only and modify or remove no existing record.
  tier:     T0
  verify:   cargo nextest run -p bep audit_log_is_opened_append_only

- **BEP-042** WHEN `min box audit <box>` is run THE SYSTEM SHALL output the audit records for that box and no other.
  tier:     T0
  verify:   cargo nextest run -p minimal box_audit_filters_to_one_box

- **BEP-043** WHEN a `min stop` or `min box destroy` of a box completes THE SYSTEM SHALL refuse redemption of every sealed value naming that box within 60 seconds.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_stopped_box_values_refused_within_60s

- **BEP-044** WHEN `min auth logout` completes THE SYSTEM SHALL refuse redemption of every sealed GitHub member on this host within 60 seconds.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_logout_refuses_all_members_within_60s

- **BEP-045** IF a referenced Keychain item has been deleted or disabled THEN THE SYSTEM SHALL refuse the next request that would inject it.
  tier:     T0
  verify:   cargo nextest run -p bep deleted_keychain_item_refuses_next_injection

- **BEP-047** THE SYSTEM SHALL run the proxy and gvproxy as separate processes under distinct OS users sharing no writable state.
  tier:     T0
  verify:   cargo nextest run -p minvmd bep_and_gvproxy_are_separate_processes_and_users

- **BEP-048** WHEN a record is appended to the audit log THE SYSTEM SHALL include in it the hash of the previous record.
  tier:     T0
  verify:   cargo nextest run -p bep audit_record_carries_previous_hash

- **BEP-049** IF an audit log's records were altered or removed THEN THE SYSTEM SHALL report the chain as failing verification.
  tier:     T2
  verify:   cargo nextest run -p bep prop_audit_chain_detects_any_edit
  property: for every sequence of records, the chain built from it verifies, and every sequence obtained by altering or removing one record fails verification
  harness:  kani_audit_chain_detects_edit, exhaustive to 4 records of at most 64 bytes; requires chaining and verification to be pure functions over bytes, separate from the file writer

## Non-goals

- Caching public artifacts through the proxy: a separate story, not yet filed.
- Anthropic and MCP upstream modules; 1Password, LastPass, Linux Secret Service, `pass` and Bitwarden store backends: follow-on epics reusing this document's module and resolver seams (Gatehouse §6.10 store members lists the roster).
- The Gatehouse-hosted proxy, the enrolled `gateway` helper, the tenant secret store and the revocation feed: [GHI](https://github.com/gominimal/gatehouse/pull/1), Gatehouse §6.10, §6.11, §8.6. With a Gatehouse configured, `min` delegates sign-in, minting and sealing to it; nothing here forecloses that and the envelope is the same.
- Repository narrowing of a locally minted GitHub member: an open question below; the enrolled path narrows at mint (Gatehouse §6.4).
- The box-zone resolver, DNS-pinned admission and the `[network]` table's egress fields: [NET](https://github.com/gominimal/minimal/pull/1380) (NET-060, NET-066, NET-072); the table's full schema is gominimal/inbox#570.
- `min secret` against the Gatehouse tenant store (deposits): Gatehouse §8.6 and architecture open item 17; here the noun binds the host keychain only, and the two forms share one grammar.
- The `:7654` hostname proxy's own parity obligations: NET-069 to NET-071.
- A node-local proxy on a SharedLinux host, inside the escape boundary: Gatehouse §6.10, SharedLinux paragraph.
- The execution-facade lane: a separate design.
- Multi-user hosts: the degraded-mode profile assumes a single-operator host (networking design §7.1).

## Non-functional requirements

- **BEP-N01** WHILE forwarding an upstream response THE SYSTEM SHALL relay each received chunk to the box before the response completes.
  tier:   T0
  verify: cargo nextest run -p bep streamed_response_is_not_buffered

## Design reasoning

**One document, one repository.** The work is host-side proxy, CLI and
box-spec surface in one workspace. A sibling in the identity plane for the
delegation seam was considered and set aside: the seam is a non-goal linking
GHI, and GHI's own requirements GHI-021 to GHI-029 are being retargeted in that
pull request, not duplicated here. A sibling for coding-agent guidance was set
aside because guidance has nothing to verify.

**Host-OS-neutral requirements, one module and one store bound.** The
redemption, CA, steering and audit requirements are written over "a module's
host set" and "the host keychain" so a second module or a Linux host fits
without rewording. GitHub is the only module and macOS Keychain the only store
this document instantiates, because the epic scoped the first slice of the
secrets plane to one of each. A macOS-only reading was rejected because it bakes
platform assumptions into the crates the hosted form will import; a generic
store abstraction from day one was rejected because it adds a resolver surface
the demo does not exercise.

**The member is `full` breadth.** A device-flow OAuth token carries OAuth
scopes, not per-repository narrowing; only a GitHub App installation token or a
fine-grained token is repository-narrowed, and neither exists without an App or
a browser step. Two alternatives were considered. Enforcing the repository set
in the proxy by mapping request paths to repositories was rejected because
Gatehouse §6.10 rules that the proxy refuses only on its own invariants and
never on endpoint mapping, and because GraphQL and repository-less endpoints
would be unmapped. Having the user create a fine-grained token in GitHub's UI
and paste it to `min` was rejected because it loses "sign in once". The bound is
therefore the token's OAuth scope and its expiry; the stolen-value story rests
on host and box binding, not on narrowing; and narrowing arrives with Gatehouse
or a later local minting path. The residual is recorded under T28.

**`source = "broker"` names the local grant.** The box spec keeps the
architecture's grammar so a spec is unchanged when the host later enrolls and
the un-enrolled client acts as the broker. Gatehouse §6.2 says that source
fails un-enrolled with `gatehouse_unenrolled_node`; the amendment is proposed in
[gominimal/arch#69](https://github.com/gominimal/arch/issues/69). A new source
value was rejected because it forces every spec to be rewritten at enrollment
and gives two code paths one job.

**Default steering is `dns`, refused until a resolver exists.** The
architecture's default is `dns` and this document keeps it, so a box spec
written today means the same thing after the resolver lands. The cost is that
every demo box writes `steering = "proxy_env"` explicitly and an unadorned
grant fails at expansion naming the missing resolver (BEP-017). Defaulting to
`proxy_env` now and flipping later was rejected because it changes the meaning
of existing specs at the flip; requiring an explicit mode was rejected because
it privileges neither mode and adds a validation error the architecture does
not have.

**Sign-in and audit verbs.** `min auth login | logout | status` follows the
published command tree; the existing `min login`, which today mints a daemon
mTLS client certificate, keeps its meaning until a separate change re-homes it.
`min box audit <box>` is a new verb under the box noun, filed as
gominimal/arch#70, chosen over folding records into `min box events` (a
minimald-authored lifecycle stream) and over `min auth audit` (a poor home for
Keychain references, which are not identity).

**Direct presentation to GitHub is a requirement, verified against GitHub.**
The sealed value is not a GitHub token, so GitHub refuses it. Keeping that as
BEP-027 costs a network test run under `--run-ignored`; dropping it to a
consequence in Security considerations, or verifying it by token-format alone,
was set aside in favour of the observable the story states.

**`NO_PROXY` carries the local zone by default.** `.min.internal`,
`host.min.internal`, loopback and the spec's `no_proxy` entries, so local and
in-box traffic never touches the proxy while everything else non-credentialed
is refused `off_module`, which is the privacy-preferring mode's stated
behaviour. Declaring only the spec's list was rejected because a box that omits
`.min.internal` loses peer previews by name while `proxy_env` is set.

**The audit log is hash-chained.** Append-only alone was the cheaper option and
its residual, host-root edits, is T31's accepted residual on a single-operator
host. Chaining was chosen so the format does not change when the enrolled
helper needs F12's chained audit, and so an edit is detectable now.

**The redemption decision is pure, and proved at T2.** Every check in BEP-019
to BEP-025 and BEP-031 is a decision over owned values, and the tier constrains
the code: the decision is one function, separate from the TLS and socket shell,
with authorities interned as small ids so Kani can exhaust host sets of at most
four authorities and two members. Expansion validation (BEP-008, 009, 017, 036),
name constraints (BEP-013), audit secrecy (BEP-040) and the hash chain (BEP-049)
are property-tested at T1 or T2 for the same reason; T1 adds `proptest` to the
workspace as a dev-dependency. T3 was refused: the repository has no Lean
project, so any T3 is also a toolchain and a CI lane.

**Three-layer CA, key in the keychain.** A root whose certificate is the trust
anchor injected at creation, a signing CA whose non-exportable key lives in the
host keychain (Secure Enclave where the hardware offers it) and rotates freely,
and throwaway leaves per hostname; this is the local reading of Gatehouse §6.10's
per-host name-constrained intermediate, with the root playing the anchor's role.
Requirements state only the observable, BEP-013 and BEP-014.

**`min secret` is the store's front door.** Without it a user drives the OS
keychain by hand, and an item created outside `min` carries no access-control
entry for the proxy, so every redemption prompts on the host; a store reference
is then unusable from an unattended box. `set` reads the value from the
terminal or standard input and refuses an argument, because an argument lands
in shell history and the process table. `list` shows metadata and readability
so a broken reference is diagnosable without the value. Replacing an item is
rotation: the proxy reads per request (BEP-033), so no restart is needed. The
same noun's tenant-store deposit form is the architecture's open item 17; the
grammar here is chosen so that form can share it.

**Prior art.** The `docs/spec-credential-lane` branch's policy gate, resolver
seam, `min session credentials` review surface and the "tasks stop mapping
credentials" fix carry over in intent; its lane endpoint, bearer token store and
path-segment selector do not, because reachability was the authorization and
Gatehouse §12.11 dismissed that shape. The shipped `:7654` Host-header router is
the closest code and the plan decides whether the proxy extends its head-parsing
core or stands beside it.

**Generality:** the requirements hold on any LocalVM host OS and for any
upstream module declaring a host set; GitHub and the macOS Keychain are the
only module and store this document binds, and a second store needs only a
resolver behind the same seam.

## Security considerations

Threat gradient, in the architecture's words and intent (Gatehouse §6.10):
off-host a stolen value is dead, because without this host's key it does not
decrypt and without a box attachment it cannot reach the redemption listener;
cross-box on `own_ip` it is dead by attribution; co-resident on `host_ip` it is
usable within the member's own bound, fully audited, until expiry or
revocation, and for a `full` member that is the signed-in account's whole reach
until expiry (at most 8 hours), which is why `full` members belong on `own_ip`
placements (T28). A remote accomplice must relay whole flows into the
compromised box, the irreducible floor, now scoped, audited and revocable. The
baseline this replaces, a raw token in the box environment usable from anywhere
for its full TTL, is retired in every mode.

Residuals recorded: T28 for `host_ip` cohort attribution; T31 for host-OS
compromise, which on a single-operator laptop is compromise of the operator's
own machine, reaching the signing key by use but not export, and the audit log
only detectably; T32 for store-reference abuse, bounded by the client-owned
rules, the deny set and per-request Keychain access control.

- **Invariant:** THE SYSTEM SHALL place no plaintext credential in a box's environment, files or volumes.
  enforced by: sealing at mint; delivery of the sealed value only
  covered by: BEP-002, BEP-007, BEP-033

- **Invariant:** THE SYSTEM SHALL redeem a sealed value only on this host and only from the box it names.
  enforced by: host key binding; box attribution from the switch's source address
  covered by: BEP-019, BEP-020, BEP-026, BEP-028

- **Invariant:** THE SYSTEM SHALL substitute a credential only into a request whose connection authority and `Host` are one declared authority of its module or registration.
  enforced by: host-set membership, request-authority pinning, port discipline, name-constrained CA
  covered by: BEP-013, BEP-021, BEP-023, BEP-031, BEP-032

- **Invariant:** THE SYSTEM SHALL admit no credentialed reach that the box's declared egress denies.
  enforced by: full-set validation at expansion; egress re-check at redemption
  covered by: BEP-008, BEP-022, BEP-036

- **Invariant:** THE SYSTEM SHALL write no credential to any log, spec rendering or diagnostic bundle.
  enforced by: audit record construction from the decision only; `min box spec` and `min secret` render identifiers and references only
  covered by: BEP-004, BEP-038, BEP-040, BEP-050, BEP-052

- **Invariant:** THE SYSTEM SHALL hold the signing key and store access only in the proxy process.
  enforced by: process separation; keychain access control bound to the proxy's identity
  covered by: BEP-014, BEP-047, BEP-051

- **Invariant:** THE SYSTEM SHALL stop redeeming a revoked or expired value within 60 seconds.
  enforced by: expiry in the sealed context; revocation set consulted per request
  covered by: BEP-024, BEP-043, BEP-044, BEP-045

Architecture threats this document must hold: T28, T31, T32 (Gatehouse §11);
AT7 and AT25 (architecture threat model).

## Open questions

- [NEEDS CLARIFICATION (HIGH): How does a locally minted GitHub member become repository-narrowed without a GitHub App? Until it is, the member is `full` breadth (Design reasoning) and the T28 residual is the signed-in account's whole reach for at most 8 hours; tracked with gominimal/arch#69.]
- [NEEDS CLARIFICATION (MEDIUM): gominimal/arch#69 proposes amending Gatehouse §6.10's un-enrolled bullet and §6.2's `gatehouse_unenrolled_node` rule so an un-enrolled client may mint and seal GitHub members. If the owner rules otherwise, BEP-001 to BEP-007 move behind enrollment and the first slice becomes Keychain references only.]
- [NEEDS CLARIFICATION (MEDIUM): Does every intended client accept the sealed handle as its bearer unmodified? Claude Code with an OAuth token and MCP clients send `Authorization: Bearer <value>`, which BEP-032 substitutes, but a client that validates token shape before sending, or sends the credential in a header the rule does not name, needs the harness adapter (gominimal/inbox#345); unmeasured, a plan spike.]
- [NEEDS CLARIFICATION (MEDIUM): On a Linux LocalVM host, which key store holds the signing CA key as non-exportable (TPM 2.0 via a PKCS#11 provider, or Secret Service without hardware backing)? BEP-014 is written over "the host keychain"; the plan carries a spike, and until it lands the Linux host is unverified for BEP-014.]
