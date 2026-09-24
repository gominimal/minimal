---
id: BEP
title: Local Box Egress Proxy — sealed GitHub credentials and host-store secrets without Gatehouse
owner: norrietaylor
epic: gominimal/inbox#625
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-23
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
outside the VM, and that an un-enrolled client mints GitHub-module members from
its own GitHub sign-in under a Minimal-published GitHub App (Gatehouse F19,
§6.10 un-enrolled bullet; [networking design
§7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).
Gatehouse v1.23 made that member a reference to the sign-in, resolved and
renewed at the proxy on each request, so a box's credentials work for its life
within the credentialed lane's ceiling; v1.24
gave an un-enrolled box a per-creation id, scoped revocation to that id, and
made the proxy's address infrastructure for a box with a credentialed lane
(networking design v0.8.3); v1.25 ruled which HTTP versions the proxy carries
and conditioned `quic443`'s `auto` on the steering mode (networking design v0.9
§5.3, §5.7). The Gatehouse-hosted path lands with the identity plane's fifth phase
([GHI](https://github.com/gominimal/gatehouse/pull/1)); until then an
un-enrolled laptop has no credential path. The local-first ordering decided on
2026-09-15 puts that laptop first.

This document binds the un-enrolled form: a host-side proxy beside gvproxy that
terminates TLS only for a box's declared credentialed upstream hosts under a
host-generated, name-constrained CA the box can see in its spec; substitutes
sealed references to a local GitHub sign-in and to Keychain secrets by
identifier; re-checks the box's declared egress; and audits every decision
to a local log. The surfaces are the `min` CLI (`min auth`, `min secret`, `min
box spec`, `min box audit`), the box spec (`[network.bep]`, `quic443`,
`[secrets]`, the client's `[secret-store-rules]` and its full-breadth
acknowledgement), the box host's session creation, and the proxy itself.

**Success:** in a box that holds no plaintext credential anywhere in its
environment, files or volumes, `git clone`, `git push` and `gh api` against a
private repository of the signed-in account succeed; the same sealed value
copied to the host shell or into another box is refused; and every admit and
refuse is readable per box.

**First slice:** `proxy_env` steering, the GitHub v1 host set (Gatehouse §6.10
Module host sets: `github.com`, `api.github.com`, `uploads.github.com`,
`codeload.github.com`; pre-signed content hosts such as
`release-assets.githubusercontent.com` stay ordinary egress) as the one
module, a sealed reference to the device-flow `min auth login` sign-in, redemption
with every check, the local audit log with its one-shot `min box audit <box>`
read, and `min box spec` showing the CA and the upstream set. The
demo box declares `github:user-token`, the honest spelling of a `full` member,
so the slice also exercises `min box spec`'s `full` marker (BEP-038). Keychain
references with `min secret`, `dns` steering, the browser sign-in flow, `min box
audit --follow` and `--parent`, audit segment rotation, signing-CA rotation, the
PAC recipe and `host_ip` cohort handling are later slices.

## Users and stories

**Roles:** developer on an un-enrolled laptop, developer working in a box, developer reviewing what a box may reach

- AS A developer using Minimal on a laptop with no Gatehouse, I WANT to sign in to GitHub once with `min`, SO THAT every box I start afterwards can reach my repositories without me handling a token.
- AS A developer who signed in yesterday, I WANT today's boxes, and the boxes I left running overnight, to have working GitHub credentials without signing in again or re-creating anything, SO THAT the 8-hour life of a GitHub token asks nothing of me.
- AS A developer working in a box, I WANT `git clone`, `git push` and `gh` to work against my repositories, SO THAT I do real work without configuring any tool.
- AS A developer with an API key in my macOS Keychain, I WANT to reference it by identifier in a box spec, SO THAT requests from the box to that key's upstream carry it without the key entering the box.
- AS A developer with a third-party API key, such as a Claude OAuth token or an MCP server credential, I WANT to store it once with `min secret`, SO THAT box specs reference it by identifier and its value never appears in `min` output, a spec, or a box.
- AS A developer, I WANT the proxy to refuse any use of a sealed or referenced secret outside its declared authority, SO THAT a compromised workload cannot redirect my credential.
- AS A developer, I WANT a sealed value copied out of a box to be worthless anywhere else, SO THAT exfiltration of the box environment yields nothing usable.
- AS A developer reviewing what a box may reach, I WANT the expanded box spec to show the interception CA and the derived credentialed upstream set, SO THAT interception is declared, not discovered.
- AS A developer, I WANT to read what the proxy admitted and refused, SO THAT I can see what my agents did with my credentials.
- AS A developer, I WANT to revoke a session's credentials, SO THAT a value already delivered stops working and nothing I create afterwards is affected.
- AS A developer who signs out, I WANT every box's GitHub credentials to stop working at once and a later sign-in to revive none of them, SO THAT signing out is the host-wide stop it looks like.
- AS A developer who removes a box and creates another under the same name, I WANT the new box's credentials to work, SO THAT a revocation stays with the box it was made for, not with its name.

## Requirements

Sign-in

- **BEP-001** WHERE no Gatehouse is configured, WHEN `min auth login` is run with `--device`, or with no flow flag while no browser flow is shipped, THE SYSTEM SHALL complete the GitHub device flow under the Minimal-published GitHub App and report the signed-in account.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_login_completes_device_flow_and_reports_account
  <!-- Gatehouse §6.10 un-enrolled bullet: device flow is the reference profile; the App's registration is the member's ceiling; the verb keeps the command tree's shape, `--device` pinning the device flow, the bare verb the browser flow wherever one exists (Design reasoning) -->
  - WHERE the browser flow is shipped, WHEN `min auth login` is run with no flow flag THE SYSTEM SHALL complete the authorization-code flow with PKCE under the same App and report the signed-in account.
    tier:   T0
    verify: cargo nextest run -p minimal auth_login_completes_browser_pkce_flow
    <!-- additive, a later slice; the embedded public client secret is a recorded decision, rationale in Gatehouse §6.10; the bare verb moves to this flow when it lands, and a script that needs the device flow says `--device` -->

- **BEP-002** WHEN a GitHub sign-in completes THE SYSTEM SHALL store the token and refresh material in one host keychain item and in no file under the project or the box.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_login_stores_material_in_keychain_only
  <!-- Gatehouse §6.10 un-enrolled bullet (v1.23): the sign-in is a host-keychain item and the member a box holds is a reference to it (BEP-005) -->
  - WHEN a sign-in completes and no sign-in item is held THE SYSTEM SHALL give the item an instance identifier no earlier item on this host carried.
    tier:   T0
    verify: cargo nextest run -p minimal a_sign_in_with_no_held_item_is_a_new_instance
    <!-- first sign-in, any sign-in after a logout, and a different account are new instances; references bind the identifier, so a reference that logout refused never names a later sign-in (BEP-044) -->
  - WHEN a sign-in to the held item's account completes while the item is held THE SYSTEM SHALL replace the item's token and refresh material in place and keep its instance identifier.
    tier:   T0
    verify: cargo nextest run -p minimal re_login_to_the_same_account_keeps_the_instance
    <!-- event-driven; a host whose refresh material lapsed (6 months) heals its running boxes by signing in again, with no re-creation -->

- **BEP-003** WHILE a GitHub sign-in is held, WHEN a box declaring a GitHub grant is created THE SYSTEM SHALL create it without prompting for sign-in.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_second_box_needs_no_sign_in
  - IF a box declaring a GitHub grant is created while no GitHub sign-in is held THEN THE SYSTEM SHALL fail the creation with the defined error `github_sign_in_required` and not prompt for sign-in.
    tier:   T0
    verify: cargo nextest run -p sessions creation_without_sign_in_fails_with_defined_error
    <!-- Gatehouse §6.2 v1.20 leaves the error name to this document; distinct from `gatehouse_unenrolled_node`, which stays the refusal where no proxy exists -->

- **BEP-004** WHEN `min auth status` is run THE SYSTEM SHALL report whether a GitHub sign-in is held and its expiry, and output no token value.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_status_reports_expiry_without_token
  - WHERE the held token has expired and its refresh material has not, WHEN `min auth status` is run THE SYSTEM SHALL report that the sign-in renews at the proxy on the next request that uses it.
    tier:   T0
    verify: cargo nextest run -p minimal auth_status_reports_renewal_of_expired_sign_in
    <!-- status reads the item's metadata; the client neither presents nor refreshes the token (BEP-069) -->

- **BEP-069** WHEN a request redeeming a sign-in reference passes every redemption check and the held token has expired or expires within 5 minutes THE SYSTEM SHALL renew the sign-in from its refresh material, write the renewed token and refresh material to the same keychain item, and substitute the renewed token.
  tier:     T0
  verify:   cargo nextest run -p bep an_expiring_sign_in_is_renewed_at_the_proxy
  <!-- Gatehouse §6.10 Resolution and renewal (v1.23): GitHub revokes the prior token and refresh token at each renewal, which is harmless only because the proxy is the token's sole consumer; a device-flow sign-in renews with no client secret, a browser-flow one under the embedded published-App secret; the renewal is the proxy's one keychain write and is audited as its own event -->
  - THE SYSTEM SHALL present and renew the GitHub token at the proxy alone; after sign-in the client reads only the item's metadata.
    tier:   T0
    verify: cargo nextest run -p minimal client_never_presents_or_refreshes_the_token
    <!-- ubiquitous; the sole-consumer invariant; creation needs a held sign-in, never a live token (BEP-003) -->
  - WHILE a renewal of a sign-in item is in flight, WHEN another request needs that item THE SYSTEM SHALL wait for that renewal's outcome and not renew again.
    tier:   T0
    verify: cargo nextest run -p bep concurrent_redemptions_share_one_renewal
    <!-- state-driven; single-flight per item, because GitHub's refresh grant is single-use and a second renewal from the same refresh material fails -->
  - IF the renewed token and refresh material cannot be written to the item THEN THE SYSTEM SHALL refuse the request and substitute nothing.
    tier:   T0
    verify: cargo nextest run -p bep renewal_not_persisted_is_refused
    <!-- unwanted; persist before first substitution; a crash between renewal and write strands the sign-in, and signing in again recovers it (BEP-002) -->
  - IF the item has been deleted when a renewal would write it THEN THE SYSTEM SHALL discard the renewed material, refuse the request, and create no item.
    tier:   T0
    verify: cargo nextest run -p bep renewal_finding_item_deleted_refuses_and_creates_nothing
    <!-- unwanted; the write is update-only, so a logout during a renewal stays a logout (BEP-044) -->
  - IF the held token expires more than 5 minutes after the request THEN THE SYSTEM SHALL substitute it without renewing.
    tier:   T0
    verify: cargo nextest run -p bep a_sign_in_with_time_to_live_is_not_renewed
    <!-- unwanted; Gatehouse leaves the window as "a short window of expiry"; 5 minutes is this document's -->
  - IF the held token has expired and GitHub refuses the renewal, or the refresh material has expired too THEN THE SYSTEM SHALL refuse the request and record an audit event marked `github_sign_in_required` until the sign-in is renewed by signing in again.
    tier:   T0
    verify: cargo nextest run -p bep unrenewable_sign_in_refuses_with_sign_in_required
    <!-- the §6.2 sign-in-required error, here an audited redemption marker; BEP-002's same-account sign-in heals the running boxes -->

Minting and sealing

- **BEP-005** WHERE the host is not enrolled, WHEN a box declaring a `source = "broker"` GitHub grant is created THE SYSTEM SHALL mint a `mode = "user"` member of `full` breadth that is a sign-in reference and carries no token: a handle signed under the client's local key naming the held sign-in item and its instance identifier, with the module's authorities as its upstream set, no injection form, and an expiry equal to the root CA's remaining validity at the mint.
  tier:     T0
  verify:   cargo nextest run -p minimal local_member_is_a_sign_in_reference_expiring_with_the_root
  <!-- Gatehouse §6.10 un-enrolled bullet (v1.23): the member is `{kind: "signin", breadth: "full", jws}` in the store-handle wire format (BEP-063); its expiry is the box's credentialed-lane ceiling, the injected anchor's remaining validity (the durations are an open question below), so the member works for the life of the box within it; the GitHub module stands as its registration (BEP-064) -->

- **BEP-006** WHEN a GitHub member is minted THE SYSTEM SHALL seal it to this host's proxy key with the box's id, the host, the module identifier, the host-set version, the mode and the expiry bound in the authenticated context, and the member's breadth in the authenticated plaintext.
  tier:     T0
  verify:   cargo nextest run -p bep sealed_context_binds_box_host_module_version_expiry
  <!-- the module's host set and its version are Gatehouse §6.10's (Module host sets): the v1 GitHub set is `github.com`, `api.github.com`, `uploads.github.com` and `codeload.github.com`, enumerated and versioned by the module definition; every "host set" in this document reads there; the box id names one creation (BEP-070), which is all a revocation needs to name (BEP-071), so the context stays member-invariant; per-member bounds, `breadth` included, ride the plaintext so a change of member cardinality touches the plaintext alone (Gatehouse §6.10 Sealed secret) -->

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
  - IF a box spec declares `steering = "off"` and `[network.bep] proxy_env = true` THEN THE SYSTEM SHALL refuse the expansion with exit 3 naming both fields.
    tier:   T0
    verify: cargo nextest run -p sessions steering_off_with_proxy_env_is_refused
    <!-- design §5.4 composes `proxy_env` with any steering mode, but `off` also disables CA injection, so an environment pointing at the proxy would fail every TLS handshake; the combination is unbuildable and is refused rather than warned -->

- **BEP-056** WHERE the host is not enrolled, IF a box spec declares a GitHub grant with `mode = "installation"` THEN THE SYSTEM SHALL refuse expansion with exit 3 naming the grant.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_installation_mode_unenrolled_is_exit_3
  property: for every box spec on an un-enrolled host, expansion refuses with exit 3 iff a GitHub grant declares `mode = "installation"`
  <!-- Gatehouse §6.10 Validation, un-enrolled: no App private key exists locally -->

- **BEP-057** WHERE the host is not enrolled, IF a box spec declares a GitHub grant whose `github:repo:*` scopes are narrower than `full` and the client configuration does not acknowledge full-breadth minting THEN THE SYSTEM SHALL refuse expansion with exit 3 naming the grant and the acknowledgement as the remedy.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_narrow_scopes_unenrolled_need_acknowledgement
  property: for every box spec on an un-enrolled host and every client configuration, expansion refuses with exit 3 iff some GitHub grant declares scopes narrower than `full` and the acknowledgement is unset
  <!-- Gatehouse §6.10 Validation, un-enrolled: the declared bound cannot be honored locally until local narrowing lands, and a warning would be the silent widening §6.4 forbids -->
  - WHERE the user-level or organization-level client configuration sets `[secrets] acknowledge_full_breadth_unenrolled = true` THE SYSTEM SHALL mint the member `full` and render it as `full` in `min box spec` with the acknowledgement visible and stating that it covers the member's reach for the box's life, within the credentialed lane's ceiling.
    tier:   T0
    verify: cargo nextest run -p minimal acknowledged_narrow_grant_renders_full
    <!-- the field name is this document's; the architecture carries it as a placeholder; Gatehouse v1.23 extends the acknowledgement to the reference's box-lifetime reach, so the rendering names that window, not the 8-hour token it replaced -->
  - IF a project `minimal.toml` sets the acknowledgement THEN THE SYSTEM SHALL ignore it and emit a warning.
    tier:   T0
    verify: cargo nextest run -p sessions project_acknowledgement_is_ignored_with_warning
    <!-- never project-supplied, so the declared scopes are honored unchanged the moment the host enrolls -->

Steering and the interception CA

- **BEP-011** WHERE a box declares a credentialed upstream and its steering is not `off`, WHEN the box is created THE SYSTEM SHALL add the host root CA certificate, the self-signed anchor that carries the name constraints, to the box's OS trust store in both standard forms, appended to the CA bundle and linked in the hashed certificate directory under its subject hash, beside the system roots.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_root_ca_present_in_box_trust_store
  <!-- Gatehouse §6.10 trust-store injection: the bundle alone is invisible to OpenSSL built with a certificate directory and no bundle file, and the directory alone to bundle readers such as Go and GnuTLS; additive, because the proxy terminates only credentialed flows and every other flow validates against the system roots; the box host writes and the image reads; a box's trust store does not change after its creation, because Gatehouse §6.10 makes it a per-box snapshot no re-certification rewrites and gives an un-enrolled root replacement no overlap window (BEP-013, BEP-060) -->
  - WHERE a box declares no credentialed upstream, or its steering is `off`, THE SYSTEM SHALL keep the root out of the box's trust store, whichever other boxes on the host were created from the same packages.
    tier:   T0
    verify: ./scripts/session-e2e.sh bep_root_ca_absent_from_box_without_credentialed_upstream
    <!-- trust injected only where declared (Gatehouse T27); the bundle a box reads can be the package store's own copy, and writing the root into that copy would put it in every box built from the package -->
  - WHERE the root is injected, WHEN the box is created THE SYSTEM SHALL set `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` to the box's CA bundle and `NODE_EXTRA_CA_CERTS` to the root.
    tier:   T0
    verify: ./scripts/session-e2e.sh bep_trust_env_points_at_bundle_and_root
    <!-- Gatehouse §6.10 trust-store injection's environment block, carried there as [proposed]: making it normative was considered and declined (Gatehouse v1.22), so the architecture's guarantee covers OS-trust-store readers alone and this document builds the proposed block; if the architecture ratifies a different variable list, this requirement follows it; the block serves stacks that keep a store of their own; Node reads no OS store, so a Node client such as Claude Code refuses every leaf without it; the list is maintained with the package set, and the JVM keystore is outside it -->
  - IF a box spec's environment sets one of those variables THEN THE SYSTEM SHALL keep the spec's value and emit a validation warning naming the variable.
    tier:   T0
    verify: cargo nextest run -p sessions spec_trust_env_shadows_platform_with_warning

- **BEP-012** WHERE a box's steering is `proxy_env` or `both`, or its `[network.bep] proxy_env` is true, WHEN the box is created THE SYSTEM SHALL set `HTTPS_PROXY` and `HTTP_PROXY` in the box environment to the proxy's address and set `NO_PROXY` to `.min.internal`, `host.min.internal`, `localhost`, `127.0.0.1` and the box's `[network.bep] no_proxy` entries.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_proxy_env_and_no_proxy_are_set

- **BEP-013** WHEN a box connects to an admitted credentialed hostname through the proxy THE SYSTEM SHALL present a leaf certificate for that hostname that chains through the host's one signing CA to the host root CA, whose name constraints equal the union of the configured modules' host sets and the authorities the operator's `[secret-store-rules]` register, less the fixed deny set.
  tier:     T1
  verify:   cargo nextest run -p bep prop_root_constraints_equal_registered_union
  property: for every family of module host sets and registered authorities on a host, the root's permitted-names constraint equals their union less the deny set, a leaf for a name in the union validates against the root alone, a leaf for any name outside the subtrees the union permits fails validation, and the proxy issues leaves for names in the union alone
  <!-- Gatehouse §6.10 per-node interception CA and trust-store injection: the constraints come from the host's registrations, never a spec-chosen name, and sit on the self-signed anchor itself; one keychain-held signing CA per host (BEP-014, BEP-059 to BEP-061), not one per box; X.509 permitted subtrees admit a name's subdomains (RFC 5280 §4.2.1.10), so exact admission is by leaf issuance, never by the constraint alone; a box's own reach within the union is bounded by its egress declaration (BEP-022) and its sealed values' host sets (BEP-021); a rule's authority written with no port is port 443 -->
  - WHEN the registered authorities change THE SYSTEM SHALL re-issue the root under the same key and subject with the changed constraints, and leave every running box's trust store as it was.
    tier:   T0
    verify: cargo nextest run -p bep root_recertified_under_same_key_and_subject
    <!-- Gatehouse §6.10: re-certification is not rotation; a running box keeps validating the names its root already permitted and reaches an added authority once re-created; the certificates below the root carry a key-identifier-only authority key identifier, so they chain to either issue of it -->

- **BEP-014** THE SYSTEM SHALL hold the signing CA private key in the host keychain as a non-exportable key and write it to no file.
  tier:     T0
  verify:   cargo nextest run -p bep signing_key_is_non_exportable_and_has_no_file

- **BEP-059** THE SYSTEM SHALL generate the proxy's sealing key and the root CA key non-exportable on the host, hold them in the host keychain across proxy restarts, and write them to no file.
  tier:     T0
  verify:   cargo nextest run -p bep sealing_and_root_keys_persist_non_exportable
  <!-- Gatehouse §6.10 un-enrolled lifecycle and the hardware-backed custody bullet -->

- **BEP-072** THE SYSTEM SHALL publish the sealing key's public half, the key fingerprints a sealed context binds and the root certificate where the operator's processes read them, and seal every value from that published material without opening the proxy's key store.
  tier:     T0
  verify:   cargo nextest run -p bep a_value_sealed_to_the_published_identity_unseals_under_the_keys
  <!-- ubiquitous; sealing is public-key work; a client that opened the store would be refused keys the keychain admits to the proxy alone, or would generate keys the proxy cannot use; this is how the custody invariant holds on the client's side -->
  - IF the published material does not parse as a key of the role it is published under THEN THE SYSTEM SHALL refuse to seal and name the role.
    tier:   T0
    verify: cargo nextest run -p bep a_published_identity_carrying_no_key_is_refused_by_role

- **BEP-060** THE SYSTEM SHALL replace the sealing key or the root CA only on an explicit operator command, and never on restart.
  tier:     T0
  verify:   cargo nextest run -p bep keys_never_regenerated_on_restart
  <!-- Gatehouse §6.10 un-enrolled lifecycle: replacement is never a silent overlap failure -->
  - WHEN the sealing key or the root CA is replaced THE SYSTEM SHALL refuse every member sealed to the previous key and report that running boxes holding one are re-created to re-mint.
    tier:   T0
    verify: cargo nextest run -p bep key_replacement_kills_outstanding_members
    <!-- the recreate-to-re-mint rule of Gatehouse §8.3 -->
  - IF the host keychain refuses the proxy a key it holds for the proxy THEN THE SYSTEM SHALL refuse to start and name `bep --replace-key` with the role of each refused key.
    tier:   T0
    verify: cargo nextest run -p bep refused_key_names_the_replacement_command
    <!-- unwanted; the keychain admits a key to the program that generated it, so a rebuilt proxy is a different program and is refused its predecessor's keys; the replacement is this requirement's operator command, and it runs without the files a serving proxy reads, since the case it exists for is a proxy that will not start -->

- **BEP-061** WHEN the signing CA rotates under an unchanged root THE SYSTEM SHALL keep every running box's trust anchor valid with no change inside the box.
  tier:     T0
  verify:   cargo nextest run -p bep signing_ca_rotation_invisible_to_boxes

- **BEP-015** WHILE a box with steering `proxy_env` holds a sealed GitHub member THE SYSTEM SHALL complete `git clone`, `git push` and `gh api` against a private repository of the signed-in account with no tool configuration in the box beyond what the box carries at creation.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_git_and_gh_against_private_repo
  <!-- a clone's pack fetch is served by `github.com` itself over the smart HTTP protocol, inside the host set; archive downloads redirect to `codeload.github.com`, also inside the host set; release assets redirect to `release-assets.githubusercontent.com`, ordinary egress a box lists in `[network.bep] no_proxy` under `proxy_env` (Gatehouse §6.10: `NO_PROXY` is the compatibility lever) -->

- **BEP-016** WHERE a box spec declares a credentialed upstream and no `steering` THE SYSTEM SHALL resolve `steering` to `dns`.
  tier:     T0
  verify:   cargo nextest run -p sessions steering_defaults_to_dns

- **BEP-017** WHILE the host has no box-zone resolver, IF a box spec's resolved steering is `dns` or `both` and it declares a credentialed upstream THEN THE SYSTEM SHALL refuse expansion with exit 3 naming the missing resolver.
  tier:     T1
  verify:   cargo nextest run -p sessions prop_dns_steering_without_resolver_is_exit_3
  property: for every box spec declaring a credentialed upstream, on a host with no box-zone resolver, expansion refuses iff the resolved steering is `dns` or `both`

- **BEP-018** WHILE a box's resolved `quic443` stance is blocked, IF the box sends UDP to port 443 THEN THE SYSTEM SHALL reject the datagram with ICMP port unreachable.
  tier:     T0
  verify:   cargo nextest run -p minimald quic443_blocked_rejects_udp_443
  <!-- networking design §5.3 (v0.9): an active reject, never a silent drop, so a client falls back to TCP at once (§5.7's determinism rule); the stance governs the resolver-bypass path -->
  - THE SYSTEM SHALL resolve `quic443 = "auto"` to blocked exactly when the box declares a credentialed upstream and its resolved steering is `dns` or `both`, and to allowed otherwise.
    tier:   T1
    verify: cargo nextest run -p sessions prop_quic443_auto_resolves_on_grants_and_steering
    property: for every `quic443` value, credentialed-upstream set and steering mode, the resolved stance is blocked iff the value is `block`, or the value is `auto`, the set is non-empty and the steering is `dns` or `both`
    <!-- ubiquitous; Gatehouse §6.3.2/§6.11 (v1.25): under `proxy_env` or `off` nothing is steered at a TCP-only listener, so the block bought neither interception coverage nor fallback determinism -->
  - IF a box sends UDP to port 443 toward the steered proxy address THEN THE SYSTEM SHALL reject it with ICMP port unreachable, whatever the box's stance.
    tier:   T0
    verify: cargo nextest run -p minimald udp_443_to_steered_proxy_rejected_in_every_stance
    <!-- unwanted; networking §5.3 (v0.9): the proxy has no QUIC listener, and `allow` re-opens resolver-bypass QUIC only -->
  - WHERE boxes share the `host_ip` cohort address THE SYSTEM SHALL block UDP to port 443 for the cohort when any resident member's resolved stance is blocked.
    tier:   T0
    verify: cargo nextest run -p minimald host_ip_cohort_quic_stance_most_restrictive_wins
    <!-- networking §5.3 (v0.9): most-restrictive-wins on the shared address, a grant-holding member costing its cohort HTTP/3; `own_ip` stances hold per box -->

- **BEP-078** WHERE a box's steering is `dns` or `both`, WHEN the box asks for an AAAA, HTTPS (type 65) or SVCB (type 64) record of a steered name THE SYSTEM SHALL answer NODATA.
  tier:     T0
  verify:   cargo nextest run -p minimald steered_name_aaaa_https_svcb_are_nodata
  <!-- networking §5.3 and §5.7 (v0.9): an HTTPS record would advertise `alpn="h3"` and endpoint hints for a name whose only reachable endpoint is the TCP-only proxy; with BEP-076's `Alt-Svc` strip it keeps clients from caching "this name speaks h3" -->

- **BEP-062** WHILE the proxy's listener is not live, WHEN a box with `dns` or `both` steering resolves a credentialed hostname THE SYSTEM SHALL answer SERVFAIL.
  tier:     T0
  verify:   cargo nextest run -p minimald steered_name_servfail_while_proxy_down
  <!-- fail closed: a steered name never falls back to real DNS, so the egress re-check and the audit record are never skipped; under `proxy_env` a dead listener reaches nothing already -->

HTTP versions and framing

- **BEP-073** WHEN the proxy terminates a box's TLS THE SYSTEM SHALL offer `http/1.1` alone in ALPN and carry the request to the upstream over HTTP/1.1.
  tier:     T0
  verify:   cargo nextest run -p bep proxy_offers_http11_only_on_both_legs
  <!-- networking §5.7 (v0.9): h2 header insertion is full termination, since HPACK's dynamic table is connection-scoped; clients offering `h2, http/1.1` downgrade silently; a client requiring h2 in ALPN, gRPC libraries among them, gets a handshake refusal, the recorded v1 limit (Non-goals) -->

- **BEP-074** IF a request on a terminated flow opens with the HTTP/2 prior-knowledge preface THEN THE SYSTEM SHALL close the connection.
  tier:     T0
  verify:   cargo nextest run -p bep h2_prior_knowledge_preface_is_closed
  - IF a request carries `Upgrade: h2c` THEN THE SYSTEM SHALL remove it, its `Connection` token and `HTTP2-Settings`, and handle the request as HTTP/1.1.
    tier:   T0
    verify: cargo nextest run -p bep h2c_upgrade_is_stripped
    <!-- networking §5.7: the same rule as the `:7654` proxy's (NET-135) -->

- **BEP-075** WHERE a box's steering is `proxy_env` or its `[network.bep] proxy_env` is true, THE SYSTEM SHALL accept CONNECT and absolute-form plain HTTP requests over HTTP/1.1 only, and refuse Extended CONNECT and `connect-udp` in either form.
  tier:     T0
  verify:   cargo nextest run -p bep connect_and_absolute_form_accepted_over_http11_only
  <!-- networking §5.7's `proxy_env` row: h3 through an HTTP proxy exists only as MASQUE, absent in v1; an accepted tunnel's inner TLS is terminated under BEP-073; either form naming a target outside the module host sets is refused `off_module` (BEP-029), and an absolute-form request to a credentialed host is refused `upstream_not_tls` (BEP-055) -->

- **BEP-076** WHEN the proxy relays an upstream response THE SYSTEM SHALL remove every `Alt-Svc` header from it.
  tier:     T0
  verify:   cargo nextest run -p bep alt_svc_is_stripped_from_responses
  <!-- networking §5.7 h3 discovery suppression, the response-side half of BEP-078 -->

- **BEP-077** WHEN the proxy forwards a request THE SYSTEM SHALL forward a canonical re-serialization of the parsed request and never the box's head bytes.
  tier:     T1
  verify:   cargo nextest run -p bep prop_forwarded_head_is_canonical
  property: for every request head the parser accepts, the forwarded head is the canonical serialization of the parsed request, and parsing it again yields the same request
  <!-- networking §5.7 framing discipline (normative): without it a box authoring ambiguous framing desyncs the proxy's parser from the upstream's, and bytes audited as body arrive upstream as a request the audit never saw and the authority pinning never checked -->
  - IF a request carries `Content-Length` together with `Transfer-Encoding`, duplicate or conflicting `Content-Length` values, an obsolete line fold, or a transfer coding other than a final `chunked` THEN THE SYSTEM SHALL close the connection and record an audit event marked `framing_ambiguous`.
    tier:   T1
    verify: cargo nextest run -p bep prop_ambiguous_framing_is_refused
    property: for every request head, the proxy forwards it only when its framing is unambiguous under the rules listed, and refuses and audits it otherwise
  - THE SYSTEM SHALL carry each box's requests on upstream connections no other box's requests use.
    tier:   T0
    verify: cargo nextest run -p bep upstream_connections_never_shared_across_boxes
    <!-- ubiquitous; networking §5.7 -->

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

- **BEP-023** IF a request's `Host` header, or the authority of an absolute-form request target, differs from the connection authority it arrived on THEN THE SYSTEM SHALL refuse the request before substitution.
  tier:     T2
  verify:   cargo nextest run -p bep prop_host_header_mismatch_is_refused
  property: for every connection authority, every `Host` value and every request-target authority (the connection authority itself for an origin-form request), substitution happens only when all three are equal
  harness:  kani_redeem_pins_request_authority, same bound and purity constraint as BEP-019

- **BEP-024** IF a sealed value's expiry has passed, or a revocation in force covers it (BEP-071) THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_expired_or_revoked_value_is_refused
  property: for every sealed value, every clock reading and every revocation set, redemption admits only when the clock is before the value's expiry and no revocation in the set covers the value
  harness:  kani_redeem_refuses_expired_or_revoked, same bound and purity constraint as BEP-019

- **BEP-058** IF a sealed member carries no `mode` or no `breadth`, or a `breadth` the proxy does not recognise THEN THE SYSTEM SHALL refuse the request.
  tier:     T2
  verify:   cargo nextest run -p bep prop_member_without_bounds_is_refused
  property: for every sealed member, redemption admits only when the member carries a `mode` and a recognised `breadth`
  harness:  kani_redeem_refuses_unbounded_member, same bound and purity constraint as BEP-019
  <!-- Gatehouse §6.4 makes `breadth` required and fail-closed; the local envelope is the same by ruling -->

- **BEP-025** WHEN a request carrying a sealed value passes every redemption check THE SYSTEM SHALL replace the sealed value with the member's credential and forward the request to the connection authority.
  tier:     T2
  verify:   cargo nextest run -p bep prop_admit_iff_every_check_passes
  property: for every redemption input, the decision is Admit exactly when every check of BEP-019 to BEP-024, BEP-031, BEP-058 and BEP-064 passes, and Refuse naming the first failing check otherwise
  harness:  kani_redeem_admits_iff_all_checks_pass, same bound and purity constraint as BEP-019

- **BEP-055** WHEN the proxy opens the upstream connection for a flow it terminated THE SYSTEM SHALL validate the upstream certificate chain and hostname against the host's trust store, never against the interception root, before forwarding any request on it or substituting any credential.
  tier:     T1
  verify:   cargo nextest run -p bep prop_upstream_tls_validated_before_substitution
  property: for every upstream chain and every connection authority, a request is forwarded on a terminated flow, and a credential substituted, only when the chain validates against the host trust store for that authority; a chain rooted in the interception root, an expired chain, or a hostname mismatch is refused before any forwarding
  <!-- a resolver or route compromise at an allowed name otherwise receives the real credential, the theft the sealing exists to end; BEP-030's passthrough rides the same leg, so a box's own credential is validated no less than a direct connection would be -->
  - IF upstream validation fails THEN THE SYSTEM SHALL refuse the request and record an audit event marked `upstream_tls_invalid`.
    tier:   T0
    verify: cargo nextest run -p bep upstream_tls_failure_is_refused_and_audited
  - IF a request to a credentialed host, sealed or not, would ride an upstream leg that is not TLS THEN THE SYSTEM SHALL refuse the request and record an audit event marked `upstream_not_tls`.
    tier:   T0
    verify: cargo nextest run -p bep plaintext_request_to_credentialed_host_is_refused
    <!-- unwanted; an absolute-form `http://` request under `proxy_env` reaches the proxy inside the CONNECT-port connection, where BEP-031's port discipline does not see it; the v1 authorities carry the default port 443 (Gatehouse §6.10 Module host sets), so no plaintext authority exists in the set and there is no chain for the parent requirement to validate -->

- **BEP-026** IF a connection arrives that is not a box attachment on this host THEN THE SYSTEM SHALL refuse it at the listener, sealed value or not.
  tier:     T0
  verify:   cargo nextest run -p bep host_shell_connection_is_refused
  <!-- Gatehouse §6.10: a connection attempt outside any node association is refused at the listener; the proxy is a credential proxy for boxes, never a general egress proxy for the host -->

- **BEP-027** THE SYSTEM SHALL seal values in a form that `api.github.com` rejects as a credential when presented directly.
  tier:     T0
  verify:   cargo nextest run -p bep --run-ignored ignored-only sealed_value_rejected_by_github

- **BEP-028** WHERE the sending box is `host_ip`, WHEN a request carrying a sealed value that names a live `host_ip` box of this host passes the remaining checks THE SYSTEM SHALL admit it and mark its audit record `cohort_attributed`.
  tier:     T0
  verify:   cargo nextest run -p bep host_ip_redemption_is_cohort_attributed

- **BEP-029** IF a CONNECT or an absolute-form request names an authority outside the union of the configured modules' host sets and the registered store authorities THEN THE SYSTEM SHALL refuse it and record an audit event marked `off_module`.
  tier:     T0
  verify:   cargo nextest run -p bep request_outside_modules_is_refused_off_module
  <!-- both request forms: `HTTP_PROXY` (BEP-012) makes a plain `http://` fetch arrive absolute-form, not as CONNECT; a credential proxy, never a general egress proxy -->

- **BEP-030** WHEN a request to a credentialed host carries no sealed value and its authority is admitted by the box's egress THE SYSTEM SHALL forward it unmodified and record an audit event, marked `foreign_credential` when the request carries a credential of its own.
  tier:     T0
  verify:   cargo nextest run -p bep unsealed_request_passes_through_and_is_audited

- **BEP-031** IF a connection arrives for a credentialed hostname on a port outside the module's declared authorities THEN THE SYSTEM SHALL refuse the connection.
  tier:     T2
  verify:   cargo nextest run -p bep prop_off_port_connection_is_refused
  property: for every credentialed hostname, every port and every module authority set, the connection is admitted only when `host:port` is a declared authority
  harness:  kani_redeem_enforces_port_discipline, same bound and purity constraint as BEP-019

Store references

- **BEP-032** WHERE a box declares a `source = "store"` reference matched by a `[secret-store-rules]` rule, WHEN a request from that box to the rule's registered upstream passes BEP-019, BEP-020, BEP-022 to BEP-024 and BEP-064 THE SYSTEM SHALL inject the referenced Keychain value in the rule's injection form.
  tier:     T0
  verify:   cargo nextest run -p bep store_reference_injects_in_registered_form
  <!-- the store handle (BEP-063) is the member inside the same sealed envelope, so BEP-019 and BEP-020 apply unchanged; BEP-064's handle checks stand where BEP-021, BEP-031 and BEP-058 read a module host set, mode and breadth, with the handle's `upstream` as the bound set; one decision function over both member kinds (BEP-025) -->

- **BEP-033** WHEN a store reference is redeemed THE SYSTEM SHALL read the value from the Keychain for that request and write it to no file.
  tier:     T0
  verify:   cargo nextest run -p bep store_value_read_per_request_never_written

- **BEP-063** WHEN a store reference is minted for a box THE SYSTEM SHALL issue a handle signed under the client's local key carrying the store, the identifier, the registered upstream authorities, the injection form and an expiry equal to the root CA's remaining validity at the mint, and register that key with the proxy over the proxy's control socket before the handle is delivered.
  tier:     T0
  verify:   cargo nextest run -p minimal store_handle_signed_and_key_registered
  <!-- Gatehouse §6.10 store members, un-enrolled: the client signs handles in the store-handle wire format under its local key, and an un-enrolled handle's expiry is the credentialed-lane ceiling (v1.23), the same as a sign-in reference's (BEP-005): the value is resolved per request and item deletion revokes it at once, so a shorter clock would only end a running box's references with no re-mint path to renew them; the control socket is the local UDS of §6.2's same-machine trust, distinct from the redemption listener BEP-026 closes to non-box connections -->
  - WHEN the proxy restarts THE SYSTEM SHALL verify store handles under every client key registered before the restart.
    tier:   T0
    verify: cargo nextest run -p bep client_key_registrations_survive_restart
    <!-- event-driven; a registration held only by the running process would refuse every running box's store references after a restart, until the next mint registered the key again -->
  - IF the host keychain refuses the running client its handle-signing key THEN THE SYSTEM SHALL replace the key and register the replacement before minting.
    tier:   T0
    verify: cargo nextest run -p bep a_client_key_this_program_is_refused_is_replaced
    <!-- unwanted; unlike the proxy's keys (BEP-060), this key signs handles only and every mint registers the key it signs under, so its replacement needs no operator step -->
  - THE SYSTEM SHALL accept key registration and audit submissions only over a control socket owned by the operator's user with mode `0600`, separate from the redemption listener.
    tier:   T0
    verify: cargo nextest run -p bep control_socket_is_owner_only_and_separate_from_listener
    <!-- ubiquitous; the operator's own processes are the trust boundary un-enrolled (Gatehouse §6.2), and the redemption listener stays closed to them (BEP-026) -->

- **BEP-064** IF a store handle's signature does not verify under a registered client key, its expiry has passed, its `upstream` is not a subset of the current rule for its store and identifier, or its `inject` differs from that rule's THEN THE SYSTEM SHALL refuse the request and record an audit event marked `store_handle_invalid`.
  tier:     T2
  verify:   cargo nextest run -p bep prop_store_handle_verified_against_current_rule
  property: for every handle, every registered key set, every clock reading and every current rule, redemption admits only when the signature verifies, the clock is before `exp`, `upstream` is a subset of the rule's authorities and `inject` equals the rule's form
  harness:  kani_redeem_refuses_invalid_store_handle, same bound and purity constraint as BEP-019
  <!-- a rule that has since narrowed, or changed its injection form, refuses: editing a rule bites a running box -->
  - WHEN the operator's `[secret-store-rules]` change THE SYSTEM SHALL judge the next request against the changed rules, with no restart of the proxy or the box.
    tier:   T0
    verify: cargo nextest run -p bep edited_store_rule_applies_to_next_request
    <!-- event-driven; the rule is read as current at each request, as BEP-054 reads the stored value; a rule registering a new authority also changes the root's constraints (BEP-013), which reach boxes created afterwards -->
  - WHERE the handle is a sign-in reference THE SYSTEM SHALL judge it against the GitHub module as its rule: `upstream` within the module's current authorities and no `inject`.
    tier:   T0
    verify: cargo nextest run -p bep sign_in_reference_is_judged_against_the_module
    <!-- Gatehouse §6.10 store-handle wire format (v1.23): the GitHub module stands as the registration, so the same check applies module-supplied and a reference whose fields disagree with the module refuses as a stale registration does -->

- **BEP-034** IF a `[secret-store-rules]` rule names a deep module's host, Minimal's own infrastructure, or an injection header among `Host`, `:authority`, `Cookie`, `Proxy-*`, `Transfer-Encoding`, `Connection` and `Upgrade` THEN THE SYSTEM SHALL refuse the rule when reading configuration and name it.
  tier:     T0
  verify:   cargo nextest run -p sessions store_rule_in_deny_set_is_refused
  - IF a `[secret-store-rules]` rule or a `source = "store"` reference names the GitHub sign-in item THEN THE SYSTEM SHALL refuse it when reading configuration and name the GitHub module as the item's owner.
    tier:   T0
    verify: cargo nextest run -p sessions store_rule_naming_sign_in_item_is_refused
    <!-- Gatehouse §6.10 (v1.23): the item's identifier is reserved to the module, so a generic reference can never inject the operator's GitHub token -->

- **BEP-065** WHEN a store value is injected THE SYSTEM SHALL emit exactly the registered prefix followed by the value as the header's value, or fill one `basic_auth` field with it.
  tier:     T0
  verify:   cargo nextest run -p bep injected_value_is_exactly_prefix_plus_value
  <!-- Gatehouse §6.10 injection rule -->

- **BEP-066** IF a store value or a registered prefix contains a carriage return or a line feed THEN THE SYSTEM SHALL refuse the injection and record an audit event marked `injection_invalid`.
  tier:     T0
  verify:   cargo nextest run -p bep crlf_in_value_or_prefix_refuses_injection

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

Review, audit and revocation

- **BEP-038** WHEN `min box spec` is run for an entry declaring a credentialed upstream THE SYSTEM SHALL render the root CA fingerprint, the derived upstream set for each grant, the resolved steering mode, and each store reference with its registered authorities.
  tier:     T0
  verify:   cargo nextest run -p minimal box_spec_renders_ca_upstreams_steering_and_references
  - WHEN `min box spec` renders a grant whose member is `full` breadth THE SYSTEM SHALL mark the grant `full` beside its declared scope.
    tier:   T0
    verify: cargo nextest run -p minimal box_spec_marks_full_breadth_member
    <!-- event-driven; the marker the first slice exercises with `github:user-token`; BEP-057's acknowledged case renders the acknowledgement beside the same marker -->
  - WHEN `min box spec` renders a box that declares a credentialed upstream and whose resolved `quic443` stance is allowed THE SYSTEM SHALL flag the stance, whether `allow` was declared or `auto` resolved to it.
    tier:   T0
    verify: cargo nextest run -p minimal box_spec_flags_allowed_quic_stance_on_grant_box
    <!-- networking §5.3 (v0.9): the flag keys to the resolved stance, never the input; at v1.25 rollout a running grant-holding `auto` box under `proxy_env` or `off` flips from blocked to allowed with no event of its own -->

- **BEP-039** WHEN the proxy admits or refuses a request THE SYSTEM SHALL append one JSONL record under the `min/v1` audit schema carrying its `kind`, the subject box, `act` and `txn` left empty, the upstream authority, the member or store identifier or `none`, the mapped resource and permission or `module_unmapped`, the decision and any marker.
  tier:     T0
  verify:   cargo nextest run -p bep every_decision_appends_one_audit_record
  <!-- the F12 shape by ruling (Gatehouse §6.10 Audit bullet, v1.20.1); `kind` tells a proxy decision from an identity event once the host enrolls; off-module and unsealed records carry `none` -->

- **BEP-067** WHEN the client mints a member or a store handle, or a live box is destroyed (BEP-043) THE SYSTEM SHALL append a record of kind `mint` or `revocation` to the same log through the proxy, the log's sole writer, over the control socket.
  tier:     T0
  verify:   cargo nextest run -p minimal mint_and_destroy_append_audit_records
  <!-- so a box's trail reads the same un-enrolled and enrolled, where the STS pipeline carries the box's identity events; one writer means the head read, the append and the chain advance are one operation in one process, so concurrent client and proxy records cannot share a predecessor; the log is the home of a box's revocation record (Gatehouse §6.10 v1.24); a logout writes none, since it revokes by deleting the sign-in item (BEP-044); no value binds its mint record, because a revocation names a box id that never returns (BEP-071) -->

- **BEP-040** THE SYSTEM SHALL write no credential, injected header value, or request body to the audit log.
  tier:     T1
  verify:   cargo nextest run -p bep prop_audit_records_never_contain_secrets
  property: for every two requests identical in every BEP-039 field and differing only in body, the serialized records are identical apart from BEP-048's chain field; and every record field is derived from the BEP-039 field set and the chain field alone, which carry neither the member credential, the store value, an injected header value nor the body

- **BEP-041** THE SYSTEM SHALL open the audit log for append only and modify or remove no existing record.
  tier:     T0
  verify:   cargo nextest run -p bep audit_log_is_opened_append_only

- **BEP-068** WHEN the active audit segment reaches its size bound THE SYSTEM SHALL open a new segment whose first record carries the previous segment's final hash.
  tier:     T0
  verify:   cargo nextest run -p bep segment_rotation_continues_chain
  <!-- the chain spans segments; the size and retention bounds are plan facts -->
  - WHEN `min box audit` is run THE SYSTEM SHALL read across every retained segment.
    tier:   T0
    verify: cargo nextest run -p minimal box_audit_reads_across_segments
  - WHEN the proxy starts THE SYSTEM SHALL restore every revocation recorded in every retained segment.
    tier:   T0
    verify: cargo nextest run -p bep revocations_restored_from_every_segment_on_start
  - THE SYSTEM SHALL retain a segment holding a box's revocation record until every value naming that box has expired.
    tier:   T0
    verify: cargo nextest run -p bep segment_with_live_revocation_is_retained
    <!-- ubiquitous; Gatehouse §6.10 v1.24: a revocation record is compactable once no value naming its box can be unexpired, and the credentialed-lane ceiling bounds that; pruning earlier would lose the revocation at the next start -->

- **BEP-042** WHEN `min box audit <id> [-o jsonl]` is run with a box id THE SYSTEM SHALL output the retained audit records whose subject is that box and no other, a reaped box included.
  tier:     T0
  verify:   cargo nextest run -p minimal box_audit_filters_to_one_box
  <!-- the ruled grammar: `min box audit <box|self> | --parent <box|self> [-o jsonl] [--follow]`; the log is the proxy's, not part of the box record, so `rm` and `prune` never touch it; retention is BEP-068's -->
  - WHEN `min box audit <name>` is run with a friendly name THE SYSTEM SHALL read the live box of that name, else the most recent creation under it, and name the id it read.
    tier:   T0
    verify: cargo nextest run -p minimal box_audit_name_reads_live_else_latest_creation
    <!-- Gatehouse §6.10 v1.24 and the architecture's audit paragraph: a name is an alias, never identity; reading across a name's creations is an explicit listing convenience, a non-goal here -->
  - WHEN `--follow` is given THE SYSTEM SHALL replay the box's records and then tail new ones.
    tier:   T0
    verify: cargo nextest run -p minimal box_audit_follow_replays_then_tails
    <!-- the `events` model; a later slice -->
  - WHEN `--parent <box|self>` is given THE SYSTEM SHALL merge the records of every child of that box onto one stream, each naming its box.
    tier:   T0
    verify: cargo nextest run -p minimal box_audit_parent_merges_children
    <!-- a later slice -->
  - WHERE the host is not enrolled, IF `min box audit self` is run inside a box THEN THE SYSTEM SHALL refuse it with the defined error `audit_self_unsupported_unenrolled` naming `min box audit <box>` on the host.
    tier:   T0
    verify: cargo nextest run -p minimal box_audit_self_unenrolled_refused_with_error
    <!-- no `identity.sock` un-enrolled; the architecture leaves the in-box read path for `self` to the local implementation -->

- **BEP-043** WHEN a live box is destroyed, by `min session destroy`, a stop-and-remove of the box, or a type-noun alias of either, THE SYSTEM SHALL record a revocation naming the box's id and refuse redemption of every sealed value naming that box within 60 seconds.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_destroyed_box_values_refused_within_60s
  <!-- Gatehouse §6.10 v1.24: destroying a live box is the mode's one revocation event; reaping a stopped box's retained record later is not one, and a stopped box's values are refused by attribution once its attachment is withdrawn (BEP-020, NET-133) -->
  - IF the proxy does not record a destroyed box's revocation THEN THE SYSTEM SHALL complete the destroy and refuse the box's values through the withdrawal of its attachment.
    tier:   T0
    verify: ./scripts/session-e2e.sh bep_destroy_with_proxy_down_refuses_by_attachment
    <!-- unwanted; Gatehouse §6.10 v1.24 makes the host-side creator's attachment facts (NET-133) a v1 conformance requirement, so a destroyed box's values arrive from no live box and BEP-020 refuses them whether or not the record was written; a proxy that is down redeems nothing meanwhile; the record adds nothing the withdrawal lacks for a box id that never returns, and a revocation is never a reason to leave a box the operator asked to remove -->

- **BEP-044** WHEN `min auth logout` is run THE SYSTEM SHALL delete the sign-in item from the host keychain and refuse every sign-in reference to it at its next request.
  tier:     T0
  verify:   ./scripts/session-e2e.sh bep_logout_refuses_every_reference_at_next_request
  <!-- Gatehouse §6.10 v1.23: deletion is revocation, with no revocation record and no dependency on the proxy being up; host-wide and workload-preserving, so the boxes' processes keep running and a box that should regain the lane is re-created -->
  - WHEN `min auth logout` deletes the item THE SYSTEM SHALL ask GitHub to revoke the sign-in, and report a refused or unreachable revocation without failing the logout.
    tier:   T0
    verify: cargo nextest run -p minimal logout_revokes_at_github_best_effort
    <!-- best effort under the embedded secret: local deletion is the enforcement, and the GitHub call bounds refresh material a host compromise may already have taken -->
  - WHEN a GitHub sign-in completes after `min auth logout` THE SYSTEM SHALL redeem the references minted from it and keep refusing those minted before the logout.
    tier:   T0
    verify: cargo nextest run -p minimal sign_in_after_logout_revives_no_earlier_reference
    <!-- the new sign-in is a new instance (BEP-002), which no earlier reference names (BEP-045) -->

- **BEP-070** WHERE the host is not enrolled, WHEN a box is created THE SYSTEM SHALL give it a UUIDv7 box id whose random fields come from the OS CSPRNG, minted by the host-side creator outside the VM.
  tier:     T0
  verify:   cargo nextest run -p minimal box_id_is_a_csprng_uuidv7_per_creation
  <!-- Gatehouse §5.2 and §6.10 v1.24: the box id is unique per creation and a friendly name is an alias; the sealed context, the revocation and the audit subject all name the id; random fills, never counters, because revocation scoping rests on an id never returning -->
  - IF a minted box id is named by any retained record THEN THE SYSTEM SHALL refuse the creation.
    tier:   T0
    verify: cargo nextest run -p minimal colliding_box_id_refuses_creation
  - WHEN a box is created under the name a destroyed box held THE SYSTEM SHALL redeem the new box's sealed values and keep refusing the destroyed box's.
    tier:   T0
    verify: ./scripts/session-e2e.sh bep_box_recreated_under_its_name_redeems

- **BEP-071** THE SYSTEM SHALL treat a revocation as covering a sealed value exactly when it names the value's box id.
  tier:     T1
  verify:   cargo nextest run -p bep prop_revocation_covers_exactly_its_box
  property: for every set of revocation records and every sealed value, the value is covered iff some record names its box id; a box created after the revocation, under any name, is covered by no record
  <!-- Gatehouse §6.10 v1.24: held by construction, since a box id never returns (BEP-070) and a sign-in instance never returns (BEP-002); the filter selects the revocations in force for a value before the pure decision reads them, so BEP-024's harness is unchanged -->
  - WHEN a request carries a value a revocation covers THE SYSTEM SHALL refuse it before resolving any reference or renewing any sign-in.
    tier:   T0
    verify: cargo nextest run -p bep revoked_value_never_triggers_renewal
    <!-- redemption step 2 consults the records first, so a revoked blob never makes the proxy touch the keychain -->

- **BEP-045** IF a referenced Keychain item has been deleted or disabled THEN THE SYSTEM SHALL refuse the next request that would inject it.
  tier:     T0
  verify:   cargo nextest run -p bep deleted_keychain_item_refuses_next_injection
  <!-- deletion is revocation for store items and the sign-in item alike (Gatehouse §6.10) -->
  - IF a sign-in reference names an instance identifier the held sign-in item does not carry THEN THE SYSTEM SHALL refuse the request.
    tier:   T0
    verify: cargo nextest run -p bep reference_to_another_sign_in_instance_is_refused
    <!-- unwanted; what keeps a reference minted before a logout refused after the next sign-in (BEP-002, BEP-044) -->

- **BEP-047** THE SYSTEM SHALL run the proxy as the operator's login user and gvproxy and the VM as a dedicated unprivileged user, as separate processes sharing no writable state.
  tier:     T0
  verify:   cargo nextest run -p minvmd bep_and_gvproxy_are_separate_processes_and_users

- **BEP-048** WHEN a record is appended to the audit log THE SYSTEM SHALL include in it, as `previous_hash`, the SHA-256 of the previous record's serialized line, the UTF-8 JSON bytes without the trailing newline, or the all-zero hash for the first record of a log.
  tier:     T0
  verify:   cargo nextest run -p bep audit_record_carries_previous_hash
  <!-- the construction the writer, the verifier, the segment rotator (BEP-068) and the harness (BEP-049) share: the hash covers the whole previous line, its own `previous_hash` included; F12 fixes the fields, this document fixes the bytes -->

- **BEP-049** IF an audit log's records were altered or removed without recomputing every hash that follows THEN THE SYSTEM SHALL report the chain as failing verification in `min doctor`.
  tier:     T2
  verify:   cargo nextest run -p bep prop_audit_chain_detects_unrecomputed_edit
  property: for every sequence of records, the chain built from it verifies, and every sequence obtained by altering or removing one record that has a successor, without recomputing the hashes that follow, fails verification
  harness:  kani_audit_chain_detects_edit, exhaustive to 4 records of at most 64 bytes; requires chaining and verification to be pure functions over bytes, separate from the file writer
  <!-- what a bare chain detects; an edit followed by recomputation, and alteration or removal of the terminal record, are the T31 residual; whole-log verification is a `min doctor` check, never an `audit` flag -->

Setting secrets

- **BEP-050** WHEN `min secret set <id> [--store <s>]` is run THE SYSTEM SHALL read the value from the terminal or standard input, store it under `<id>` in the named store or, with no `--store`, in the host's native store, and output the identifier and no value.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_set_stores_in_keychain_and_prints_id_only
  <!-- the architecture's `min secret` reference: one grammar, the store deciding which fields are the caller's; the host's native store is the macOS Keychain here, the Linux default waits on the store roster -->
  - IF the value is supplied as a command-line argument or through an environment-variable flag THEN THE SYSTEM SHALL refuse the command and name the terminal and standard input as the accepted sources.
    tier:   T0
    verify: cargo nextest run -p minimal secret_set_refuses_value_argument_and_env_flag
  - IF the command runs with no terminal and no standard input THEN THE SYSTEM SHALL fail immediately.
    tier:   T0
    verify: cargo nextest run -p minimal secret_set_without_tty_or_stdin_fails_immediately
  - IF `--store gatehouse` is given THEN THE SYSTEM SHALL refuse the command and name the tenant-store deposit as outside this host's scope.
    tier:   T0
    verify: cargo nextest run -p minimal secret_set_refuses_gatehouse_store

- **BEP-051** WHEN `min secret set` stores an item THE SYSTEM SHALL set the item's access control so that the proxy process reads it without a prompt and any other application prompts.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_item_acl_admits_proxy_only
  - IF the proxy binary is not at the path the item's access control would name THEN THE SYSTEM SHALL refuse the command, naming that path, before reading the value.
    tier:   T0
    verify: cargo nextest run -p minimal secret_set_refuses_when_proxy_binary_absent
    <!-- unwanted; the keychain resolves a trusted application from a path that has to exist -->

- **BEP-052** WHEN `min secret list [--store <s>]` is run THE SYSTEM SHALL output, for each stored identifier: its store; the authorities and the injection form the matching `[secret-store-rules]` rule registers for it; the consent rule or `none`; and whether the item's access control carries the entry `set` created for the proxy's process identity; and output no value.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_list_shows_metadata_without_values

- **BEP-053** WHEN `min secret rm <id> [--store <s>]` completes THE SYSTEM SHALL have removed the item from that store.
  tier:     T0
  verify:   cargo nextest run -p minimal secret_rm_removes_item

- **BEP-054** WHEN `min secret set <id>` replaces an existing item THE SYSTEM SHALL inject the new value in the next request that redeems a reference to `<id>`, with no restart of the proxy or the box.
  tier:     T0
  verify:   cargo nextest run -p bep replaced_secret_is_injected_on_next_request

## Non-goals

- Caching public artifacts through the proxy: a separate story, not yet filed.
- Anthropic and MCP upstream modules; 1Password, LastPass, Linux Secret Service, `pass` and Bitwarden store backends: follow-on epics reusing this document's module and resolver seams (Gatehouse §6.10 store members lists the roster).
- The Gatehouse-hosted proxy, the enrolled `gateway` helper, the tenant secret store and the revocation feed: [GHI](https://github.com/gominimal/gatehouse/pull/1), Gatehouse §6.10, §6.11, §8.6. With a Gatehouse configured, `min` delegates sign-in, minting and sealing to it; nothing here forecloses that and the envelope is the same.
- Repository narrowing of a locally minted GitHub member: later work, the §6.4 scoped-token endpoint against the local App under the embedded client secret (Gatehouse §14.4 item 7); an open question below records the residual meanwhile.
- An in-box re-mint path for a locally minted member or store handle: none is needed un-enrolled, because both are references resolved at the proxy on each request (BEP-005, BEP-063), and Gatehouse v1.23 closed §14.4 item 7's re-mint surface by construction. A box is re-created only for what a reference cannot cross: the root's expiry and a sealing-key or root replacement (BEP-060).
- Reading every creation under a friendly name: the architecture names it an explicit listing convenience, never what the name means, and gives it no grammar yet; `min box audit <name>` reads one creation (BEP-042).
- HTTP/2 and HTTP/3 through the proxy, and MASQUE: networking design §12 item 10, whose first increment is h2 termination. Until then a client that requires h2 in ALPN, such as a gRPC library, is refused at the handshake (BEP-073), the recorded v1 limit.
- The JVM keystore: out of v1 scope by Gatehouse §6.10's trust-store injection, a recorded limit; a JVM client in a credentialed box needs its own trust configuration.
- The box-zone resolver, DNS-pinned admission, `network.mode` and the `[network]` table's egress fields: [NET](https://github.com/gominimal/minimal/pull/1380) (NET-060, NET-066, NET-072, NET-122). This document owns `[network.bep]` (`steering`, `proxy_env`, `no_proxy`) and `quic443`; the rest of the `[network]` schema is [gominimal/inbox#570](https://github.com/gominimal/inbox/issues/570).
- `min secret` against the Gatehouse tenant store (deposits): Gatehouse §8.6 and the architecture's `min secret` reference; here the noun binds host stores only and refuses `--store gatehouse` (BEP-050), and the two forms share one grammar.
- `min login` as the alias for `min auth login`: the command tree; the daemon-mTLS meaning the verb carries today is retired by NET (NET-109).
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

**The member is `full` breadth.** Both sign-in flows need a `client_id`, so the
client presents the Minimal-published GitHub App, and the App's registration is
the member's ceiling: a GitHub App user token is the App's permissions
intersected with the user's and with the installations the user holds, expires
in 8 hours and renews on GitHub's refresh token, which is why BEP-002 keeps the
refresh material and BEP-069 renews at the proxy. The App must be installed on the
account or organization whose repositories the token should reach, surfaced at
first sign-in. Two alternatives were considered. Enforcing the repository set in
the proxy by mapping request paths to repositories was rejected because
Gatehouse §6.10 rules that the proxy refuses only on its own invariants and
never on endpoint mapping, and because GraphQL and repository-less endpoints
would be unmapped. Having the user create a fine-grained token in GitHub's UI
and paste it to `min` was rejected because it loses "sign in once". The member
is therefore `full` breadth at v1, the T28 residual; a grant declaring narrower
scopes is refused un-enrolled unless the operator acknowledges the widening
(BEP-057), and the narrowing path is recorded: the §6.4 scoped-token endpoint
against the local App under the embedded client secret, with the non-scoped
token never leaving the host keychain (Gatehouse §14.4 item 7). The demo box
declares `github:user-token` rather than setting the acknowledgement, because
that is the honest spelling of the member and it exercises the `full` marker.
**`source = "broker"` names the local grant.** The grammar is kept so a spec is
unchanged at enrollment; Gatehouse §6.2, §6.3, §8.3 and §6.10 carry the
un-enrolled form. A new source value was rejected because it forces every spec
to be rewritten at enrollment and gives two code paths one job.

**Default steering is `dns`, refused until a resolver exists.** The
architecture's default is `dns` and this document keeps it, so a box spec
written today means the same thing after the resolver lands. The cost is that
every demo box writes `steering = "proxy_env"` explicitly and an unadorned
grant fails at expansion naming the missing resolver (BEP-017). Defaulting to
`proxy_env` now and flipping later was rejected because it changes the meaning
of existing specs at the flip; requiring an explicit mode was rejected because
it privileges neither mode and adds a validation error the architecture does
not have.

**The member is a reference, renewed where it is used.** GitHub revokes the
token and the refresh token at each renewal, so a token copied into a box, a
creation-time snapshot, cannot outlive 8 hours: renewing it on the host kills
the copy. Gatehouse v1.23 makes the member a reference to the sign-in item
(BEP-005), resolved by the proxy per request, and puts renewal at the proxy,
which is the token's only consumer once the client stops presenting it
(BEP-069). Renewal is single-flight per item because the refresh grant is
single-use, persisted before the renewed token is first used, and update-only so
a logout racing a renewal stays a logout. The reference expires with the
root's validity, the lane's ceiling; a shorter clock would bring back the
cliff while protecting little, since each request resolves it and deleting the
item revokes it. The architecture weighed and declined a local re-mint socket,
non-expiring App tokens, and a client timer that re-seals into running boxes
(Gatehouse §14.5, v1.23).

**A revocation names an identity that never returns.** Both failures that
prompted scoped revocation, a box re-created under a used name refused and a
sign-in after logout refused, came from identities that were reused, not from
revocations scoped too widely. So a box gets a UUIDv7 id per creation (BEP-070)
and a sign-in an instance identifier per login (BEP-002), and a revocation
covers exactly the id it names (BEP-071). Scoping by the mint record's position
in the log, by issue time, or by a sign-in field in the sealed context were
each weighed and dropped (Gatehouse §14.5, v1.24): with ids that never return
they scope nothing a plain match does not, and they add envelope fields and a
recording order. Logout revokes by deleting the sign-in item (BEP-044) and
needs no record; destroying a live box writes the one record this mode has
(BEP-043), kept until no value naming the box can be unexpired (BEP-068). A
destroy the proxy cannot record still completes: the withdrawn attachment
(NET-133) already refuses the box's values, so failing the destroy would keep a
box alive the operator asked to remove, and holding the record in the client
would add a queue that protects nothing the withdrawal does not. An id
embedding the name, such as `<name>@<session id>`, was rejected because renaming
a box would change its identity. The two levers are blunt: destroy stops one box
and its workload, and logout stops every reference on the host while the
processes keep running.

**Sign-in and audit verbs.** `min auth login | logout | status` and the `min box
audit` grammar follow the command tree; `login` is the tree's alias for `min
auth login`, and NET retires the daemon-mTLS meaning the verb carries today.
`min auth login` keeps the command tree's shape un-enrolled: the bare verb is
the browser flow wherever one exists, `--device` pins the device flow, and no
other flag is added. Slice one's bare verb runs the device flow because it is
the only flow shipped, and it moves to the browser flow when that lands; a
script that needs the device flow says `--device`, which is what the flag is
for. One verb, one default on both sides of enrollment. The embedded public
secret and its rationale are Gatehouse §6.10's. `min box audit self` is refused
un-enrolled in v1: there is no `identity.sock`, and a relay through minimald to
the proxy is a new socket surface for one verb, so it waits; the architecture
leaves the in-box read path to the local implementation. `--follow` and `--parent` are bound now
and built in a later slice so the grammar does not change under scripts.
**The proxy is its own crate.** The verify lines name `bep`: a host-side crate
beside the switch, with the shipped `:7654` router's head-parsing core shared
or copied as the plan sees fit. Extending the router in place was rejected
because the router runs inside the box host and the proxy must run outside it.
**The proxy runs as the operator.** Keychain items are per user and `min secret
set` writes to the operator's keychain, so the proxy reads as the operator's
login user; gvproxy and the VM run as a dedicated unprivileged user (BEP-047).
A proxy user with a keychain of its own was rejected for v1 because the write
path would need a helper channel and the items would fall outside the
operator's Keychain Access view. On macOS the keychain keys on code signature: a
stored item's access control prompts for any binary it does not name, and a
non-exportable key admits only the program that generated it, so a rebuilt
proxy is refused its own keys outright. A release signed with a stable identity
stays the same program across upgrades; a development build does not, and
recovers through the replacement command after each rebuild (BEP-060). That is
a build-time constraint for the plan, not a requirement.
**`[network.bep]` is bound here.** This document owns `steering`, `proxy_env`
and `no_proxy`, and `quic443`, because it introduces them and three
requirements cannot be implemented without them; `network.mode` stays NET's and
the rest of the `[network]` schema waits on the box-spec work. Sequencing the
first slice after that work was rejected because it blocks the demo on a schema
no requirement here needs.
**A steered name fails closed while the proxy is down.** BEP-062 answers
SERVFAIL rather than falling back to real DNS, because a fallback sends the box
direct with no egress re-check and no audit record; `proxy_env` fails closed
for free and `dns` steering is made to match.

**HTTP/1.1 on both legs, with a strict parser.** Substituting a credential
means inserting a header after TLS termination. On HTTP/1.1 that is a parse,
an append and a stream over a self-delimiting head, the parser the audit needs
anyway. On h2 it is full termination: HPACK's dynamic table is shared by every
stream on a connection, so one inserted header means decoding and re-encoding
every header block, and gRPC pins the upstream leg to h2 as well. Networking
design §5.7 therefore rules HTTP/1.1 on both legs in v1 (BEP-073 to BEP-076)
and defers h2 to §12 item 10. The cost it records is h2's immunity to request
smuggling, which is why BEP-077 re-serializes every request and refuses
ambiguous framing: a desync between the proxy's parser and the upstream's
would carry a request past the audit and the authority pinning.

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

**The audit log is hash-chained, and the record is the F12 shape.** Append-only
alone was the cheaper option and its residual, host-root edits, is T31's
accepted residual on a single-operator host. Chaining was chosen so the format
does not change when the enrolled helper needs F12's chained audit; what a bare
chain detects is an edit not followed by recomputation (BEP-049). Anchoring the
chain, an HMAC over each record under a keychain-held key with `min doctor`
checking the last recorded head, was considered and set aside for v1: it adds a
second keychain key and a doctor-recorded head to defend against the operator's
own root, which T31 already concedes; it is the shape to revisit when the
enrolled pipeline lands. Records carry the F12 fields with `kind`, so a box's
trail reads the same in both modes, and the client's mints and a destroyed
box's revocation are recorded in the same chain (BEP-067). Segments rotate at a size bound with the
chain continued across them (BEP-068), because an unbounded log fills a laptop
disk.

**The redemption decision is pure, and proved at T2.** Every check in BEP-019 to
BEP-025, BEP-031, BEP-058 and BEP-064 is a decision over owned values, and the
tier constrains the code: the decision is one function, separate from the TLS
and socket shell, with authorities interned as small ids so Kani can exhaust
host sets of at most four authorities and two members. Expansion validation
(BEP-008, 009, 017, 036, 056, 057), name constraints (BEP-013), upstream
validation (BEP-055), audit secrecy (BEP-040) and the hash chain (BEP-049) are
property-tested at T1 or T2 for the same reason; T1 adds `proptest` to the
workspace as a dev-dependency. T3 was refused: the repository has no Lean
project, so any T3 is also a toolchain and a CI lane. Two invariants stay at T0
by design: no plaintext credential in the box is a placement property the e2e
observes directly in the box's environment and filesystem (BEP-002, BEP-007,
BEP-033), and unattended key and store access confined to the proxy identity is
enforced by keychain access control rather than by a decision function this code
owns (BEP-014, BEP-051, BEP-059), so a property test would restate the
keychain's contract.

**Three-layer CA, keys in the keychain.** A self-signed root as the injected
anchor, a keychain-held signing CA that rotates freely, and per-hostname leaves
is the reading of the per-host intermediate Gatehouse §6.10 records; the
un-enrolled key lifecycle it states is bound as BEP-059 to BEP-061. The name
constraints sit on the root itself (BEP-013). Two alternatives were set aside.
Constraints on the signing CA alone bind only while the proxy presents that
certificate, so a certificate the root signed directly would validate
unconstrained. Anchoring boxes on the constrained signing CA instead needs
partial-chain validation, which OpenSSL's own `verify` and stock Node lack;
constraints on a self-signed anchor are enforced by OpenSSL, Go and rustls, and
signing-CA rotation stays invisible to boxes. Injection writes the bundle and
the hashed directory both (BEP-011), because each form is read by stacks the
other misses. Requirements state only the observables.

**`min secret` is the store's front door.** The grammar and the `list` row are
the architecture's `min secret` reference; this document binds the host-store
form and refuses the tenant-store one. Without the verb an item created outside
`min` carries no access-control entry for the proxy, so every redemption
prompts on the host and a store reference is unusable from an unattended box.
Replacing an item is rotation: the proxy reads per request (BEP-033), so no
restart is needed.

**Prior art.** The `docs/spec-credential-lane` branch's policy gate, resolver
seam, `min session credentials` review surface and the "tasks stop mapping
credentials" fix carry over in intent; its lane endpoint, bearer token store and
path-segment selector do not, because reachability was the authorization and
Gatehouse §12.11 dismissed that shape. The shipped `:7654` Host-header router
is the closest code; the proxy stands beside it as its own crate.

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
until the box ends, the reference is revoked, or the root expires, which is
longer than the 8-hour token it replaces and is why `full` members belong on
`own_ip` placements (T28). A remote accomplice must relay whole flows into the
compromised box, the irreducible floor, now scoped, audited and revocable. The
baseline this replaces, a raw token in the box environment usable from anywhere
for its full TTL, is retired in every mode.

Residuals recorded: T28 for `host_ip` cohort attribution, and, until NET-132
and NET-133 are built, for every VM-hosted box, `own_ip` included, and the host
shell: every redemption then arrives from one shared attachment, so a copied
value is redeemable from any box or the host shell, audited
`cohort_attributed`, BEP-020's cross-box and BEP-026's host-shell refusals do
not hold, and BEP-022 checks the egress of the box the value names rather than
the sender's, so a stolen sibling value also reaches upstreams the thief's box
was denied. Gatehouse accepts that interim only under the single-operator
premise, and states its cost: malware running as the operator redeems through
the proxy past every prompt and consent surface, for as long as the reference
lives. The interim has a destroy-time facet too: with one shared attachment
there is no per-box withdrawal, so a destroy while the proxy is down leaves the
destroyed box's values redeemable from the cohort until the root expires, with
no revocation record ever written (BEP-043's sub-requirement holds only once
NET-133 is built). T31 for host-OS compromise, which on a single-operator laptop is
compromise of the operator's own machine, reaching the signing key by use but
not export; the proxy's keychain holds the sign-in's 6-month refresh material,
usable off the host until GitHub revokes it (BEP-044 asks it to); the listener
is parser surface reachable from credentialed-lane boxes; and the audit log's
chain detects an edit that is not followed by recomputation and nothing more.
Revocation is host state: restoring the host from a backup restores what was
valid before the revocation, keychain deletions included. T32 for
store-reference abuse, bounded by the client-owned rules, the deny set and
per-request Keychain access control.

- **Invariant:** THE SYSTEM SHALL place no plaintext credential in a box's environment, files or volumes.
  enforced by: sealing at mint; delivery of the sealed value only
  covered by: BEP-002, BEP-007, BEP-033

- **Invariant:** THE SYSTEM SHALL redeem a sealed value only on this host, and only from the box it names or, where that box is `host_ip`, from another live `host_ip` box of this host with the redemption audited `cohort_attributed`.
  enforced by: host key binding; box attribution from the switch's source address and the host-side creator's attachments; the `host_ip` cohort rule
  covered by: BEP-019, BEP-020, BEP-026, BEP-028, BEP-058, BEP-070

- **Invariant:** THE SYSTEM SHALL substitute a credential only into a request whose connection authority and `Host` are one declared authority of its module or registration, on an upstream connection that authenticated as that authority.
  enforced by: host-set membership, request-authority pinning, port discipline, name-constrained CA, upstream validation against the host trust store, TLS-only upstream legs for credentialed hosts, canonical re-serialization with ambiguous framing refused, no upstream connection shared across boxes
  covered by: BEP-013, BEP-021, BEP-023, BEP-031, BEP-032, BEP-055, BEP-064, BEP-065, BEP-077

- **Invariant:** THE SYSTEM SHALL admit no credentialed reach that the box's declared egress denies.
  enforced by: full-set validation at expansion; egress re-check at redemption
  covered by: BEP-008, BEP-022, BEP-036

- **Invariant:** THE SYSTEM SHALL write no credential to any log, spec rendering or diagnostic bundle.
  enforced by: audit record construction from the decision only; `min box spec` and `min secret` render identifiers and references only
  covered by: BEP-004, BEP-038, BEP-040, BEP-050, BEP-052

- **Invariant:** THE SYSTEM SHALL grant unattended access to the signing key, the sealing key and store items to the proxy's process identity alone.
  enforced by: process separation; keychain access control bound to the proxy's identity
  covered by: BEP-014, BEP-047, BEP-051, BEP-059, BEP-060, BEP-072

- **Invariant:** THE SYSTEM SHALL stop redeeming a revoked or expired value within 60 seconds.
  enforced by: expiry in the sealed context; revocation records consulted per request before any resolution; sign-in and store items resolved per request, so deletion revokes
  covered by: BEP-024, BEP-043, BEP-044, BEP-045, BEP-060, BEP-068, BEP-069, BEP-071

Architecture threats this document must hold: T28, T31, T32 (Gatehouse §11);
AT7 and AT25 (architecture threat model).

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): When does local repository narrowing land? The path is recorded, the §6.4 scoped-token endpoint against the local App under the embedded client secret (Gatehouse §14.4 item 7), and until it does the member is `full` breadth and the T28 residual is the signed-in account's manifest-capped reach for the reference's life.]
- [NEEDS CLARIFICATION (MEDIUM): Does every intended client accept the sealed handle as its bearer unmodified? Claude Code with an OAuth token and MCP clients send `Authorization: Bearer <value>`, which BEP-032 substitutes, but a client that validates token shape before sending, or sends the credential in a header the rule does not name, needs the harness adapter ([gominimal/inbox#345](https://github.com/gominimal/inbox/issues/345)); unmeasured, a plan spike.]
- [NEEDS CLARIFICATION (MEDIUM): How long is the root valid ([gominimal/arch#85](https://github.com/gominimal/arch/issues/85))? Its remaining validity at mint is the expiry of every sign-in reference and store handle (BEP-005, BEP-063), so it is the ceiling on a box's credentialed life and on the T28 window of a stolen reference, and the point at which a running box has to be re-created.]
- [NEEDS CLARIFICATION (MEDIUM): On a Linux LocalVM host, which key store holds the signing CA key as non-exportable (TPM 2.0 via a PKCS#11 provider, or Secret Service without hardware backing)? BEP-014 is written over "the host keychain"; the plan carries a spike, and until it lands the Linux host is unverified for BEP-014.]
