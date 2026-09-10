---
id: MCC
title: "Shared min client core: one Rust core for the CLI, the browser and mobile"
status: draft
owner: mitodrummer
epic: gominimal/inbox#513
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-10
---

# MCC — Shared min client core: one Rust core for the CLI, the browser and mobile

## Context

A developer reaches a session only from the machine that runs `min`: there
is no browser client, no credential plane in the CLI, and no client code a
second head could reuse. The "Mobile / Web Browser" story needs a client
that lives in a tab, and the owner's direction rules out any server in the
session path. After this ships one Rust core carries the mesh peer, the
attach sequence, the RPC driver, the credential flow and host trust for
every head: the `min` CLI, the browser bundle, and later a mobile app. The
direction is [the direction plan](https://github.com/gominimal/minimal/blob/feat/min-core-wasm-poc/plans/browser-min-client-direction.plan.md)
carried on the proof-of-concept branch (#1350), and the identity plane is
Gatehouse; neither is restated here.

**Success:** A developer signed in with GitHub attaches from a browser tab
to a session on a daemon they own, SSH terminating in the tab under a
certificate on a key the tab cannot export and a host verified against the
tenant's Host CA; and the same `min` binary attaches to the same session
through the same core.

**First slice:** The core promoted from the proof of concept with its
native tests green, the browser bundle driven headlessly through a full
attach with certificate authentication and host verification against a
stand-in daemon, and `min session list` showing a mesh node's sessions
beside the local ones.

## Users and stories

**Roles:** developer using long-running agentic workflows; developer
running sessions both locally and remote.

- AS A developer using long running agentic workflow, I WANT to monitor and
  jump into an session via a mobile or desktop web browser, SO THAT I can
  provide additional input and course correct the agent when I'm not at my
  workstation.
  Acceptance criteria:
  - A user can navigate to a session URL in a desktop or mobile browser, and
    authenticate via GitHub to access the running workbench stream.
  - The web interface streams session stdout/stderr in real time and accepts
    terminal input to course-correct active agent runs.
  - The web session view renders cleanly on mobile screen width in portrait
    and landscape without breaking terminal text layouts or input controls.
  - Closing the browser tab or dropping mobile connection leaves the remote
    session continuously active in a detached state.
- AS A developer running sessions both locally and remote, I WANT to enumerate
  and reconnect with remote sessions just like local sessions, SO THAT I can
  work with all my sessions the same way. Acceptance criterion: remote boxes
  are enumerable and attachable through the same CLI surface as local ones.

The third acceptance criterion of the first story is the page's (WMC). The
epic's "Sync Files Out" story reaches no spec yet (Non-goals).

## Requirements

A *head* is a client built on the core: the `min` CLI, the browser bundle,
later a mobile app. The *host* is the head's runtime; it supplies the core a
byte stream or datagram pipe, a clock and timer, an HTTP call and a
*signer*, which signs the bytes the core hands it and returns a raw
signature. A *suspension* is any interval in which the host delivers no
timer tick, a *resume* the first tick after it. A *page session* is one
document's lifetime, ended by a reload or a navigation. The *issuer set* is
the fixed set of deployment issuers the head configures the core with at
start. Wire shapes, endpoints and decisions are the architecture of
record's (Gatehouse, cited by section) and the siblings'; this document
cites them rather than repeating them.

Siblings: the browser client spec (WMC, webapp#763) consumes the browser
contract group by ID; the mesh-ingress spec (MMI, #1356) is the daemon
side, bound by ID here, and may be superseded by the networking spec in
preparation, whose inputs are the architecture's networking requirements v2
(arch#46) and its deployment and egress-gateway design — ingress and
transport bind to that spec by name once it exists; the GitHub sessions
spec (GHS, #1351) owns the CLI sign-in ceremony; the Box Provider
abstraction (BPA, arch#45) states what a provider reports about a host.

### Core boundary

- **MCC-001** THE SYSTEM SHALL build and pass the same tests of the network
  layer, the attach sequence, the RPC driver, the credential module and host
  policy on `wasm32-unknown-unknown` and on the native targets.
  tier:     T0
  verify:   just wasm-core-headless one_source_tree_attaches_on_the_wasm_target

- **MCC-002** THE SYSTEM SHALL import into the browser bundle no filesystem,
  terminal, process, OS-socket or OS-timer capability, taking each from the
  host.
  tier:     T0
  verify:   just wasm-core-headless bundle_imports_no_host_capability

- **MCC-003** THE SYSTEM SHALL decode every wire type the heads and the
  daemon share identically in the core and in the CLI.
  tier:     T0
  verify:   cargo nextest run -p min-wire core_and_cli_decode_from_one_wire_definition

- **MCC-006** WHEN the core connects to a daemon THE SYSTEM SHALL negotiate
  the protocol version before any session operation, report both versions
  to the head, and refuse a daemon outside `protocol_window` — the
  configured range of daemon versions the core accepts, an interim whose
  default is an open question — or one that has not answered within 10 s,
  naming both versions and the remedy, or the timeout.
  tier:     T1
  verify:   cargo nextest run -p min-core version_outside_window_fails_closed_naming_both_versions
  property: for every window W the core is built with, every daemon version v and every answer time t at the injected clock, a session operation is issued iff v ∈ W and t ≤ 10 s; otherwise nothing but the version exchange is sent, and the refusal names both versions and the remedy, or the timeout

### Transport and network layer

How a daemon is reached — whether the head is a mesh peer or dials a
gateway — is the networking spec's to decide; until it exists these bind to
MMI by ID.

- **MCC-010** THE SYSTEM SHALL run the attach sequence and the RPC driver
  over any byte stream the host supplies, exchanging the same messages with
  the daemon on each.
  tier:     T0
  verify:   cargo nextest run -p min-core same_attach_sequence_over_pipe_socket_and_tunnel

- **MCC-011** WHEN the host supplies a datagram pipe and a peer configuration
  THE SYSTEM SHALL complete a WireGuard handshake with the peer and open TCP
  connections inside the tunnel.
  tier:     T0
  verify:   cargo nextest run -p min-core ssh_attach_through_the_tunnel
  - IF no handshake response arrives within 20 s of the dial request,
    a pipe that never opens included, THEN THE SYSTEM SHALL cancel the dial
    and fail it with a `transport:` outcome (MCC-064) naming the endpoint.
    tier:   T0
    verify: cargo nextest run -p min-core silent_handshake_fails_after_20s_at_the_injected_clock

- **MCC-012** WHERE the datagram pipe is a WebSocket THE SYSTEM SHALL carry
  one WireGuard datagram per binary frame in each direction (Gatehouse
  §6.9; MMI-001, MMI-072).
  tier:     T0
  verify:   cargo nextest run -p min-core attach_over_websocket_carried_wireguard

- **MCC-013** WHEN the datagram pipe closes or errors THE SYSTEM SHALL end
  every attachment and RPC on it with `tunnel_lost` (MCC-065) and retry
  nothing; a re-attach is the head's new attach call (MCC-057; WMC-026,
  WMC-028).
  tier:     T0
  verify:   cargo nextest run -p min-core dead_websocket_reaches_the_ssh_layer
  - IF the pipe stays open but no datagram arrives for 60 s THEN THE SYSTEM
    SHALL treat the tunnel as lost.
    tier:   T0
    verify: cargo nextest run -p min-core silent_peer_is_lost_after_60s_at_the_injected_clock

- **MCC-014** WHEN a node advertises a direct endpoint THE SYSTEM SHALL dial
  it first, and dial the node's home relay with the node's ticket only when
  the direct dial fails — a refused connection, or MCC-011's 20 s passing
  from the dial request with no handshake response, the pipe never opening
  included — or none is advertised (Gatehouse §6.9; architecture D7); the
  fallback runs inside MCC-060's attach bound.
  tier:     T0
  verify:   cargo nextest run -p min-core direct_endpoint_first_relay_as_fallback

- **MCC-015** WHEN a head lists nodes THE SYSTEM SHALL return the identity
  plane's node listing (`GET /v1/nodes`, Gatehouse §8.2) — name, identity,
  class, `last_seen`, liveness state and advertised reachability — joined to
  the peer document's entry (MCC-070), opening no tunnel.
  tier:     T0
  verify:   cargo nextest run -p min-core listing_opens_no_tunnel

- **MCC-016** WHEN the host resumes the core after a suspension THE SYSTEM
  SHALL re-evaluate the tunnel on the first tick and, where it is lost
  (MCC-013), end the attachment with `tunnel_lost` within 1 s; re-attaching
  is the head's (MCC-057, WMC-028).
  tier:     T0
  verify:   cargo nextest run -p min-core resume_after_suspension_surfaces_the_lost_tunnel_within_1s

- **MCC-017** WHEN a head selects a node THE SYSTEM SHALL open one tunnel to
  it and list its sessions through the RPC driver (MCC-072).
  tier:     T0
  verify:   cargo nextest run -p min-core selecting_a_node_opens_one_tunnel_and_lists_its_sessions

### Attach and RPC

- **MCC-020** WHEN a head attaches THE SYSTEM SHALL authenticate, open one
  session channel, set the session identifier, request a PTY of the given
  size and a shell, deliver output and the daemon's error stream in the
  order they arrive on the channel, forward input and window changes, and
  deliver the exit status.
  tier:     T0
  verify:   cargo nextest run -p min-core attach_write_resize_exit
  - IF the daemon refuses the shell THEN THE SYSTEM SHALL report which
    request was refused, an unknown session distinguishably (`attach:`,
    MCC-064).
    tier:   T0
    verify: cargo nextest run -p min-core shell_is_refused_without_a_session_id

- **MCC-021** THE SYSTEM SHALL present as the SSH username the principal the
  head supplies: `minimal-cli` under local trust, the certificate's box
  login principal (Gatehouse §5.3; the value MMI-024 admits) under
  certificate authentication — an interim until the daemon side's final
  rule (Open questions).
  tier:     T0
  verify:   cargo nextest run -p min-core ssh_username_is_the_heads_input

- **MCC-022** WHEN a head closes an attachment THE SYSTEM SHALL close the
  channel and nothing else, leaving the session running and detached.
  tier:     T0
  verify:   cargo nextest run -p minimald core_close_detaches_and_leaves_the_session_running

- **MCC-023** WHEN a head issues a oneshot RPC THE SYSTEM SHALL open a
  session channel, request the RPC's subsystem, send one request,
  half-close, and return the answer or the daemon's error; a refused
  subsystem is reported naming the RPC.
  tier:     T0
  verify:   cargo nextest run -p min-core oneshot_rpc_returns_answer_error_or_refusal

- **MCC-024** WHEN `min` runs a non-PTY command against a session THE SYSTEM
  SHALL drive the exec channel with the daemon's exec vocabulary and
  propagate the exit code; the browser never requests it (MMI-027).
  tier:     T0
  verify:   cargo nextest run -p min-core exec_channel_speaks_the_daemon_vocabulary

### Credential, the client half

- **MCC-030** THE SYSTEM SHALL sign every SSH authentication request and
  every DPoP proof through the head's signer, handing it the exact bytes and
  taking back a raw signature, and SHALL reach the key through nothing else.
  tier:     T1
  verify:   cargo nextest run -p min-core signer_output_is_the_buffer_extended_with_the_ssh_encoded_signature
  property: for every to-sign buffer b and algorithm a ∈ {ssh-ed25519, ecdsa-sha2-nistp256}, with s the signer's raw signature over b, the bytes the core hands the SSH layer are exactly b ‖ string(string(a) ‖ string(blob(a, s))), blob being the identity for Ed25519 and the mpint pair (r, s) for P-256; and every DPoP proof is header.claims.base64url(s) with s the signer's signature over the signing input
  - IF the signer fails or returns a signature of the wrong length THEN THE
    SYSTEM SHALL abort with a signing failure and send no authentication
    request.
    tier:   T0
    verify: cargo nextest run -p min-core signer_failure_aborts_before_any_auth_request

- **MCC-031** WHEN a credential is supplied THE SYSTEM SHALL authenticate
  with the certificate and the signer only.
  tier:     T0
  verify:   cargo nextest run -p min-core valid_certificate_attaches_and_the_host_certificate_is_verified
  - IF the daemon refuses the certificate THEN THE SYSTEM SHALL report an
    authentication refusal and never retry with `auth_none`.
    tier:   T0
    verify: cargo nextest run -p min-core each_refusal_case_is_refused

- **MCC-032** THE SYSTEM SHALL accept a host reached over any transport other
  than a local UDS or vsock (MCC-033) only when its host certificate verifies
  under the host policy — MCC-034's decision for the host type with an
  empty revocation set — for the expected principal,
  named exactly or by the per-node wildcard `*.<node_id>.box.<td>`,
  refusing anything else before authentication with the failing check
  named.
  tier:     T1
  verify:   cargo nextest run -p min-core host_policy_accepts_iff_every_check_holds
  property: for every host reached over a transport other than a local UDS or vsock and every (certificate, anchors, expected, now): accept ⇔ decision(certificate, anchors, host, now, revoked = ∅) = ok (MCC-034) ∧ (expected ∈ principals ∨ ∃ p ∈ principals: p = "*." ‖ suffix ∧ expected ends with "." ‖ suffix); a refusal names the first failing check, the decision's order first and the principal last; over a local UDS or vsock the decision is not consulted (MCC-033)
  - IF the host presents a bare key, a certificate from outside the anchors,
    or one for another principal THEN THE SYSTEM SHALL refuse it.
    tier:   T0
    verify: cargo nextest run -p min-core host_policy_refuses_a_wrong_principal_a_rogue_ca_and_a_bare_key
  - WHERE a principal is the per-node wildcard THE SYSTEM SHALL match every
    name under the node and no name beside it.
    tier:   T0
    verify: cargo nextest run -p min-core per_node_wildcard_principals_match_boxes_under_the_node
  - WHERE the host was dialed at a tunnel address THE SYSTEM SHALL match the
    canonical `<node_id>.box.<td>` name the peer document names and never
    the address (Gatehouse §5.3, mesh attaches).
    tier:   T0
    verify: cargo nextest run -p min-core tunnel_addressed_host_is_verified_against_its_canonical_name

- **MCC-033** WHERE the transport is a local UDS or vsock THE SYSTEM SHALL
  accept the daemon without a host certificate.
  tier:     T0
  verify:   cargo nextest run -p min-core local_socket_needs_no_host_certificate

- **MCC-034** THE SYSTEM SHALL provide one certificate decision naming the
  seven codes the architecture's vectors expect and `principal_mismatch`
  for a principal the certificate does not carry, the codes the daemon's
  decision names too (MMI-022).
  tier:     T1
  verify:   cargo nextest run -p min-core every_invalid_vector_is_refused_with_its_expected_error
  property: for every certificate, anchor set, expected type, clock, revocation set and principal, the decision accepts iff every check holds, and a refusal carries the code of the first failing check in the order signature, issuer, type, validity, critical options, revocation, principal
  - WHEN the architecture's user vector is presented THE SYSTEM SHALL accept
    it for its principals and refuse every other.
    tier:   T0
    verify: cargo nextest run -p min-core valid_user_vector_is_accepted_for_its_principals_only

- **MCC-035** WHEN a head signs in THE SYSTEM SHALL run the public-client
  flow — PKCE S256 with the signer key's RFC 7638 thumbprint on the
  authorization request, a DPoP proof on the token request, refresh with
  rotation, tokens in the core's memory — differing between heads only in
  the authorization leg: the browser's HTTPS redirect as the `public` client
  of Gatehouse §6.1.7, the CLI's device flow (GHS-006). Persistence beyond
  memory is the head's (MCC-050, MCC-076).
  tier:     T0
  verify:   cargo nextest run -p min-core login_is_pkce_and_dpop_bound_for_every_head

- **MCC-036** THE SYSTEM SHALL attach a fresh DPoP proof, signed through the
  signer, to every request it composes for the issuer: token, certify,
  mesh-bind, node listing, peer document, relay ticket and revoke.
  tier:     T1
  verify:   cargo nextest run -p min-core every_issuer_request_carries_a_fresh_dpop_proof
  property: for every issuer request r the core composes for the host to send, r carries a DPoP proof signed through the signer whose `htm` and `htu` are r's method and URL and whose `jti` differs from every proof composed before it

- **MCC-037** WHEN a head requests a credential while the core holds an
  access token with `box:ssh` THE SYSTEM SHALL request a certificate for the
  signer's key with the head's profile and TTL: `interactive` for the CLI,
  `exchange` at most 900 s for the browser (Gatehouse §6.6, §5.7); an
  issuer's refusal, a missing tenant opt-in included (§6.1.7), is reported
  as MCC-081 shapes it.
  tier:     T0
  verify:   cargo nextest run -p min-core certify_carries_the_heads_profile_and_ttl

- **MCC-038** THE SYSTEM SHALL take Host CA anchors only from
  `{iss}/v1/ssh/ca` of the issuer named in the credential it holds
  (Gatehouse §8.2), and SHALL attempt no certificate-authenticated attach
  while it holds none; a local UDS or vsock needs none (MCC-033).
  tier:     T1
  verify:   cargo nextest run -p min-core anchors_come_only_from_the_credentials_issuer
  property: for every credential c, every peer document d and every anchor state: the only anchors request the core composes is to `{iss}/v1/ssh/ca` for c's issuer; d is refused and opens no tunnel whenever its `td` differs from c's trust domain; and no certificate-authenticated attach is composed while no anchors are held, an attach over a local UDS or vsock (MCC-033) needing none
  - IF a peer document's `td` differs from the credential's trust domain
    THEN THE SYSTEM SHALL refuse the document and open no tunnel from it.
    tier:   T0
    verify: cargo nextest run -p min-core peer_document_with_a_foreign_issuer_is_refused

- **MCC-039** WHILE an attachment is open under a certificate THE SYSTEM
  SHALL obtain a fresh certificate 120 s before expiry (Gatehouse §5.7),
  re-handshake over the same tunnel, re-attach, and continue with the
  attachment object unchanged (MCC-069).
  tier:     T0
  verify:   cargo nextest run -p min-core renewal_reattaches_before_expiry_at_the_injected_clock
  - IF the issuer cannot be reached in time THEN THE SYSTEM SHALL let the
    attachment end at expiry with `credential_expired` (MCC-065), leave the
    session detached, and retry nothing; the re-attach is the head's new
    attach call (WMC-007, MCC-057).
    tier:   T0
    verify: cargo nextest run -p min-core issuer_outage_ends_attach_at_expiry_with_credential_expired

- **MCC-040** WHERE the head is a browser THE SYSTEM SHALL renew without user
  presence only while an attachment is open and less than 8 h after the
  presence-backed initial certify that began the chain (Gatehouse §6.1.7);
  past either bound the next certify requires a presence step, a user
  gesture at the head and never a fresh sign-in (WMC-009). The CLI's rule
  is MCC-056.
  tier:     T1
  verify:   cargo nextest run -p min-core renewal_chain_stops_at_8h_or_without_an_open_attach
  property: for every attachment state a ∈ {open, closed}, every chain start c and every instant now at the injected clock, an unattended renewal is composed iff a = open and now − c < 8 h; past either bound the next certify is composed only after a presence step

- **MCC-041** WHERE the head is a browser THE SYSTEM SHALL generate a fresh
  WireGuard keypair in memory per page session, request a binding for it
  under the DPoP-bound token (`JoinMesh`, Gatehouse §6.9), use it for at
  most 8 h, and discard it when the page session ends. The CLI's node key
  is MCC-053's.
  tier:     T1
  verify:   cargo nextest run -p min-core browser_mesh_key_is_fresh_per_page_session_bound_and_discarded
  property: for every page session s, the mesh keypair the core holds during s was generated after s began and differs from every earlier session's; no handshake uses it later than 8 h after its binding at the injected clock; and no handle to it survives the end of s

- **MCC-042** THE SYSTEM SHALL use a head's signing key for DPoP proofs and
  SSH authentication signatures only, deriving no SSH-PoP assertion from it
  (Gatehouse §6.1.7).
  tier:     T1
  verify:   cargo nextest run -p min-core heads_key_signs_only_dpop_and_ssh_userauth
  property: for every buffer b the core hands the signer, b is a DPoP proof's signing input or an SSH userauth request; no b is the signing input of an SSH-PoP assertion

### CLI adoption

- **MCC-050** WHEN a developer runs `min auth login` THE SYSTEM SHALL sign in
  by the device flow (MCC-035; its ceremony is GHS-006), obtain the
  interactive certificate and the Host CA anchors, and keep the key and the
  refresh token in the CLI's own stores, neither surviving in the core's
  memory past the process.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_login_installs_certificate_and_anchors

- **MCC-051** WHEN `min` reaches a daemon over any transport other than a
  local UDS or vsock THE SYSTEM SHALL apply the host policy (MCC-032) and
  certificate authentication (MCC-031).
  tier:     T0
  verify:   cargo nextest run -p minimal remote_daemon_needs_a_host_certificate_and_a_credential

- **MCC-052** WHEN a developer attaches to a session THE SYSTEM SHALL attach
  in process, with raw-mode terminal, resize and signal handling, on a
  machine with no `ssh` binary.
  tier:     T0
  verify:   cargo nextest run -p minimal session_attach_runs_in_process_without_ssh
  - WHILE the TTY attach still runs through the system `ssh`, the first
    adoption step, THE SYSTEM SHALL generate its `known_hosts`
    `@cert-authority` fragment from the anchors and expected principal the
    host policy uses.
    tier:   T0
    verify: cargo nextest run -p minimal known_hosts_fragment_matches_host_policy

- **MCC-053** WHEN a developer runs `min net mesh join <network>` THE SYSTEM
  SHALL request a Gatehouse §6.9 binding and consume the peer document
  through the credential module, with no manual key exchange (the daemon's
  static peer table is the POC interim, MMI-011), keeping its mesh node key
  across invocations for the lifetime of the membership the command
  establishes, until a leave or a later join — an interim, its rotation
  being an open question.
  tier:     T0
  verify:   cargo nextest run -p minimal mesh_join_needs_no_manual_key_exchange

- **MCC-054** WHEN a developer lists sessions THE SYSTEM SHALL include the
  sessions on every node the identity plane lists for the developer
  (MCC-015), addressed and attachable with the same grammar as local ones;
  hosts reached only through the client-managed provider list stay listed
  by today's path (Gatehouse §8.2 scope decision; BPA-013, BPA-015).
  tier:     T0
  verify:   cargo nextest run -p minimal list_and_attach_use_one_grammar_for_mesh_nodes

- **MCC-056** WHILE `min` holds a refresh token THE SYSTEM SHALL renew the
  interactive certificate in the background before it expires (Gatehouse
  §5.7), with no open attachment required and no chain cap beyond the
  refresh token's lifetime.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_renews_interactive_certificate_in_background

- **MCC-057** WHEN an in-process attachment ends with `tunnel_lost` or
  `credential_expired` THE SYSTEM SHALL re-attach by a new attach call, with
  backoff from 1 s doubling to a 30 s cap, until the daemon is reachable and
  a certificate is held again or the developer detaches, showing a
  reconnecting state and landing on the daemon's repaint (MCC-063).
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reattaches_after_loss_with_bounded_backoff

### Browser contract

The browser client spec (WMC) cites these by ID; page behaviour is WMC's
and verified there.

- **MCC-060** WHEN the page calls attach with one JSON configuration
  document, a signer callback, a data callback and a close callback THE
  SYSTEM SHALL resolve to an attachment offering `write(bytes)`,
  `resize(cols, rows)` and `close()`, and deliver every byte of session
  output and of the daemon's error stream, merged in channel arrival order
  (MCC-020), to the data callback.
  tier:     T0
  verify:   just wasm-core-headless attach_api_shape
  - IF the attach has not reached the accepted shell within 30 s of the
    call THEN THE SYSTEM SHALL reject with the prefix of the stage reached
    (MCC-064).
    tier:   T0
    verify: just wasm-core-headless attach_that_never_completes_rejects_within_30s

- **MCC-061** THE SYSTEM SHALL accept as the configuration document the
  node's peer-document entry (MCC-070) as served, the session identifier,
  the terminal type and size, and an auth block naming the SSH username and
  the expected host principal, the certificate and anchors being those the
  core holds (MCC-067); the core declares no scrollback request (the
  daemon's replay requirement is retired until a head asks); a missing or
  malformed field rejects the
  promise naming the field before any network activity.
  tier:     T0
  verify:   just wasm-core-headless config_rejections_name_the_field_before_dialing

- **MCC-062** THE SYSTEM SHALL deliver bytes passed to `write` to the session
  PTY unmodified and in call order, and apply a `resize` to the session PTY
  in order with the writes around it.
  tier:     T0
  verify:   just wasm-core-headless input_and_resize_are_ordered_and_unmodified

- **MCC-063** WHEN an attachment is established, at first attach and after
  every transparent renewal, THE SYSTEM SHALL deliver as the first bytes to
  the data callback the first bytes the daemon writes — its reconstruction
  of the session's current screen (MMI-051) — adding nothing before them;
  the page's rendering is WMC-029.
  tier:     T0
  verify:   cargo nextest run -p min-core first_bytes_delivered_are_the_daemons_first_bytes_unprefixed

- **MCC-064** IF the attach fails THEN THE SYSTEM SHALL reject the promise,
  with no attachment object, carrying a reason whose prefix names the
  stage: `config:`; `credential:` (the core's own pre-check of its
  certificate before any dial, or a credential call that failed, MCC-081);
  `version:`; `transport:` (a relay that refused the ticket, or a dial or
  handshake that did not complete in time); `host rejected:` with the
  failing check's code; `authentication rejected`; `signing:`; `attach:`
  (the daemon refused the env, pty or shell request, naming which, with
  `unknown session` distinguishable, or the channel closed before the
  shell was established).
  tier:     T0
  verify:   just wasm-core-headless attach_rejections_name_the_stage

- **MCC-065** WHEN an attachment ends THE SYSTEM SHALL call the close
  callback exactly once with one cause and an exit status only for `exit`:
  `exit` for the shell's own exit; `superseded` for `SUPERSEDED@minimal.dev`;
  `credential_expired` for `EXPIRED@minimal.dev`; `revoked` for
  `REVOKED@minimal.dev`; `daemon_shutdown` for `SHUTDOWN@minimal.dev`
  (the daemon's exit signals, MMI-053); `tunnel_lost` for a transport loss
  (MCC-013); `closed` when the head closed it (MCC-022).
  tier:     T0
  verify:   just wasm-core-headless close_causes_are_distinct_and_status_only_on_exit
  - IF `SUPERSEDED@minimal.dev` arrives on a channel the core is itself
    replacing during a renewal (MCC-069) THEN THE SYSTEM SHALL consume it
    and surface no close.
    tier:   T0
    verify: just wasm-core-headless own_renewal_supersession_is_not_surfaced

- **MCC-066** THE SYSTEM SHALL call the signer callback with the exact bytes
  to sign and require a raw signature back — 64 bytes for Ed25519, and
  64 bytes r ‖ s for P-256 under the FIPS profile, the algorithm being the
  head key's — performing every SSH and JWS encoding itself (MCC-030).
  tier:     T0
  verify:   just wasm-core-headless signer_gets_bytes_and_returns_a_raw_signature

- **MCC-067** THE SYSTEM SHALL perform the token exchange, refresh, certify,
  anchors fetch, mesh-bind, node listing, peer-document fetch, relay-ticket
  request, renewal and the revoke at sign-out itself over the HTTP call the
  host supplies, which follows no redirect (a 3xx answer is a refused call,
  MCC-081), produce the authorization URL the page navigates to, and
  consume the callback the page hands back, checking its `state` against
  the request and its `iss` against the issuer set before exchanging; the
  check is set membership, not equality with the issuer the request
  started at, because the front door may land a sign-in on a tenant
  issuer (Gatehouse §6.1.6); the page composes none of these requests.
  tier:     T0
  verify:   just wasm-core-headless credential_helpers_run_in_the_core_over_the_supplied_fetch
  - IF the callback's `iss` is outside the issuer set or its `state` does
    not match THEN THE SYSTEM SHALL exchange nothing and report a sign-in
    failure naming neither the issuer nor the code (WMC-001).
    tier:   T0
    verify: just wasm-core-headless foreign_iss_or_bad_state_exchanges_nothing

- **MCC-068** THE SYSTEM SHALL send the certify request and read its
  response as Gatehouse §6.6 shapes them, fetch anchors as §8.2 shapes
  `GET {iss}/v1/ssh/ca`, and read the node listing and the peer document as
  §8.2 shapes `GET {iss}/v1/nodes` and `GET {iss}/v1/mesh/peers`.
  tier:     T0
  verify:   cargo nextest run -p min-core certify_and_anchors_exchanges_match_gatehouse

- **MCC-069** WHILE an attachment is open THE SYSTEM SHALL renew (MCC-039)
  by attaching on the new connection with the fresh certificate first, then
  closing its old channel itself — with no second attach call, no change to
  the attachment object and no close callback, the head observing only the
  repaint (MCC-063) — within the chain cap (MCC-040); a
  `SUPERSEDED@minimal.dev` the daemon sends on the old channel (MMI-053) is
  consumed (MCC-065).
  tier:     T0
  verify:   just wasm-core-headless renewal_is_invisible_to_the_page

- **MCC-070** THE SYSTEM SHALL consume the subject's peer document as
  Gatehouse §6.9 and §8.2 shape it, taking per subject and mesh the head's
  tunnel address and prefix, and per node its identity, `wg_pub`, tunnel
  address, allowed IPs, SSH port, expected host principal, `td` (checked
  against the credential's trust domain, MCC-038) and reachability options
  — a direct endpoint and/or a home relay dialed with a ticket; liveness,
  `last_seen` and the display name come from the node listing (MCC-015).
  tier:     T0
  verify:   cargo nextest run -p min-core peer_document_maps_onto_the_attach_configuration
  - THE SYSTEM SHALL reject a document whose `seq` regresses below the last
    one accepted for that (audience, mesh), and SHALL treat a document
    older than `issued_at` + 5 min as expired: no new tunnel is opened from
    it, while an established tunnel rides its binding's TTL (§6.9).
    tier:   T0
    verify: cargo nextest run -p min-core stale_or_regressed_peer_document_opens_no_new_tunnel

- **MCC-071** WHEN dialing through a relay THE SYSTEM SHALL present the
  node's ticket (Gatehouse §6.9, issued under `ReadNode`, §7.4) opaque and
  unmodified at WebSocket open, with a DPoP proof over it and the head's
  mesh binding, from which the relay takes the client's mesh public key
  (MMI-071; a shared interim, Open questions); use a ticket only for its
  node; and obtain a new one when the relay reports it expired.
  tier:     T0
  verify:   cargo nextest run -p min-core relay_ticket_is_opaque_per_node_and_presented_at_open

- **MCC-072** THE SYSTEM SHALL run the browser's v1 command set — list
  sessions, show, rename, stop and version — through the RPC driver
  (MCC-023) over the selected node's tunnel with MCC-064's taxonomy; stop
  is the daemon's `StopSession` (MMI-028), ending the process and keeping
  the record; the daemon evaluates each as Gatehouse §7.4 maps it, sessions
  being boxes, with the owner rule as the ratified interim (MMI-025,
  MMI-027).
  tier:     T0
  verify:   just wasm-core-headless v1_rpcs_run_through_the_driver_with_the_attach_taxonomy

- **MCC-073** THE SYSTEM SHALL publish the wasm module and its JS glue as
  content-addressed assets with one manifest per CLI release, and `min`
  SHALL verify a served bundle's hash against the manifest of the release
  whose core version the bundle reports (MCC-074), refusing a bundle whose
  core release is older than `min`'s own, so that a server cannot roll a
  client back to an older valid bundle.
  tier:     T0
  verify:   cargo nextest run -p minimal served_bundle_hash_verifies_against_the_release_manifest

- **MCC-074** THE SYSTEM SHALL expose, before any network activity, its
  version and `protocol_window` (MCC-006); a daemon outside the window is
  refused per MCC-006 and surfaced as `version:` (MCC-064).
  tier:     T0
  verify:   just wasm-core-headless version_signal_is_exposed_before_dialing

- **MCC-075** THE SYSTEM SHALL run the browser bundle with
  `'wasm-unsafe-eval'` as the only script-source allowance beyond `'self'`,
  needing no `'unsafe-eval'` and no inline script (WMC-035, WMC-036).
  tier:     T0
  verify:   just wasm-core-headless bundle_runs_without_unsafe_eval_or_inline_script

- **MCC-076** WHERE the head is a browser THE SYSTEM SHALL hold tokens,
  certificates, the binding and the mesh key in memory only, the bundle
  importing no storage capability (WMC-004).
  tier:     T0
  verify:   just wasm-core-headless bundle_imports_no_storage_capability

- **MCC-077** WHERE the head is a browser THE SYSTEM SHALL take the signing
  key only as a signer callback; no entry point of the bundle accepts
  private-key bytes (WMC-003).
  tier:     T0
  verify:   just wasm-core-headless browser_entry_points_accept_no_private_key

- **MCC-078** THE SYSTEM SHALL open network connections only to the
  credential's issuer, the node endpoints the configuration names, and the
  relays the configuration names.
  tier:     T1
  verify:   just wasm-core-headless bundle_dials_only_the_issuer_and_configured_endpoints
  property: for every configuration (issuer, node endpoints, relays) and every dial the core requests of the host through its pipe, the target is that issuer, a named node endpoint or a named relay

- **MCC-079** THE SYSTEM SHALL deliver the stripped wasm module at no more
  than 600 KB gzip-compressed and its JS glue at no more than 20 KB,
  measured at each release (WMC-N02 cites the module ceiling).
  tier:     T0
  verify:   just wasm-core-budget

- **MCC-080** WHEN a head asks for status THE SYSTEM SHALL report the
  certificate's serial and remaining lifetime, the tunnel path in use and
  the age of its last handshake, and the last error of MCC-064 or MCC-065,
  from memory, persisting nothing.
  tier:     T0
  verify:   just wasm-core-headless status_reports_certificate_tunnel_and_last_error

- **MCC-081** IF a credential call of MCC-067 fails THEN THE SYSTEM SHALL
  report it to the head in one of two shapes: `credential: refused (<code>)`
  when the issuer answered with an error, carrying its code and reason
  verbatim; `credential: unreachable` when no well-formed answer arrived
  within 10 s at the injected clock, the call being cancelled at that
  bound, carrying the transport detail (WMC-006, WMC-007).
  tier:     T0
  verify:   just wasm-core-headless credential_call_failures_are_refused_or_unreachable
  - IF the call that failed was a renewal during an open attach THEN THE
    SYSTEM SHALL keep the attachment open and report the failure through
    the status accessor (MCC-080) until the certificate expires (MCC-039).
    tier:   T0
    verify: just wasm-core-headless renewal_failure_is_reported_without_closing_the_attachment

## Non-goals

- The daemon's ingress, certificate-auth surface and allowlist, host
  certificate, terminal state and repaint, exit signals and the relay
  service: the mesh-ingress spec (MMI, #1356), which the networking spec in
  preparation may supersede.
- The browser page — origin, policy, integrity loading, key generation,
  storage, reconnect cadence, rendering, mobile layout: the browser client
  spec (WMC, webapp#763).
- The identity plane's capabilities this core consumes — the `public`
  client kind, certify, node listing and heartbeat, relay tickets, the peer
  document, the mesh-attach host principal, the session-operation decisions:
  Gatehouse §6.1.7, §6.6, §5.7, §8.2, §6.9, §5.3 and §7.4 (v1.11 to
  v1.16), implemented by the identity plane's own specs.
- The mobile app and its in-process network stack: the same core, plan S13;
  nobody owns it yet.
- Session recording: plan S9 and Gatehouse §14.4(1); nobody owns it yet.
- Sharing a session and teammate access: gominimal/inbox#480 and plan S8;
  nobody owns it yet.
- Creating a session, workspace sync, loadouts, hooks, diagnostics and agent
  dispatch from the browser: WMC's non-goal on the page side; agent dispatch
  is G4 of gominimal/inbox#494; a daemon-side checkout (plan S8) has no
  owner yet.
- Copying files into or out of a box, the epic's "Sync Files Out" story:
  no spec binds it yet; nobody owns it.
- GitHub sign-in ceremony and credential-free git from sessions: the GitHub
  sessions spec (GHS, #1351); MCC-050 is the credential it rides on.
- Hosts reached only through providers in the client-managed provider list,
  un-enrolled with the identity plane: outside the browser listing in v1
  (Gatehouse §8.2 scope decision); the provider's own view of a host is BPA
  (arch#45); a server-side provider list has no owner yet.
- The CLI's auth status command and any performance bound on the core: the
  command is the architecture's CLI reference (`min auth`); the proof of
  concept's loopback measurements are recorded in the direction plan, and
  no bound is set until an owner sets one.

## Design reasoning

**One core, several heads** (decided 2026-09-03, plan §3.1). Tailscale's Go
browser client and a purpose-built TypeScript thin client were the
alternatives; both put a second implementation of the mesh peer, the SSH
client and host trust beside the CLI's, and the first brings a second
identity system whose SSH skips host-key verification, against Gatehouse
§6.2. One Rust core is the literal form of "the website is just one more
client" (minimal-hosted §1); the proof of concept priced it at 91 KB gzip
for the network layer.

**Crate shape** (plan §4.3; mechanism, so it lives here and not in the
requirements). `min-core`, wasm-clean, holds the network layer, attach,
RPC driver, credential module and host policy; `min-core-web` is the
wasm-bindgen head; `min-wire` carries the wire types shared with the
daemon. The cryptographic backend is a target-gated feature, `ring` for the
browser. The host injects the clock, so every time-dependent decision is
testable at a fixed instant; the properties above say "at the injected
clock" for that reason. Promotion updates the crate table in AGENTS.md and
the architecture overview (plan S5).

**The tab is a mesh node and no server is in the session path** (decided
2026-09-03, plan entries 12, 18, 23, 24; Gatehouse §6.9 and architecture
D7 since v1.12). Servers remain for the page, the identity plane and a
stateless relay forwarding ciphertext for daemons behind NAT; none holds a
box credential or sees SSH bytes (T29). The tab dials direct first
(MCC-014) and opens a relay socket with a per-node ticket that authorizes
routing only (MCC-071). Whether that shape survives — a tab as a WireGuard
peer, or a tab dialing a host's gateway ingress — is the networking spec's
to decide (decided 2026-09-09); this document moves no transport text until
it exists, and MMI, which this document binds for ingress and the relay,
may fold into it.

**A public client with tokens in memory** (decided 2026-09-03, entries 10,
15 to 17; Gatehouse §6.1.7 since v1.11). With no backend, only the tab can
hold tokens, and every token is sender-constrained to a non-extractable key
(§5.4). §6.6 lets the certified key equal the DPoP key and the core signs
both through one head key (MCC-042); §6.1.7's "a fresh in-tab SSH key" is
read as permitting that and carried as an open question. What outlives the
process is the head's: nothing in the browser (MCC-076), the CLI's refresh
token in its store (MCC-050). The bundle is content-addressed with one
manifest per CLI release (MCC-073), the pipeline's per-commit release
making a pre-release bundle's checksums and its manifest one artefact.

**A 15-minute certificate with transparent renewal, capped** (decided
2026-09-03, entries 7, 8, 22; Gatehouse §5.7 and §6.1.7 since v1.11). The
`interactive` 8 h profile would keep §5.7's wall warnings at the price of an
8 h window for an XSS that drives the key; `exchange` at 15 min keeps the
window short and makes reconnect a core duty (MCC-039). Unattended renewals
stop at 8 h and without an open attach (MCC-040): the same envelope as a
CLI certificate, delivered as up to 32 short ones. Presence is a user
gesture at the tab at the initial certify only, never a fresh sign-in; the
identity plane's browser session may complete the certify silently. Where
the tenant opt-in for `box:ssh` and `JoinMesh` lives is WMC's question. An
identity-plane outage detaches at the next renewal with no grace period,
which is why the daemon's repaint is a v1 prerequisite (MCC-063).

**Re-attach ownership** (decided 2026-09-04). A transport-initiated loss
closes the attachment once with `tunnel_lost`, and any re-attach is the
head's new attach call at its own cadence (MCC-057; WMC-026, WMC-028),
because when a head wants to be attached is a policy no head can express to
the core. A core-initiated reconnect, the transparent renewal, keeps the
attachment object and shows the head only the repaint (MCC-069); the
daemon's supersession of the old channel is consumed, never surfaced
(MCC-065), so WMC-030's "attached elsewhere" stays distinct.

**Host-certificate revocation** (decided 2026-09-04). v1 runs the host
policy with an empty revocation set (MCC-032); a compromised host key stays
acceptable until its 30-day certificate expires (Gatehouse §5.7) or the
Host CA rotates. Carried as an open question.

**The expected principal is the node's canonical name** (Gatehouse §5.3,
v1.15). A mesh attach dials a tunnel address and verifies the certificate
against `<node_id>.box.<td>`, which the peer document names; tunnel
addresses are never principals and owe no stability, so renumbering forces
no host-cert renewal. The core checks natively (MCC-032); the CLI's
`known_hosts` fragment (MCC-052) is the `HostKeyAlias` form of the same
rule.

**Constants.** 60 s silent-peer (MCC-013) is two 25 s keepalive intervals
plus a 10 s margin for a late one; 20 s
to the first handshake response (MCC-011) is four WireGuard retries at 5 s;
10 s for the version exchange (MCC-006) and for a credential call
(MCC-081), and 30 s for the whole attach (MCC-060), are the handshake bound
plus key exchange, authentication and the attach requests, which the proof
of concept measured at 55 ms median on loopback; a direct dial that fails
at 20 s leaves 10 s for the relay fallback (MCC-014).

**Credential helpers run in the core over an injected HTTP call** (decided
2026-09-04, MCC-067). Renewal must run inside the core during an open
attach, and one request shape across heads is the point of sharing, so the
core composes and parses every issuer request and the host executes it; the
page only navigates the authorization leg. Anchors are pinned to the issuer
the credential names (MCC-038): a peer document may repeat that issuer,
never select it.

**In-memory mesh key, Ed25519 first** (decided 2026-09-03, entries 3, 11).
The WireGuard implementation takes the static secret as bytes, so a
WebCrypto-held X25519 key needs a static-DH hook in the noise core; v1
accepts an in-memory key rotated per page session and bounded by the 8 h
binding (MCC-041), the held key being plan S13. The CLI's node key lives
as long as the mesh membership (MCC-053). P-256 is a one-variant fallback
for the FIPS profile, covered by MCC-030's property.

**Listing is the identity plane's node set plus heartbeats** (decided
2026-09-03, entry 21; Gatehouse §8.2 since v1.13). The tab reads nodes,
liveness and `last_seen` in one call, owner-only in v1, and handshakes only
with the node it attaches to (MCC-015, MCC-017); a proof-of-concept design
that opened a tunnel per node for liveness was retired by it. The same
`ReadNode` decision gates relay-ticket issuance, so what a head can list
and what it can dial never drift apart. Bindings authorize; the peer
document configures, with its `seq` and staleness bound enforced in the
core (MCC-070).

**CLI adoption order** (decided 2026-09-03, entry 6). The target is the
in-process attach (MCC-052); the first step shares the non-TTY parts and
keeps the `ssh` binary for TTY attach with a `known_hosts` fragment from
the same policy, because that changes a daily-driver path last. The CLI
keeps what the browser must not: a refresh token with background renewal
(MCC-056), a node key for the membership's lifetime (MCC-053), and its own
reconnect cadence (MCC-057).

**Bundle budget** (decided 2026-09-03, entry 25). 447 KB gzip was accepted
for v1 and the certificate path measured 501 KB stripped; MCC-079 bounds
the module at 600 KB and the glue separately. The diet is later work.

**Retired identifiers**, never reused. MCC-004 (the crypto backend as a
feature) and MCC-007 (crate boundaries) were retired on 2026-09-04 and
2026-09-09 as mechanism, now the Crate shape paragraph. On 2026-09-09,
under the rule that a requirement traces to an acceptance criterion or a
recorded decision: MCC-005 (decisions at the injected clock) was mechanism,
kept as the seam the properties name; MCC-055 duplicated MCC-033 and
GHS-009; MCC-058 (`min auth status`) had neither a criterion nor a
decision behind it; MCC-N01 to MCC-N03 were proof-of-concept measurements
with headroom, not bounds anyone set.

**Working assumptions.** Recorded in WMC and confirmed 2026-09-04: A1, the
v1 browser command set is owner-only attach (MCC-020, MCC-060) plus list
sessions, show, rename, stop and version over the RPC driver (MCC-072;
Gatehouse §7.4 since v1.16 maps them, sessions being boxes); A2,
the plan's decisions stand; A3, the browser client lives on its own origin
(MCC-075). Overturning one changes the requirements it names, not the
core's shape.

**Tiers.** Ten universals are at T1 because each is a pure function over
owned values a property test can drive across its input space: the
signer's output shape (MCC-030), the host-policy and certificate decisions
(MCC-032, MCC-034), and — since the injected clock, the signer seam and the
HTTP callback make them decisions over values the core owns — the
version-window refusal (MCC-006), DPoP on every composed request (MCC-036),
the anchor source (MCC-038), the renewal-chain cap (MCC-040), the browser
mesh key's lifetime (MCC-041), the key's permitted signing inputs
(MCC-042) and the dial set (MCC-078). The property-testing dependency is
confined to `min-core`'s development dependencies. T2 was declined because
the decisions include a signature verification no bounded harness can
exhaust. The invariant-covering requirements at T0 stay there for a reason
each: MCC-035 exercises a live issuer and its universals are MCC-030's and
MCC-036's; MCC-039 and MCC-069 drive a live tunnel and the instant they act
is MCC-040's property; MCC-051 dispatches to MCC-032's property; MCC-066
is MCC-030's property seen from the browser head; MCC-073 is one hash
comparison per release; MCC-074 is an ordering check at the entry point;
MCC-076 and MCC-077 are exhaustive over the bundle by construction.
Everything else is T0 because it reaches a socket, a daemon or a browser.

**Verification mechanics.** Native tests run under `cargo nextest` through
`just test`; `just wasm-core` builds the bundle; `just wasm-core-headless`
drives it from Node against a native stand-in through the
certificate-authenticated attach and inspects the module's import section;
`just wasm-core-budget` measures MCC-079. MCC-022 uses the daemon side's
harness. Page behaviour is verified in WMC; this spec names no test of
WMC's.

**Generality:** A second head fits by construction: the mobile app is the
same core behind a UDP datagram pipe and a keystore-backed signer; the CLI
is the same core behind a local socket and an agent-backed signer. A second
daemon fits if it terminates SSH inside the tunnel the networking spec
chooses and presents a Gatehouse host certificate. A second identity plane
does not fit: the certify, anchors, peer-document and ticket shapes
(MCC-068, MCC-070, MCC-071) are Gatehouse's by decision, acceptable because
Gatehouse is the only identity plane in the system.

## Security considerations

- **Invariant:** THE SYSTEM SHALL never hold, read or export a head's
  signing key in its attach or credential paths; every signature is the
  head's signer's, over bytes the core supplies.
  enforced by: the signer seam as the only signing path, and the browser's
  non-extractable key behind a callback (WMC-003).
  covered by: MCC-030, MCC-066, MCC-077
- **Invariant:** THE SYSTEM SHALL attach to no host reached over a
  transport other than a local UDS or vsock without a host certificate
  verifying, for the expected principal, against anchors taken from the
  tenant issuer only.
  enforced by: the host policy in the server-key check, aborting before
  authentication (Gatehouse §6.2, no TOFU); the anchors fetch bound to the
  issuer the credential names.
  covered by: MCC-032, MCC-038, MCC-051
- **Invariant:** THE SYSTEM SHALL present no bearer credential and derive
  no SSH-PoP assertion from a head's key; every issuer, relay and node
  request is DPoP-bound or certificate-authenticated.
  enforced by: DPoP proofs on every request and PKCE with `dpop_jkt` at
  sign-in (Gatehouse §6.1.1); the head's key used for DPoP and SSH
  authentication only.
  covered by: MCC-035, MCC-036, MCC-042
- **Invariant:** THE SYSTEM SHALL renew a browser credential unattended for
  at most 8 h and only while an attachment is open, and hold a browser mesh
  key for at most 8 h.
  enforced by: the renewal-chain cap and the binding TTL (Gatehouse §6.9,
  T22).
  covered by: MCC-039, MCC-040, MCC-041, MCC-069
- **Invariant:** THE SYSTEM SHALL persist no token, certificate, key handle
  or mesh key in a browser, and open no connection from the bundle to an
  endpoint other than the credential's issuer and the configured
  endpoints.
  enforced by: in-memory holders, a bundle importing no storage capability,
  and the core dialing only the issuer and configured endpoints.
  covered by: MCC-076, MCC-078
- **Invariant:** THE SYSTEM SHALL publish every bundle content-addressed
  under a release manifest `min` verifies a served bundle against, and fail
  closed on a daemon outside its protocol window; running only a bundle
  whose hash matches is the page's invariant (WMC-036).
  enforced by: content-addressed assets with one manifest per release, and
  version negotiation before any session operation.
  covered by: MCC-006, MCC-073, MCC-074

## Open questions

- [NEEDS CLARIFICATION (MEDIUM): One key or two. Gatehouse §6.1.7 mints the
  browser client's certificate "onto a fresh in-tab SSH key" and §6.6 says
  the certified key "needn't equal the DPoP key"; MCC-042 and WMC-003 sign
  both with one head key, as the proof of concept did.] Survives because
  only the identity plane's owner can say which wording rules.
- [NEEDS CLARIFICATION (MEDIUM): The relay ticket's claim set (Gatehouse
  §6.9) carries no mesh public key, which the relay needs to address frames
  (MMI-077). MCC-071 presents the head's binding beside the ticket and the
  relay takes the key from it (MMI-071); the daemon side asks the
  architecture whether a `wg_pub` claim is wanted instead. A per-node
  friendly name in the peer document is requested for the same reason;
  MCC-070 takes it from the node listing until then.] Survives because both
  are additions to an approved document and belong with its owner.
- [NEEDS CLARIFICATION (MEDIUM): Host-certificate revocation. v1 checks no
  KRL for host certificates (MCC-032). Does the identity plane want the
  client to consult the KRL for host serials, and from which feed?]
  Survives because the identity plane has not said.
- [NEEDS CLARIFICATION (MEDIUM): The CLI's mesh node key lifetime and
  rotation. MCC-053 keeps it for the membership's lifetime; whether it
  rotates on a schedule, on `min auth login`, or only on re-join, and what
  the daemon's binding check (MMI-010) needs from a rotation, is unset.]
  Survives because it is the networking spec's territory once that exists.
- [NEEDS CLARIFICATION (MEDIUM): The SSH username under certificate
  authentication. MCC-021 binds the box login principal as the interim
  MMI-024 admits; whether the canonical subject with the daemon deriving
  the sandbox user replaces it is the daemon side's to decide.] Survives
  because the daemon side has not decided.
- [NEEDS CLARIFICATION (MEDIUM): The default width of `protocol_window`
  (architecture open gap 8). MCC-006 and MCC-074 bind to the window; its
  default is unset.] Survives because the architecture owns the gap.
- [NEEDS CLARIFICATION (MEDIUM): The wasm head's packaging for the webapp —
  npm versioning of `min-core-web`, the wasm-bindgen pin policy, and how the
  webapp consumes the release manifest of MCC-073.] Survives because it
  needs the page's owner and the release pipeline's together.
- [NEEDS CLARIFICATION (LOW): Whether the daemon's WireGuard pump moves onto
  the core's network layer or keeps its own driver over the same crate.]
  Survives because it is invisible to this spec's behaviours and the
  daemon side's call.
- [NEEDS CLARIFICATION (LOW): Interoperability with WireGuard peers that are
  not the daemon's implementation; MCC-011 is proven
  implementation-to-implementation only.] Survives because no second peer
  exists to test against.
