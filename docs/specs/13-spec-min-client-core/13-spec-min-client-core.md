---
id: MCC
title: "Shared min client core: one Rust core for the CLI, the browser and mobile"
status: draft
owner: mitodrummer
epic: gominimal/inbox#513
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-04
---

# MCC — Shared min client core: one Rust core for the CLI, the browser and mobile

## Context

A developer reaches a session only from the machine that runs `min`. There is
no browser client, no credential plane in the CLI (a local socket is the whole
trust boundary), and no client code a second head could reuse. The "Mobile /
Web Browser" story below needs a client that lives in a tab, and the owner's
direction rules out any server in the session path: the tab is itself a mesh
node and SSH terminates in it.

After this ships one Rust core carries the mesh peer, the attach sequence, the
RPC driver, the credential flow and host trust for every head: the `min` CLI,
the browser bundle, and later a mobile app. The direction and its decisions
are in [the direction plan](../../../plans/browser-min-client-direction.plan.md);
the identity plane is
[Gatehouse](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).
Neither is restated here.

**Success:** A developer signed in with GitHub attaches from a browser tab to a
session on a `minimald` they own, over a WireGuard tunnel the tab runs, with
SSH terminating in the tab, authenticated by a certificate on a key the tab
cannot export and the host verified against the tenant's Host CA; and the same
`min` binary attaches to the same session through the same core.

**First slice:** The core promoted from the proof of concept with its native
tests green, the browser bundle driven headlessly from Node through a full
attach with certificate authentication and host verification against a
stand-in daemon, and `min` issuing its non-TTY RPCs through the core.

## Users and stories

**Roles:** developer using long-running agentic workflows; developer running
sessions both locally and remote; the author of the browser client spec in
gominimal/webapp (id WMC, gominimal/webapp#763), who consumes the contract
group below.

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
- AS A first-time developer (gominimal/inbox#494, G3), I WANT to see my boxes
  and sessions from both the shell and the browser, SO THAT a session is
  reachable from wherever I am.

## Requirements

### Core boundary (MCC-001–007)

- **MCC-001** THE SYSTEM SHALL provide the network layer, the attach sequence,
  the RPC driver, the credential module and host policy from one source tree
  that builds and passes its tests for `wasm32-unknown-unknown` and the native
  host targets alike.
  tier:     T0
  verify:   just wasm-core-headless one_source_tree_attaches_on_the_wasm_target

- **MCC-002** THE SYSTEM SHALL import into the browser bundle no filesystem,
  terminal, process-spawning, OS-socket or OS-timer capability; the host
  supplies the byte stream or datagram pipe, the clock, the timer, the HTTP
  call and the signer.
  tier:     T0
  verify:   just wasm-core-headless bundle_imports_no_host_capability

- **MCC-003** THE SYSTEM SHALL decode a daemon's answer in the core and in the
  CLI from one definition of the wire types the heads and the daemon share:
  version, sessions, records, screens, mesh status, rename, stop, destroy,
  abort and exec.
  tier:     T0
  verify:   cargo nextest run -p min-wire core_and_cli_decode_from_one_wire_definition

- **MCC-005** THE SYSTEM SHALL make every time-dependent decision —
  certificate validity, renewal scheduling, keepalive, dead-peer detection,
  every timeout below — at the clock the host injects, so a test at a fixed
  instant decides as the running system would at that instant.
  tier:     T0
  verify:   cargo nextest run -p min-core time_dependent_decisions_follow_the_injected_clock

- **MCC-006** WHEN the core connects to a daemon THE SYSTEM SHALL negotiate the
  protocol version before any session operation, report both versions to the
  head, and refuse a daemon outside the supported window naming both versions
  and the remedy, or one that has not answered the version exchange within
  10 s at the injected clock, naming the timeout.
  tier:     T0
  verify:   cargo nextest run -p min-core version_outside_window_fails_closed_naming_both_versions

- **MCC-007** THE SYSTEM SHALL carry no host-only dependency in the wire types
  the browser uses, so the browser bundle is built from the same definition
  the CLI decodes (MCC-003).
  tier:     T0
  verify:   cargo nextest run -p min-wire wire_types_carry_no_host_only_dependency

### Transport and network layer (MCC-010–017)

- **MCC-010** THE SYSTEM SHALL run the attach sequence and the RPC driver over
  any byte stream the host supplies — a local socket, a TCP stream inside the
  tunnel, an in-memory pipe under test — exchanging the same messages with
  the daemon on each.
  tier:     T0
  verify:   cargo nextest run -p min-core same_attach_sequence_over_pipe_socket_and_tunnel

- **MCC-011** WHEN the host supplies a datagram pipe and a peer configuration
  THE SYSTEM SHALL complete a WireGuard handshake with that peer and open TCP
  connections inside the tunnel, the host supplying only the two datagram
  queues and the clock.
  tier:     T0
  verify:   cargo nextest run -p min-core ssh_attach_through_the_tunnel
  - IF no handshake response arrives from the peer within 20 s at the
    injected clock THEN THE SYSTEM SHALL fail the dial with a `transport:`
    outcome (MCC-064) naming the endpoint tried.
    tier:   T0
    verify: cargo nextest run -p min-core silent_handshake_fails_after_20s_at_the_injected_clock

- **MCC-012** WHERE the datagram pipe is a WebSocket THE SYSTEM SHALL carry
  exactly one WireGuard datagram per binary frame in each direction.
  tier:     T0
  verify:   cargo nextest run -p min-core attach_over_websocket_carried_wireguard

- **MCC-013** WHEN the datagram pipe closes or errors THE SYSTEM SHALL fail
  every TCP stream inside the tunnel and end every attachment and RPC on it
  with a `tunnel_lost` outcome (MCC-065); the attachment is then closed, and
  any re-attach is a new attach call by the head at the head's own cadence
  (MCC-057 for the CLI; WMC-026 and WMC-028 for the page).
  tier:     T0
  verify:   cargo nextest run -p min-core dead_websocket_reaches_the_ssh_layer
  - IF the pipe stays open but no datagram arrives from the peer for 60 s at
    the injected clock THEN THE SYSTEM SHALL treat the tunnel as lost.
    tier:   T0
    verify: cargo nextest run -p min-core silent_peer_is_lost_after_60s_at_the_injected_clock

- **MCC-014** WHEN a node's reachability options include a direct endpoint THE
  SYSTEM SHALL dial it first, and SHALL dial the node's relay endpoint with
  the node's ticket only when the direct dial fails or none is offered.
  tier:     T0
  verify:   cargo nextest run -p min-core direct_endpoint_first_relay_as_fallback

- **MCC-015** WHEN a head lists nodes THE SYSTEM SHALL return the peer
  document's node set with the liveness and `last_seen` the identity plane
  reports (MCC-070), opening no tunnel.
  tier:     T0
  verify:   cargo nextest run -p min-core listing_opens_no_tunnel

- **MCC-016** WHEN the host resumes the core after a suspension, such as a tab
  returned to the foreground, THE SYSTEM SHALL re-evaluate the tunnel at the
  injected clock on the first tick and, where it is lost (MCC-013), end the
  attachment with `tunnel_lost` within 1 s of resume rather than leave it
  hung; re-attaching is the head's own call (MCC-057, WMC-028).
  tier:     T0
  verify:   cargo nextest run -p min-core resume_after_suspension_surfaces_the_lost_tunnel_within_1s

- **MCC-017** WHEN a head selects a node THE SYSTEM SHALL open one tunnel to it
  and list its sessions through the RPC driver (MCC-072); WMC-013 consumes
  the listing.
  tier:     T0
  verify:   cargo nextest run -p min-core selecting_a_node_opens_one_tunnel_and_lists_its_sessions

### Attach and RPC (MCC-020–024)

- **MCC-020** WHEN a head attaches THE SYSTEM SHALL authenticate, open one
  session channel, set the session identifier, request a PTY of the given
  size and a shell, then deliver output and the daemon's error stream in
  order, forward input and window changes, and deliver the exit status.
  tier:     T0
  verify:   cargo nextest run -p min-core attach_write_resize_exit
  - IF the daemon refuses the shell — no session identifier, no PTY, an
    unknown session — THEN THE SYSTEM SHALL report which request was refused,
    an unknown session distinguishably (the `attach:` stage of MCC-064).
    tier:   T0
    verify: cargo nextest run -p min-core shell_is_refused_without_a_session_id

- **MCC-021** THE SYSTEM SHALL present as the SSH username the principal the
  head supplies: `minimal-cli` under local trust, the certificate's box login
  principal under certificate authentication.
  tier:     T0
  verify:   cargo nextest run -p min-core ssh_username_is_the_heads_input

- **MCC-022** WHEN a head closes an attachment THE SYSTEM SHALL close the
  channel and nothing else, leaving the session running and detached.
  tier:     T0
  verify:   cargo nextest run -p minimald core_close_detaches_and_leaves_the_session_running

- **MCC-023** WHEN a head issues a oneshot RPC THE SYSTEM SHALL open a session
  channel, request the RPC's subsystem, send one request, half-close, and
  return the answer or the daemon's error text; a refused subsystem is
  reported naming the RPC, never left hanging.
  tier:     T0
  verify:   cargo nextest run -p min-core oneshot_rpc_returns_answer_error_or_refusal

- **MCC-024** WHEN `min` runs a non-PTY command against a session — its exec
  and task paths — THE SYSTEM SHALL drive the exec channel with the daemon's
  exec vocabulary and propagate the exit code; the browser never requests it
  (the daemon refuses exec under `Certified`, MMI-027).
  tier:     T0
  verify:   cargo nextest run -p min-core exec_channel_speaks_the_daemon_vocabulary

### Credential, the client half (MCC-030–042)

- **MCC-030** THE SYSTEM SHALL sign every SSH authentication request and every
  DPoP proof through a signer the head supplies, handing it the exact bytes to
  sign and taking back a raw signature; the attach and credential paths SHALL
  reach the key only through that signer, never holding, reading or exporting
  it (an in-memory signer a head constructs for itself is the head's choice,
  outside those paths).
  tier:     T1
  verify:   cargo nextest run -p min-core signer_output_is_the_buffer_extended_with_the_ssh_encoded_signature
  property: for every to-sign buffer b and algorithm a ∈ {ssh-ed25519, ecdsa-sha2-nistp256}, with s the signer's raw signature over b, the bytes the core hands the SSH layer are exactly b ‖ string(string(a) ‖ string(blob(a, s))), blob being the identity for Ed25519 and the mpint pair (r, s) for P-256; and every DPoP proof is header.claims.base64url(s) with s the signer's signature over the signing input
  - IF the signer fails or returns a signature of the wrong length THEN THE
    SYSTEM SHALL abort with a signing failure and send no authentication
    request.
    tier:   T0
    verify: cargo nextest run -p min-core signer_failure_aborts_before_any_auth_request

- **MCC-031** WHEN a credential is supplied THE SYSTEM SHALL authenticate with
  the certificate and the signer only.
  tier:     T0
  verify:   cargo nextest run -p min-core valid_certificate_attaches_and_the_host_certificate_is_verified
  - IF the daemon refuses the certificate THEN THE SYSTEM SHALL report an
    authentication refusal and never retry with `auth_none`.
    tier:   T0
    verify: cargo nextest run -p min-core each_refusal_case_is_refused

- **MCC-032** THE SYSTEM SHALL accept a host off a local socket only when it
  presents a host certificate that verifies under the host policy — the
  certificate decision of MCC-034 for the host type with an empty revocation
  set (no host KRL in v1, Design reasoning) and the expected principal named
  exactly or by the per-node wildcard `*.<node_id>.box.<td>` — refusing
  anything else before authentication with the failing check named.
  tier:     T1
  verify:   cargo nextest run -p min-core host_policy_accepts_iff_every_check_holds
  property: for every (certificate, anchors, expected, now): accept ⇔ decision(certificate, anchors, host, now, revoked = ∅) = ok (MCC-034) ∧ (expected ∈ principals ∨ ∃ p ∈ principals: p = "*." ‖ suffix ∧ expected ends with "." ‖ suffix); a refusal names the first failing check, the decision's order first and the principal last
  - IF the host presents a bare key, a certificate from outside the anchors,
    or one for another principal THEN THE SYSTEM SHALL refuse it.
    tier:   T0
    verify: cargo nextest run -p min-core host_policy_refuses_a_wrong_principal_a_rogue_ca_and_a_bare_key
  - WHERE a principal is the per-node wildcard THE SYSTEM SHALL match every
    name under the node and no name beside it.
    tier:   T0
    verify: cargo nextest run -p min-core per_node_wildcard_principals_match_boxes_under_the_node

- **MCC-033** WHERE the transport is a local UDS or vsock THE SYSTEM SHALL
  accept the daemon without a host certificate, as today.
  tier:     T0
  verify:   cargo nextest run -p min-core local_socket_needs_no_host_certificate

- **MCC-034** THE SYSTEM SHALL provide one certificate decision naming the
  same codes the daemon's decision names (MMI-022): the seven the
  architecture's vectors expect — `bad_signature`, `unknown_ca`,
  `wrong_cert_type`, `cert_not_yet_valid`, `cert_expired`,
  `unknown_critical_option`, `cert_revoked` — and the core's own
  `principal_mismatch` for a principal the certificate does not carry.
  tier:     T1
  verify:   cargo nextest run -p min-core every_invalid_vector_is_refused_with_its_expected_error
  property: for every certificate, anchor set, expected type, clock, revocation set and principal, the decision accepts iff every check holds, and a refusal carries the code of the first failing check in the order signature, issuer, type, validity, critical options, revocation, principal
  - WHEN the architecture's user vector is presented THE SYSTEM SHALL accept
    it for its principals and refuse every other.
    tier:   T0
    verify: cargo nextest run -p min-core valid_user_vector_is_accepted_for_its_principals_only

- **MCC-035** WHEN a head signs in THE SYSTEM SHALL run the public-client
  flow — a PKCE S256 challenge and the RFC 7638 thumbprint of the signer's
  key on the authorization request, the verifier and a DPoP proof on the
  token request, refresh with rotation, the tokens held in the core's
  memory — differing between heads only in the authorization leg: the
  browser's HTTPS redirect, the CLI's device flow (GHS-006). Persistence
  beyond memory is the head's: none in the browser (MCC-076, WMC-004), the
  CLI's refresh token in its own store (MCC-050).
  tier:     T0
  verify:   cargo nextest run -p min-core login_is_pkce_and_dpop_bound_for_every_head

- **MCC-036** THE SYSTEM SHALL attach a fresh DPoP proof, signed through the
  signer, to every token, certify, mesh-bind, relay-ticket and revoke
  request it makes.
  tier:     T0
  verify:   cargo nextest run -p min-core every_issuer_request_carries_a_fresh_dpop_proof

- **MCC-037** WHEN a head requests a credential while the core holds an access
  token with `box:ssh` THE SYSTEM SHALL request a certificate for the
  signer's public key with the profile and TTL the head configures:
  `interactive` for the CLI, `exchange` with a TTL of at most 900 s for the
  browser.
  tier:     T0
  verify:   cargo nextest run -p min-core certify_carries_the_heads_profile_and_ttl

- **MCC-038** THE SYSTEM SHALL take Host CA anchors only from the CA endpoint
  of the issuer named in the credential it holds — never from the page
  origin, the peer, the relay or a peer-document field — and SHALL attempt
  no attach while it holds none.
  tier:     T0
  verify:   cargo nextest run -p min-core anchors_come_only_from_the_credentials_issuer
  - IF a peer document's issuer field differs from the credential's issuer
    THEN THE SYSTEM SHALL refuse the document and open no tunnel from it.
    tier:   T0
    verify: cargo nextest run -p min-core peer_document_with_a_foreign_issuer_is_refused

- **MCC-039** WHILE an attachment is open under a certificate THE SYSTEM SHALL
  obtain a fresh certificate 120 s before the current one expires,
  re-handshake over the same tunnel, re-attach, and continue with the
  attachment object unchanged (MCC-069) and no action from the user.
  tier:     T0
  verify:   cargo nextest run -p min-core renewal_reattaches_before_expiry_at_the_injected_clock
  - IF the issuer cannot be reached in time THEN THE SYSTEM SHALL let the
    attachment end at expiry with `credential_expired` (MCC-065), leave the
    session detached, and retry nothing itself; the re-attach is the head's
    new attach call at the head's cadence (WMC-007 for the page, MCC-057 for
    the CLI).
    tier:   T0
    verify: cargo nextest run -p min-core issuer_outage_ends_attach_at_expiry_with_credential_expired

- **MCC-040** WHERE the head is a browser THE SYSTEM SHALL renew without user
  presence only while an attachment is open and less than 8 h have passed
  since the presence-backed initial certify that began the chain (plan entry
  8); past either bound, the next attach requires a presence-backed certify.
  The CLI's rule is MCC-056.
  tier:     T0
  verify:   cargo nextest run -p min-core renewal_chain_stops_at_8h_or_without_an_open_attach

- **MCC-041** WHERE the head is a browser THE SYSTEM SHALL generate a fresh
  WireGuard keypair in memory per page session, request a binding for its
  public key under the DPoP-bound token, use it for at most 8 h, and discard
  it when the page session ends. The CLI's node key is MCC-053's.
  tier:     T0
  verify:   cargo nextest run -p min-core browser_mesh_key_is_fresh_per_page_session_bound_and_discarded

- **MCC-042** THE SYSTEM SHALL use a head's signing key for DPoP proofs and
  SSH authentication signatures only, and SHALL derive no SSH-PoP (`sshpop`)
  assertion from it; a request to an issuer, relay or node is authenticated
  with DPoP or the SSH certificate, never with an SSH-PoP assertion.
  tier:     T0
  verify:   cargo nextest run -p min-core heads_key_signs_only_dpop_and_ssh_userauth

### CLI adoption (MCC-050–058)

- **MCC-050** WHEN a developer runs `min auth login` THE SYSTEM SHALL sign in
  through the shared credential module by the device flow (MCC-035, GHS-006),
  obtain the interactive certificate and the Host CA anchors, and keep the
  key in the CLI's own store (keychain or agent) and the refresh token in the
  CLI's credential store, neither surviving in the core's memory past the
  process.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_login_installs_certificate_and_anchors

- **MCC-051** WHEN `min` reaches a daemon over any transport other than a
  local UDS or vsock THE SYSTEM SHALL apply the host policy (MCC-032) and
  certificate authentication (MCC-031), refusing a daemon that presents a bare
  key.
  tier:     T0
  verify:   cargo nextest run -p minimal remote_daemon_needs_a_host_certificate_and_a_credential

- **MCC-052** WHEN a developer attaches to a session THE SYSTEM SHALL run the
  attach in-process through the core — raw-mode terminal, resize and signal
  handling in `min` — with no system `ssh` on the path.
  tier:     T0
  verify:   cargo nextest run -p minimal session_attach_runs_in_process_without_ssh
  - WHILE the system `ssh` remains the TTY attach path THE SYSTEM SHALL
    generate its `known_hosts` `@cert-authority` fragment from the same
    anchors and expected principal the host policy uses.
    tier:   T0
    verify: cargo nextest run -p minimal known_hosts_fragment_matches_host_policy

- **MCC-053** WHEN a developer runs `min net mesh join <network>` (today `min
  mesh join`; the architecture's command tree renames it) THE SYSTEM SHALL
  obtain the binding and the peer document through the credential module and
  bring the mesh up through the core's network layer over UDP, with no manual
  key exchange, keeping its mesh node key across invocations for the lifetime
  of the enrollment (its rotation is an open question).
  tier:     T0
  verify:   cargo nextest run -p minimal mesh_join_needs_no_manual_key_exchange

- **MCC-054** WHEN a developer lists sessions THE SYSTEM SHALL include the
  sessions on every node of the peer document, addressed and attachable with
  the same grammar as local ones.
  tier:     T0
  verify:   cargo nextest run -p minimal list_and_attach_use_one_grammar_for_mesh_nodes

- **MCC-055** WHILE a daemon is reached over a local UDS or vsock THE SYSTEM
  SHALL keep today's behaviour: `auth_none`, no host certificate, no sign-in.
  tier:     T0
  verify:   cargo nextest run -p minimal local_socket_sessions_are_unchanged

- **MCC-056** WHILE `min` holds a refresh token THE SYSTEM SHALL renew the
  interactive certificate in the background before it expires (Gatehouse
  §5.7), with no open attachment required and no chain cap beyond the refresh
  token's own lifetime.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_renews_interactive_certificate_in_background

- **MCC-057** WHEN an in-process attachment (MCC-052) ends with `tunnel_lost`
  or `credential_expired` THE SYSTEM SHALL re-attach by a new attach call,
  retrying with backoff from 1 s doubling to a 30 s cap until the daemon is
  reachable and a certificate is held again or the developer detaches,
  showing a reconnecting state on the terminal and landing on the daemon's
  repaint (MCC-063).
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reattaches_after_loss_with_bounded_backoff

- **MCC-058** WHEN a developer runs `min auth status` THE SYSTEM SHALL report
  the certificate's principals and expiry and whether a refresh token is held,
  printing neither.
  tier:     T0
  verify:   cargo nextest run -p minimal auth_status_reports_principals_and_expiry

### Browser contract (MCC-060–080)

The browser client spec in gominimal/webapp (WMC) cites these by ID.
Sub-groups: attach MCC-060–063, errors MCC-064–065, signer and credential
helpers MCC-066–069, peer document MCC-070, ticket MCC-071, rpc MCC-072,
bundle integrity MCC-073–075, custody MCC-076–078, size budget MCC-079,
status MCC-080. Page behaviour is cited to WMC by requirement ID and verified
there.

- **MCC-060** WHEN the page calls attach with one JSON configuration document,
  a signer callback, a data callback and a close callback THE SYSTEM SHALL
  resolve to an attachment offering `write(bytes)`, `resize(cols, rows)` and
  `close()`, and deliver every byte of session output and of the daemon's
  error stream, merged in order, to the data callback.
  tier:     T0
  verify:   just wasm-core-headless attach_api_shape
  - IF the attach has not reached the accepted shell within 30 s of the call
    at the injected clock THEN THE SYSTEM SHALL reject with the prefix of the
    stage reached (MCC-064).
    tier:   T0
    verify: just wasm-core-headless attach_that_never_completes_rejects_within_30s

- **MCC-061** THE SYSTEM SHALL accept as the configuration document the node's
  peer-document entry (MCC-070) as served, the session identifier, the
  terminal type and size, and an auth block naming the SSH username and the
  expected host principal, the certificate and anchors being those the core
  holds (MCC-067); the document has no scrollback field and the core declares
  no scrollback request (MMI-052 is a later daemon capability); a missing or
  malformed field rejects the promise naming the field before any network
  activity.
  tier:     T0
  verify:   just wasm-core-headless config_rejections_name_the_field_before_dialing

- **MCC-062** THE SYSTEM SHALL deliver bytes passed to `write` to the session
  PTY unmodified and in call order, and apply a `resize` to the session PTY
  in order with the writes around it.
  tier:     T0
  verify:   just wasm-core-headless input_and_resize_are_ordered_and_unmodified

- **MCC-063** WHEN an attachment is established, at first attach and after
  every transparent renewal, THE SYSTEM SHALL deliver as the first bytes to
  the data callback the first bytes the daemon writes — its reconstruction of
  the session's current screen (MMI-051) — adding nothing before them and
  asking for no scrollback ahead of them; the page's rendering of the repaint
  is WMC-029.
  tier:     T0
  verify:   cargo nextest run -p min-core first_bytes_delivered_are_the_daemons_first_bytes_unprefixed

- **MCC-064** IF the attach fails THEN THE SYSTEM SHALL reject the promise,
  with no attachment object, carrying a reason whose prefix names the stage:
  `config:`; `credential:` (the core's own pre-check of its certificate at
  the injected clock before any dial — expired, not yet valid, host or CA
  mismatch); `version:`; `transport:` (the relay named when it refused the
  ticket; a dial or handshake that did not complete in time); `host
  rejected:` with the failing check's code; `authentication rejected`;
  `signing:`; `attach:` (the daemon refused the env, pty or shell request,
  naming which, with `unknown session` distinguishable from every other
  refusal, or the channel closed before the shell was established).
  tier:     T0
  verify:   just wasm-core-headless attach_rejections_name_the_stage

- **MCC-065** WHEN an attachment ends THE SYSTEM SHALL call the close callback
  exactly once with one cause and an exit status only for `exit`, mapping
  the daemon's exit signals (MMI-053) and the transport as follows: `exit`
  for the shell's own exit; `superseded` for `SUPERSEDED@minimal.dev`
  (another client took the session over); `credential_expired` for
  `EXPIRED@minimal.dev` (the daemon ended the session at certificate expiry
  because a renewal did not land in time); `revoked` for
  `REVOKED@minimal.dev`; `daemon_shutdown` for `SHUTDOWN@minimal.dev`;
  `tunnel_lost` for a transport loss (MCC-013); `closed` when the head closed
  it (MCC-022).
  tier:     T0
  verify:   just wasm-core-headless close_causes_are_distinct_and_status_only_on_exit
  - IF `SUPERSEDED@minimal.dev` arrives on a channel the core is itself
    replacing during a renewal (MCC-069) THEN THE SYSTEM SHALL consume it and
    surface no close.
    tier:   T0
    verify: just wasm-core-headless own_renewal_supersession_is_not_surfaced

- **MCC-066** THE SYSTEM SHALL call the signer callback with the exact bytes to
  sign and require a raw signature back, 64 bytes for Ed25519, performing
  every SSH and JWS encoding itself; the page never encodes.
  tier:     T0
  verify:   just wasm-core-headless signer_gets_bytes_and_returns_a_raw_signature

- **MCC-067** THE SYSTEM SHALL perform the token exchange, refresh, certify,
  anchors fetch, mesh-bind, relay-ticket request, renewal and the
  refresh-token revoke at sign-out itself over an HTTP callback the page
  supplies, produce the authorization URL the page navigates to, and consume
  the callback the page hands back, checking its `state` against the request
  and its `iss` against the deployment issuer set before exchanging; the page
  composes none of these requests.
  tier:     T0
  verify:   just wasm-core-headless credential_helpers_run_in_the_core_over_the_supplied_fetch
  - IF the callback's `iss` is outside the issuer set or its `state` does not
    match THEN THE SYSTEM SHALL exchange nothing and report a sign-in failure
    naming neither the issuer nor the code (WMC-001).
    tier:   T0
    verify: just wasm-core-headless foreign_iss_or_bad_state_exchanges_nothing

- **MCC-068** THE SYSTEM SHALL send the certify request and read its response
  as Gatehouse §6.6 shapes them, and fetch the anchors as §8.2 shapes
  `GET {iss}/v1/ssh/ca`.
  tier:     T0
  verify:   cargo nextest run -p min-core certify_and_anchors_exchanges_match_gatehouse

- **MCC-069** WHILE an attachment is open THE SYSTEM SHALL renew (MCC-039) by
  opening the new connection and attaching with the fresh certificate first,
  then closing its old channel itself — with no second attach call, no change
  to the attachment object and no close callback, the head observing only the
  repaint (MCC-063), within the chain cap (MCC-040); where the daemon
  supersedes the old channel before the core closes it (MMI-053), the
  resulting `SUPERSEDED@minimal.dev` is consumed (MCC-065).
  tier:     T0
  verify:   just wasm-core-headless renewal_is_invisible_to_the_page

- **MCC-070** THE SYSTEM SHALL consume from the subject's peer document: per
  subject and mesh, the tab's tunnel address and prefix length; per node,
  node identity and friendly name, the node's WireGuard public key, the
  node's tunnel address, the SSH port, the expected host principal, the
  issuer field (checked against the credential's, MCC-038), the liveness the
  identity plane reports with its `last_seen` time, and the reachability
  options — a direct WebSocket endpoint and/or a relay endpoint with a
  ticket.
  tier:     T0
  verify:   cargo nextest run -p min-core peer_document_maps_onto_the_attach_configuration

- **MCC-071** WHEN dialing through a relay THE SYSTEM SHALL present the node's
  ticket opaque and unmodified at WebSocket open, use a ticket only for the
  node it was issued for, and obtain a new one when the relay reports it
  expired.
  tier:     T0
  verify:   cargo nextest run -p min-core relay_ticket_is_opaque_per_node_and_presented_at_open

- **MCC-072** THE SYSTEM SHALL run the browser's v1 command set through the RPC
  driver (MCC-023) over the selected node's tunnel with the taxonomy of
  MCC-064: list sessions → each session's name, state and last activity;
  show → a session's record and current screen; rename → the session renamed
  or the daemon's refusal; stop → `StopSession` (MMI-028): the session's
  process ended and the session listed with no running attributes; version →
  the daemon's version (MCC-006).
  tier:     T0
  verify:   just wasm-core-headless v1_rpcs_run_through_the_driver_with_the_attach_taxonomy

- **MCC-073** THE SYSTEM SHALL publish the wasm module and its JS glue as
  content-addressed assets with one `SHA256SUMS` manifest per CLI release,
  covering the bundle that release was built with, and `min` SHALL verify a
  served bundle's hash against the manifest of the release whose core version
  the bundle reports (MCC-074); checksums are per release, and the auto-cut
  `release-<sha>` releases make per-commit and per-release the same artefact
  for a pre-release bundle (what WMC-038 vendors).
  tier:     T0
  verify:   cargo nextest run -p minimal served_bundle_hash_verifies_against_the_release_manifest

- **MCC-074** THE SYSTEM SHALL expose, before any network activity, its own
  version and the daemon protocol window it speaks, so a served bundle
  reports the core version its checksums were published under (MCC-073); the
  refusal of a daemon outside the window is MCC-006's, surfaced as
  `version:` (MCC-064).
  tier:     T0
  verify:   just wasm-core-headless version_signal_is_exposed_before_dialing

- **MCC-075** THE SYSTEM SHALL run the browser bundle with `'wasm-unsafe-eval'`
  as the only script-source allowance beyond `'self'`, needing no
  `'unsafe-eval'` and no inline script; the page's policy and its loading
  under integrity are WMC-035 and WMC-036.
  tier:     T0
  verify:   just wasm-core-headless bundle_runs_without_unsafe_eval_or_inline_script

- **MCC-076** WHERE the head is a browser THE SYSTEM SHALL hold tokens,
  certificates, the binding and the mesh key in memory only, the bundle
  importing no storage capability — web storage, IndexedDB, cookies, the
  cache — so a reload re-mints through the identity plane's browser session;
  the page's own storage rule is WMC-004.
  tier:     T0
  verify:   just wasm-core-headless bundle_imports_no_storage_capability

- **MCC-077** WHERE the head is a browser THE SYSTEM SHALL take the signing key
  only as a signer callback: no entry point of the bundle accepts private-key
  bytes; the key's non-extractability is the page's (WMC-003).
  tier:     T0
  verify:   just wasm-core-headless browser_entry_points_accept_no_private_key

- **MCC-078** THE SYSTEM SHALL open network connections only to the
  credential's issuer, the node endpoints the configuration names, and the
  relays the configuration names, and to nothing else.
  tier:     T0
  verify:   just wasm-core-headless bundle_dials_only_the_issuer_and_configured_endpoints

- **MCC-079** THE SYSTEM SHALL deliver the stripped wasm module at no more than
  600 KB gzip-compressed (the core ceiling WMC-N02 cites) and its JS glue at
  no more than 20 KB, measured at each release.
  tier:     T0
  verify:   just wasm-core-budget

- **MCC-080** WHEN a head asks for status THE SYSTEM SHALL report the
  certificate's serial and remaining lifetime at the injected clock, the
  tunnel path in use (direct or relay) and the age of its last handshake, and
  the last error code of MCC-064 or MCC-065, from memory and persisting
  nothing; WMC-031 renders it.
  tier:     T0
  verify:   just wasm-core-headless status_reports_certificate_tunnel_and_last_error

## Non-goals

- The daemon's mesh ingress, certificate-auth surface and allowlist, host
  certificate, rejection delay, terminal state and repaint, supersession, the
  exit signals, and the relay service:
  `docs/specs/14-spec-minimald-mesh-ingress/14-spec-minimald-mesh-ingress.md`
  in this repo, drafted in parallel.
- The browser page — origin, policy, integrity loading, key generation,
  storage rule, reconnect cadence, rendering, mobile layout, the terminal
  emulator, its tests: the browser client spec in gominimal/webapp (WMC).
- The identity plane's capabilities — the public-client kind, certify for that
  client, the peer document and node listing, heartbeats, relay tickets, the
  §5.7 wording for a 15-minute certificate: gominimal/gatehouse, the
  `01-spec-*` lineage, with the open questions below as the asks.
- The mobile app and its in-process network stack: plan S13, later, from the
  same core.
- Session recording: plan S9 and Gatehouse §14.4(1); daemon-side if ever.
- Sharing a session and teammate access: plan S8, later.
- Creating a session, workspace sync, loadouts, file patches, hooks,
  diagnostics and agent dispatch from the browser: outside the core by
  construction (no filesystem or TTY in a tab).
- GitHub sign-in UX and credential-free git from sessions: the GitHub
  sessions spec (GHS) in this repo; MCC-050 is the credential it rides on.
- Hosts reached only through providers in the client-managed Box Provider
  List, un-enrolled with Gatehouse: invisible to the tab in v1 (plan S2),
  carried with the peer-document open question.

## Non-functional requirements

- **MCC-N01** WHILE attaching over a loopback datagram pipe with certificate
  authentication and host verification THE SYSTEM SHALL reach the accepted
  shell request within 200 ms at p95 of the transport opening, measured at
  the client boundary.
  tier:   T0
  verify: just wasm-core-headless attach_latency_p95_under_200ms

- **MCC-N02** WHILE attached over loopback THE SYSTEM SHALL deliver a
  keystroke's echo to the data callback within 5 ms at p95 of the `write`
  call.
  tier:   T0
  verify: just wasm-core-headless keystroke_round_trip_p95_under_5ms

- **MCC-N03** WHEN the datagram transport closes THE SYSTEM SHALL deliver the
  close callback within 1 s.
  tier:   T0
  verify: just wasm-core-headless tunnel_loss_closes_within_1s

## Design reasoning

**One core, several heads** (decided 2026-09-03, plan §3.1). The alternatives,
Tailscale's Go browser client and a purpose-built TypeScript thin client,
both put a second implementation of the mesh peer, the SSH client and host
trust next to the CLI's, and the first brings a second identity system whose
SSH skips host-key verification, against Gatehouse §6.2. One Rust core is the
literal form of "the website is just one more client" (minimal-hosted §1) and
of the client credential library "also embedded in the `min` client"
(Gatehouse §4.1); the proof of concept priced it at 91 KB gzip for the network
layer and a forty-line WireGuard clock patch.

**Crate shape** (plan §4.3; mechanism, so it lives here). `min-core`,
wasm-clean, holds the network layer, attach, RPC driver, credential module
and host policy (MCC-001, MCC-002); `min-core-web` is the wasm-bindgen head
exporting the contract group; `min-wire` carries the wire types carved out of
`minimald-rpc` and `sessions::wire` with no `common` or `args` dependency,
which MCC-007 observes. The cryptographic backend is a target-gated,
non-default feature — `ring` for the browser, the workspace's native backend
elsewhere — so a native `--workspace` build enables exactly one; MCC-004
stated that as a requirement and was retired on 2026-09-04 as mechanism, its
ID not reused. The `min-` prefix is deliberate beside `minimal-*` and
`minimald-*`: the client core, not the `minimal` crate whose binary is `min`.
Promotion updates AGENTS.md's crate table and `docs/architecture.md` §3
(plan S5) and widens the justfile's macOS `scope` to `min-core`, which
builds there.

**The tab is a mesh node and no server is in the session path** (decided
2026-09-03, plan entries 12, 18, 23, 24). Servers remain for the page,
Gatehouse, notifications and a stateless relay forwarding WireGuard
ciphertext for daemons behind NAT; none holds a box credential or sees SSH
bytes. A daemon exposes no inbound listener by default and connects outbound
to its relay; the tab dials direct first (MCC-014) because a reachable daemon
needs no relay.

**A public client with tokens in memory** (decided 2026-09-03, entries 10,
15–17). With no backend nothing but the tab can hold tokens, and every token
is sender-constrained to a non-extractable key (Gatehouse §5.4), which is
what §6.1.7's rule guarded against. The core holds tokens in memory on every
head; what outlives the process is the head's — none in the browser (MCC-076,
WMC-004), the CLI's refresh token in its store (MCC-050). A reload re-mints
through the SSO session, the client has its own origin, and the bundle is
content-addressed with one manifest per CLI release (MCC-073); because the
pipeline auto-cuts a `release-<sha>` per commit on `main`, a pre-release
bundle's per-commit checksums and its release manifest are one artefact. The
origin serving the page is trusted for code integrity, never for data, and
checkably so.

**A 15-minute certificate with transparent renewal, capped** (decided
2026-09-03, entries 7, 8, 22). The `interactive` 8 h profile would keep §5.7's
wall warnings at the price of an 8 h window for an XSS that drives the key;
`exchange` at 15 min keeps the window short and makes reconnect a core duty
(MCC-039). Unattended renewals stop at the binding's 8 h and without an open
attach (MCC-040), so the profiles are equivalent in XSS terms and differ in
revocation latency only. The chain is anchored at the presence-backed initial
certify (plan entry 8); WMC-009 counts from the sign-in and must align to the
certify, or the two differ by the length of a login. A Gatehouse outage
detaches at the next renewal with no grace period. The daemon-side repaint
makes each forced reconnect land on a full screen, which is why the
mesh-ingress spec is a v1 prerequisite and MCC-063 states the repaint as
observed.

**Re-attach ownership** (decided 2026-09-04). A transport-initiated loss
closes the attachment: the close callback fires once with `tunnel_lost`, and
any re-attach is a new attach call by the head at its own cadence — MCC-057
for the CLI; WMC-007, WMC-026 and WMC-028 for the page. The core binds no
cadence, because when a head wants to be attached is a policy no head can
express to it. A core-initiated reconnect, the transparent renewal, keeps
the attachment object, fires no close callback, and shows the head only the
repaint (MCC-069, MCC-063): the core attaches on the new connection first,
then closes its old channel itself, and a `SUPERSEDED@minimal.dev` the daemon
sends on that old channel is consumed, never surfaced as `superseded`
(MCC-065); MMI-053 carries the mirror statement. One cause per daemon exit
signal keeps WMC-030's "attached elsewhere" and a revocation distinct.

**Host-certificate revocation** (decided 2026-09-04). v1 does not consult the
KRL for host certificates: the host policy runs the shared decision with an
empty revocation set (MCC-032). The exposure is a compromised host key that
stays acceptable until its certificate's 30-day expiry (Gatehouse §5.7) or a
Host CA rotation; user-certificate revocation is the daemon's KRL
(MMI-034–037). Carried as an open question.

**Constants.** The 60 s silent-peer bound (MCC-013) is twice the 25 s
persistent keepalive the network layer configures; 20 s to the first
handshake response (MCC-011) is four WireGuard handshake retries at its 5 s
interval; 10 s for the version exchange (MCC-006) and 30 s for the whole
attach (MCC-060) are the handshake bound plus SSH key exchange,
authentication and the attach requests, which take 200 ms at p95 on loopback
(MCC-N01). Every one is decided at the injected clock (MCC-005).

**Credential helpers run in the core over an injected HTTP call** (decided
2026-09-04, MCC-067). The proof of concept let the page perform certify and
mesh-bind. Renewal must run inside the core during an open attach, and one
request shape across heads is the point of sharing, so the core composes and
parses every issuer request — the callback's `state` and `iss` checks and the
revoke at sign-out included — and the host executes it, the same seam as the
clock; the page only navigates the authorization leg. Anchors are pinned to
the issuer the credential names (MCC-038): a peer document may repeat that
issuer, never select it, which is what makes "tenant issuer only" true.

**In-memory mesh key, Ed25519 first** (decided 2026-09-03, entries 3, 11). The
WireGuard implementation takes the static secret as bytes, so a
WebCrypto-held X25519 key needs a static-DH hook in the noise core; v1
accepts an in-memory key rotated per page session and bounded by the 8 h
binding (MCC-041), the held key being plan S13 hardening. The CLI's node key
lives as long as the enrollment (MCC-053): a peer that re-keys on every run
is not the mesh peer plan S6 describes. P-256 is a one-variant fallback for
the FIPS profile, covered by MCC-030's property.

**Listing is the identity plane's node set plus heartbeats** (decided
2026-09-03, entry 21). The tab reads nodes, liveness and `last_seen` in one
call and handshakes only with the node it attaches to (MCC-015, MCC-017); a
proof-of-concept design that opened a tunnel per node for liveness was
retired by it.

**CLI adoption order** (decided 2026-09-03, entry 6). The target is the
in-process attach (MCC-052); the first step shares the non-TTY parts and keeps
the `ssh` binary for TTY attach with a `known_hosts` fragment from the same
policy, because that changes a daily-driver path last. The CLI's sign-in leg
is the device flow the GitHub sessions spec chose (GHS-006 owns its UX),
DPoP-bound like the browser's auth-code leg (Gatehouse §6.1.2); MCC-035
shares everything after it. The CLI keeps what the browser must not: a
refresh token in its store with background renewal (MCC-056), a node key for
the enrollment's lifetime (MCC-053), and its own reconnect cadence (MCC-057).

**Bundle budget** (decided 2026-09-03, entry 25). 447 KB gzip was accepted for
v1 and the certificate path measured 501 KB stripped; MCC-079 bounds the
module at 600 KB, the figure WMC-N02 cites, and the glue separately. The diet
is later work.

**Working assumptions, not decisions.** Four defaults the owner confirmed on
2026-09-04 (recorded in WMC) stay written as assumptions so a reversal is one
visible edit: A1, the v1 browser command set is owner-only list, show,
attach, rename and stop (MCC-072), with no create, sync, agent dispatch or
share links; A2, the plan's decisions above stand; A3, the browser client
lives on its own origin served from the webapp repo (MCC-075, WMC-035); A4,
the Gatehouse capabilities this spec consumes are dependencies on the identity
plane, bound by name and carried as HIGH open questions where the architecture
has not ruled. Overturning one changes the requirements it names, not the
core's shape.

**Tiers.** Three universals are at T1 — the signer's output shape (MCC-030),
the host-policy decision (MCC-032) and the certificate decision (MCC-034) —
because each is a pure function over owned values a property test can drive
across its input space, and stating the universal forbids interleaving them
with the transport; the property-testing dependency is confined to
`min-core`'s development dependencies. T2 was declined because the decisions
include a signature verification no bounded harness can exhaust. Everything
else is T0 because it reaches a socket, a daemon or a browser. MCC-001's
check is the headless attach on the wasm target: the second target compiling
and running is the observable.

**Verification mechanics.** Native tests run under `cargo nextest` through
`just test` (`just test-cross` on macOS). `just wasm-core` builds the bundle;
`just wasm-core-headless` drives the built module from Node against a native
stand-in through the certificate-authenticated attach and inspects the
module's import section (MCC-002, MCC-076), the gate before any bundle
reaches the web side; `just wasm-core-budget` measures MCC-079. MCC-022 uses
the mesh-ingress spec's daemon harness. Page behaviour is verified in WMC
under its own runner; this spec names no test of WMC's.

**Generality:** A second head fits by construction: the mobile app is the same
core behind a UDP datagram pipe and a keystore-backed signer; the CLI is the
same core behind a local socket and an agent-backed signer. A second daemon
fits if it terminates SSH inside a WireGuard tunnel and presents a Gatehouse
host certificate. A second transport is a datagram pipe. A second identity
plane does not fit: the certify, anchors, peer-document and ticket shapes
(MCC-068, MCC-070, MCC-071) are Gatehouse's by decision, acceptable because
Gatehouse is the only identity plane in the system (§6.9).

## Security considerations

- **Invariant:** THE SYSTEM SHALL never hold, read or export a head's signing
  key in its attach or credential paths; every signature is the head's
  signer's, over bytes the core supplies.
  enforced by: the signer seam as the only signing path, and the browser's
  non-extractable key behind a callback (WMC-003).
  covered by: MCC-030, MCC-066, MCC-077
- **Invariant:** THE SYSTEM SHALL attach to no host off a local socket without
  a host certificate verifying, for the expected principal, against anchors
  taken from the tenant issuer only.
  enforced by: the host policy in the server-key check, aborting before
  authentication (Gatehouse §6.2, no TOFU); the anchors fetch bound to the
  issuer the credential names, with a peer document naming another issuer
  refused.
  covered by: MCC-032, MCC-038, MCC-051
- **Invariant:** THE SYSTEM SHALL present no bearer credential and derive no
  SSH-PoP assertion from a head's key; every issuer, relay and node request
  is DPoP-bound or certificate-authenticated.
  enforced by: DPoP proofs on every request and PKCE with `dpop_jkt` at
  sign-in (Gatehouse §6.1.1); the head's key used for DPoP and SSH
  authentication signatures only.
  covered by: MCC-035, MCC-036, MCC-042
- **Invariant:** THE SYSTEM SHALL renew a browser credential unattended for at
  most 8 h and only while an attachment is open, and hold a browser mesh key
  for at most 8 h.
  enforced by: the renewal-chain cap and the binding TTL at the injected
  clock (Gatehouse §6.9, T22).
  covered by: MCC-039, MCC-040, MCC-041, MCC-069
- **Invariant:** THE SYSTEM SHALL persist no token, certificate, key handle or
  mesh key in a browser, and open no connection from the bundle to an
  endpoint other than the credential's issuer and the configured endpoints.
  enforced by: in-memory holders in the core, a bundle importing no storage
  capability, the page's storage rule (WMC-004), and the core dialing only
  the issuer and configured endpoints.
  covered by: MCC-076, MCC-078
- **Invariant:** THE SYSTEM SHALL run only a bundle whose hash matches the
  published manifest, and fail closed on a daemon outside the supported
  protocol window.
  enforced by: content-addressed assets with one manifest per release, the
  CLI-verifiable manifest, version negotiation before any session operation,
  and the page's integrity loading (WMC-036).
  covered by: MCC-006, MCC-073, MCC-074

## Open questions

- [NEEDS CLARIFICATION (HIGH): A public-client registration kind does not
  exist in the architecture of record: Gatehouse §6.1.7 says tokens never
  reach the browser and a SPA holding tokens is out of v1 scope; §14.4(2)
  leaves the in-browser path open. This spec needs a `public` kind — PKCE
  with `dpop_jkt`, exact-match HTTPS redirect URIs, DPoP required, no client
  authentication, tokens held by the client on a non-extractable key, and the
  statement that the client's key never becomes an SSH-PoP key. MCC-035,
  MCC-036, MCC-042, MCC-067 and MCC-076 wait on the ruling. Filed: gominimal/arch#16.]
- [NEEDS CLARIFICATION (HIGH): Certify for the browser client. §6.1.7 grants
  web clients no `box:ssh` by default, the website's registration
  (minimal-hosted §4, §7) omits it, and §6.9 keeps `JoinMesh` deny-by-default.
  This spec needs both as tenant opt-ins for the public client, a personal
  tenant's sole admin opting in for themselves, both key thumbprints audited
  on certify. MCC-037, MCC-041 and MCC-068 depend on it. Filed: gominimal/arch#16.]
- [NEEDS CLARIFICATION (HIGH): A 15-minute `exchange` certificate for an
  interactive browser session. §5.7 gives interactive users 8 h with wall
  warnings at T-15 and T-1 min. This spec renews at T-2 min with the warnings
  suppressed for a client that reconnects transparently, caps the unattended
  chain at 8 h from the initial certify and requires presence there; §5.7
  must say so. MCC-039, MCC-040 and MCC-069 depend on it. Filed: gominimal/arch#16.]
- [NEEDS CLARIFICATION (HIGH): The peer document, node listing and
  heartbeats. §6.9 issues bindings but no peer configuration; §9 holds nodes
  with `last_seen` but exposes no per-subject read; §8.2 has no endpoint for
  either. This spec needs one read returning the fields MCC-070 lists, with
  liveness and `last_seen` from daemon heartbeats. MCC-014, MCC-015, MCC-017,
  MCC-053, MCC-054 and MCC-070 depend on it; the un-enrolled provider-list
  gap rides with it. Filed: gominimal/arch#19 and gominimal/arch#17.]
- [NEEDS CLARIFICATION (HIGH): The relay tier and its tickets. No
  architecture text describes a stateless ciphertext relay, a Gatehouse-issued
  per-node ticket bound to the tab's DPoP key, or the daemon's outbound relay
  connection under `sshpop-host`; box-provider-api §1 and the Cloudflare
  sketch §1 keep the provider out of the box data path, which a ciphertext
  relay needs restating. The protocol is the mesh-ingress spec's; the ticket's
  issuer and shape are Gatehouse's. MCC-014 and MCC-071 depend on it. Filed: gominimal/arch#18.]
- [NEEDS CLARIFICATION (MEDIUM): Which principal the host certificate carries
  for a tunnel-addressed connection. §5.3 lists the names and IPs clients may
  connect to; the tab dials a tunnel address. Either the address is a
  principal or the peer document names the node's canonical name and the core
  resolves it. MCC-032 and MCC-070 allow either; the document must pick one.]
- [NEEDS CLARIFICATION (MEDIUM): Host-certificate revocation. v1 checks no
  KRL for host certificates (MCC-032, Design reasoning), leaving a
  compromised host key acceptable until its 30-day certificate expires
  (Gatehouse §5.7). Does the identity plane want the client to consult the
  KRL for host serials, and if so from which feed — the same §8.2 feed the
  daemon polls (MMI-035) fetched by the core over MCC-067's HTTP callback?]
- [NEEDS CLARIFICATION (MEDIUM): The CLI's mesh node key lifetime and
  rotation. MCC-053 keeps it for the enrollment's lifetime; whether it
  rotates on a schedule, on `min auth login`, or only on re-enrollment, and
  what the daemon's binding check (MMI-010) needs from a rotation, is
  unset.]
- [NEEDS CLARIFICATION (MEDIUM): The SSH username under certificate
  authentication (plan S4): the box login principal as bound in MCC-021, or
  the canonical subject with the daemon deriving the sandbox user. The core
  takes it as input either way; the mesh-ingress spec decides.]
- [NEEDS CLARIFICATION (MEDIUM): The width of the supported version-skew
  window (architecture open gap 8). MCC-006 and MCC-074 fail closed outside
  it; its width is unset.]
- [NEEDS CLARIFICATION (MEDIUM): The wasm head's packaging for the webapp —
  npm versioning of `min-core-web`, the wasm-bindgen pin policy, and how the
  webapp consumes the release manifest of MCC-073.]
- [NEEDS CLARIFICATION (LOW): Stop is `StopSession` (MMI-028) and bound in
  MCC-003 and MCC-072; destroy stays Local-only in the daemon (MMI-027). Does
  the browser ever get destroy of an exited session, which WMC today does not
  offer?]
- [NEEDS CLARIFICATION (LOW): Whether `minimald`'s WireGuard pump moves onto
  the core's network layer or keeps its own driver over the same crate; the
  mesh-ingress spec's call, invisible to this spec's behaviours.]
- [NEEDS CLARIFICATION (LOW): Interoperability with WireGuard peers that are
  not the daemon's implementation; MCC-011 is proven
  implementation-to-implementation only.]
