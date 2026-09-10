---
id: MMI
title: minimald as a mesh-reachable session host
owner: mitodrummer
epic: gominimal/inbox#513
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-10
---

# MMI — minimald as a mesh-reachable session host

## Context

A session daemon answers only its Unix socket or vsock and trusts whoever
reaches it; nothing outside the machine can attach. The remote-sessions epic
needs a browser tab to attach to a session on any of a developer's daemons
with SSH ending in the tab, and to leave the session running when the tab
closes. After this ships a daemon accepts WireGuard over a TLS WebSocket,
terminates SSH inside its own tunnel, admits a connection only on a
certificate from the identity plane, reaches the outside through an outbound
connection to a Minimal-run relay by default, reports its liveness to the
identity plane, and repaints the current screen on every re-attach. This
document covers the daemon and the relay, `minrelay`. The deployment and
egress-gateway design now owns the transport mechanism, down to a pinned
host's gateway forwarding the attach path in the relay's role (§4.5), so
the networking spec in preparation is expected to implement the daemon's
side of that design (§4.1, §4.5) rather than supersede this document
whole; the relay leg and path choice (MMI-008, MMI-009) are the parts
expected to fold into it (Open questions).

**Success:** A developer closes the laptop on a running session, opens the
session's address in a phone browser, sees the current screen, types into
it, closes the tab, and the session is still running and attachable from the
shell.

**First slice:** One native daemon with a static trust anchor and peer table,
a browser attach through its WebSocket ingress with a certificate, `auth_none`
refused on that path, local socket clients unchanged except for the
terminal-state group, and a second attach that repaints the screen.

## Users and stories

**Roles:** developer using a long-running agentic workflow who is away from
the workstation; developer who deploys long-running workflows in sessions;
developer running sessions both locally and remote; operator of the relay
tier, who runs `minrelay` for the daemons that cannot be reached directly.

- AS A developer using long running agentic workflow, I WANT to monitor and
  jump into an session via a mobile or desktop web browser, SO THAT I can
  provide additional input and course correct the agent when I'm not at my
  workstation.
  - A user can navigate to a session URL in a desktop or mobile browser, and
    authenticate via GitHub to access the running workbench stream.
  - The web interface streams session stdout/stderr in real time and accepts
    terminal input to course-correct active agent runs.
  - The web session view renders cleanly on mobile screen width in portrait
    and landscape without breaking terminal text layouts or input controls.
  - Closing the browser tab or dropping mobile connection leaves the remote
    session continuously active in a detached state.
- AS A developer who deploys long running workflow in sessions, I WANT my
  sessions to stay active when my laptop is closed or asleep, SO THAT my
  workflow can successfully complete its objective without interruption or
  retries.
  - Processes in the session remain continuously active, and the session is
    in a state equivalent to detached, not exited.
- AS A developer running sessions both locally and remote, I WANT to
  enumerate and reconnect with remote sessions just like local sessions, SO
  THAT I can work with all my sessions the same way.
  - Remote boxes are enumerable and attachable through the same CLI surface
    as local ones.

## Requirements

Wire details, field names, feed shapes and error codes are the architecture
of record's (Gatehouse v1.17 §5.3, §5.7, §6.9, §6.11, §7.4, §8.2;
architecture D7, D8; the deployment and egress-gateway design,
`specs/networking/deployment-and-egress-gateway.md`, cited below as the
deployment design) and the siblings'; the requirements cite them rather
than repeat them. The siblings are the client core, MCC
(gominimal/minimal#1355), which consumes this ingress and its close
signals, and the browser client, WMC (gominimal/webapp#763), which consumes
them through the core. The gateway association and box address assignment
are the deployment design's (§4.1, §4.2), implemented daemon-side by the
networking spec in preparation; this document reports their state on the
heartbeat and nothing more (MMI-061).

Configuration vocabulary: the identity plane's issuer is one configuration
item, and every node-scoped endpoint named below — the KRL feed, the
decision endpoint, host-certificate renewal, the heartbeat, the peer
document's mirror
and the relay set — is discovered from its `gatehouse_node_endpoints`
(Gatehouse §8.2), so "WHERE … is configured" means the issuer is configured
and advertises that endpoint. "Direct ingress" is the one opt-in that opens
the UDP mesh socket and the `/wg` route on a non-loopback address; the
WebSocket ingress is that route, and on a loopback address needs no opt-in.

### Mesh ingress

- **MMI-001** WHERE the WebSocket ingress is enabled THE SYSTEM SHALL accept
  WireGuard datagrams as binary frames, one datagram per frame, on the `/wg`
  route of its TLS listener (03-spec-networking R4.4), and a peer's tunnel
  SHALL behave identically on that carrier and on UDP.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_ingress_ws_frames_reach_the_same_tunnels

- **MMI-002** THE SYSTEM SHALL serve the `/wg` route without a TLS client
  certificate; the WireGuard handshake is that route's authentication.
  tier:     T1
  verify:   cargo nextest run -p minimald wg_route_needs_no_client_certificate
  property: for every route r the TLS listener registers and every request to r that carries no client certificate, r is served iff r = `/wg`, and every other r answers the existing empty 401; walked over the listener's route table

- **MMI-003** WHEN a decrypted packet from an admitted peer is addressed to
  the daemon's own tunnel address THE SYSTEM SHALL answer it itself, serving
  a TCP connection to its SSH port there as a non-local SSH connection.
  tier:     T0
  verify:   cargo nextest run -p minimald own_address_terminates_at_the_ssh_server

- **MMI-005** THE SYSTEM SHALL drop a decrypted packet whose source address
  is outside the sending peer's allowed addresses or whose destination is
  outside the destinations that peer's configuration admits, counting the
  drop without logging an address.
  tier:     T1
  verify:   cargo nextest run -p minimald cryptokey_routing_drops_out_of_policy_packets
  property: for every admitted peer p and every packet k decrypted under p, delivered(k) implies src(k) in allowed(p) and dst(k) in admitted(p); walked over every address class the peer table can express

- **MMI-006** WHEN the transport carrying a peer's datagrams closes, or no
  datagram from that peer authenticates for 180 s, THE SYSTEM SHALL end every
  SSH connection carried inside that peer's tunnel within 1 s.
  tier:     T0
  verify:   cargo nextest run -p minimald dead_transport_ends_carried_ssh_connections

- **MMI-007** THE SYSTEM SHALL open no inbound mesh listener, neither a UDP
  socket nor the `/wg` route on a non-loopback address, unless direct
  ingress is enabled in its configuration.
  tier:     T1
  verify:   cargo nextest run -p minimald no_inbound_mesh_listener_without_opt_in
  property: for every configuration c whose mesh, relay and ingress options do not enable direct ingress, the set of sockets the daemon opens under c holds no UDP mesh socket and no `/wg` route bound to a non-loopback address; walked over every combination of those options

- **MMI-008** WHERE a relay is configured, by the peer document's relay
  assignment or by configuration until one is, THE SYSTEM SHALL connect
  outbound to it over a TLS WebSocket, authenticate with its node identity
  (`sshpop-host`, `aud` the relay's URL from the `relays` member of
  `gatehouse_node_endpoints`; Gatehouse §6.9, architecture D7), and treat
  each frame received there as a datagram whose source is the mesh public
  key the frame is addressed with (MMI-077).
  tier:     T0
  verify:   cargo nextest run -p minimald relay_client_registers_with_sshpop_host
  - IF the relay connection fails or closes THEN THE SYSTEM SHALL reconnect
    with backoff from 1 s doubling to a 60 s cap, each delay jittered by up
    to 10%, until it succeeds.
    tier:   T0
    verify: cargo nextest run -p minimald relay_client_reconnects_with_bounded_backoff

- **MMI-009** THE SYSTEM SHALL send to a peer over a direct endpoint whenever
  that endpoint has authenticated a datagram from the peer within 180 s, and
  otherwise over the relay connection addressed to that peer (architecture
  D7: direct paths preferred, the relay the fallback).
  tier:     T0
  verify:   cargo nextest run -p minimald direct_endpoint_preferred_over_relay

- **MMI-010** WHERE a peer document is configured THE SYSTEM SHALL fetch the
  daemon's mirror view of it (`GET /v1/mesh/peers` under `sshpop-host`, the
  `gatehouse-mesh-peers+jws` feed of Gatehouse §6.9) and admit a peer only
  while the document holds a valid, unexpired mesh binding for that peer's
  key, re-checked at every rekey; the document configures and never
  authorizes.
  tier:     T0
  verify:   cargo nextest run -p minimald peer_admitted_only_against_a_valid_binding
  - IF a binding expires or is revoked, by TTL or by the document's
    `revoked_bindings[]` delta, THEN THE SYSTEM SHALL refuse the peer's next
    handshake and end its carried connections within 60 s.
    tier:   T0
    verify: cargo nextest run -p minimald revoked_binding_ends_the_peer
  - IF a document's `seq` regresses below the last accepted for its
    (audience, mesh), or its `issued_at` is older than the 5 min staleness
    bound, THEN THE SYSTEM SHALL keep the last accepted document, admit no
    peer it did not already admit, and leave established tunnels to ride
    their bindings' TTLs.
    tier:   T0
    verify: cargo nextest run -p minimald stale_or_regressed_peer_document_admits_no_new_peer

- **MMI-011** WHERE a static peer table is configured and no peer document is
  THE SYSTEM SHALL admit exactly the listed keys; the static table is the
  proof-of-concept interim the peer document retires (Gatehouse §6.9).
  tier:     T0
  verify:   cargo nextest run -p minimald static_peer_table_admits_listed_keys_only

### Authentication surface

- **MMI-020** WHEN an SSH connection arrives over the mesh ingress THE SYSTEM
  SHALL start it unauthenticated and admit it only to a `Certified` state
  through certificate authentication; UDS and vsock connections keep `Local`.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_connection_is_never_local

- **MMI-021** THE SYSTEM SHALL refuse `none` authentication on every
  non-local connection, naming public-key authentication as the method to
  continue with.
  tier:     T1
  verify:   cargo nextest run -p minimald auth_none_refused_on_mesh_ingress
  property: for every non-local connection and every authentication method in the SSH server's dispatched vocabulary, `none` is refused and the refusal names `publickey` as the method to continue with; walked over the method vocabulary

- **MMI-022** THE SYSTEM SHALL decide a presented user certificate as a pure
  function of (certificate, username, clock, trusted User CA keys, revoked
  serials) that accepts iff the type is user, the signature verifies under a
  trusted User CA, `valid_after − 60 s ≤ clock < valid_before` (Gatehouse
  N6), the serial is not revoked, the username is among the certificate's
  principals, and every critical option is `source-address`, taking the
  subject from `key_id.sub` (SSHPOP.md §3.1); otherwise it refuses with the
  code of the first failing check in the order signature, issuer, type,
  validity, critical options, revocation, principal — `bad_signature`,
  `unknown_ca`, `wrong_cert_type`, `cert_not_yet_valid`, `cert_expired`,
  `unknown_critical_option`, `cert_revoked`, `principal_mismatch` — the same
  decision and order as the client core's (MCC-034).
  tier:     T1
  verify:   cargo nextest run -p minimald cert_decision_matches_the_arch_vectors_at_the_fixed_clock
  property: for every case in gominimal/arch spec/vectors/ssh-certs/invalid/manifest.json at clock 1750000000 with krl/krl-v1.bin loaded, the decision is Err(expected_error); for user-interactive-valid.cert it is Ok for username `dev` and Err(principal_mismatch) for `nobody`
  - IF a certificate reaches the decision THEN THE SYSTEM SHALL log the
    outcome with the serial and `key_id`, never the certificate bytes.
    tier:   T0
    verify: cargo nextest run -p minimald refusal_codes_are_logged_with_serial_and_key_id

- **MMI-023** THE SYSTEM SHALL hold on every session record an owner
  subject — the certificate subject of the connection that created it, or,
  for a session created over a local connection, the node's configured
  owner subject (the `local`-class linkage of Gatehouse §6.2, held in
  configuration until enrollment exists) — and SHALL compare that owner,
  never the record's sandbox username, when an ownership-gated request
  arrives; a record created before a subject was configured is owned by no
  subject and refuses every ownership-gated request.
  tier:     T1
  verify:   cargo nextest run -p minimald session_owner_is_the_creating_subject_or_the_node_subject
  property: for every creating-connection class c in {Local, Certified}, every configured-subject state in {configured, none}, and every record r created under them, owner(r) is the certificate subject when c is Certified, the configured subject when c is Local and one is configured, and no subject otherwise; and for every ownership-gated request in MMI-027's vocabulary the comparison reads owner(r) and never r's sandbox username; walked exhaustively

- **MMI-024** THE SYSTEM SHALL accept the username a non-local connection
  presents only when it is among the certificate's principals and not in
  canonical-subject form (`u:` or `m:` prefix), refusing a subject-form
  username as `principal_mismatch`; a subject-form string is never used as
  a sandbox user.
  tier:     T1
  verify:   cargo nextest run -p minimald subject_form_username_is_refused
  property: for every principal p in the arch's user-certificate vectors and every subject-form string built from p with the `u:` or `m:` prefix, presented as the username on a non-local connection, accepted(name) iff name is among the certificate's principals and carries neither prefix, and a refusal names `principal_mismatch`; walked over the vectors

- **MMI-025** WHERE no authorization decision endpoint is configured THE
  SYSTEM SHALL admit only certificates whose subject equals the daemon's
  configured owner subject, refusing every other subject before any channel
  opens, and with no owner subject configured SHALL admit no certificate
  (the ownership interim Gatehouse §7.4 ratifies).
  tier:     T1
  verify:   cargo nextest run -p minimald owner_subject_rule_admits_only_the_owner
  property: for every subject s in the arch's user-certificate vectors and every configured owner o drawn from the same set or absent, admitted(s) iff o is present and s = o; walked over the vectors' subject set

- **MMI-026** WHERE a decision endpoint is configured THE SYSTEM SHALL open a
  session channel for a `Certified` connection only on an allow `SshConnect`
  decision for (subject, session) cached within 60 s, fetching a missing one
  with a 2 s deadline and denying on deadline or unreachability (Gatehouse
  §6.3.1), and SHALL evaluate the other admitted requests on the same cache
  as Gatehouse §7.4 maps them: `BoxRead` for `GetSessionRecord`,
  `GetSessionScreen` and each `ListSessions` row, `ReadNode` over (subject,
  node) for the listing itself and for `GetVersion`, `StopBox` for
  `StopSession`, `RenameBox` for `RenameSession`. Until a decision endpoint
  is configured, MMI-025 and MMI-027 govern.
  tier:     T0
  verify:   cargo nextest run -p minimald decision_cache_miss_fails_closed_when_the_sts_is_unreachable

- **MMI-027** THE SYSTEM SHALL admit a channel request, subsystem, exec
  request, or direct-tcpip open by auth state: under `Local`, everything;
  under `Certified`, `GetVersion`, and, for a session the connection's
  subject owns (MMI-023), the shell attach path including the attach that
  restarts a stopped session (MMI-028), `GetSessionRecord`,
  `GetSessionScreen`, `RenameSession` and `StopSession`, with `ListSessions`
  returning only the rows the subject owns; under `Pending`, nothing;
  refusing with channel failure or an administratively-prohibited open.
  Every other request stays local-only in v1, as Gatehouse §7.4 keeps exec,
  direct-tcpip, sftp, shutdown, cache, diagnostics, client-cert issuance,
  create and destroy.
  tier:     T1
  verify:   cargo nextest run -p minimald rpc_allowlist_by_auth_state
  property: for every auth state s, every request r in the daemon's dispatched subsystem, exec, sftp and direct-tcpip vocabulary, and every ownership o in {owner, other}: admit(s, r, o) iff s = Local, or s = Certified and r = GetVersion, or s = Certified and o = owner and r in {attach, GetSessionRecord, GetSessionScreen, RenameSession, StopSession}; and every `ListSessions` row returned under Certified has o = owner; walked exhaustively
  - IF a `Certified` connection sends `exec`, `sftp`, `direct-tcpip`, or a
    subsystem outside the allowlist THEN THE SYSTEM SHALL refuse it without
    side effects.
    tier:   T0
    verify: cargo nextest run -p minimald local_only_requests_refused_under_certified

- **MMI-028** WHEN `StopSession` is admitted (the `StopBox` decision of
  Gatehouse §7.4) THE SYSTEM SHALL end the session's process without the
  exit prompt, keep the record, end any attached channel with the process's
  exit status as for a shell exit, list the session as exited (MMI-055),
  answer a screen read as not active, and start a fresh shell in the same
  workspace on the next attach.
  tier:     T0
  verify:   cargo nextest run -p minimald stop_session_ends_the_process_and_keeps_the_record

- **MMI-029** WHERE a host certificate is configured THE SYSTEM SHALL present
  it on every non-local connection, with principals covering the node's
  canonical `<node_id>.box.<td>` name and the per-node wildcard, and never
  the daemon's tunnel address (Gatehouse §5.3, mesh attaches).
  tier:     T0
  verify:   cargo nextest run -p minimald host_certificate_presented_on_mesh_ingress
  - IF the host certificate is absent, unparsable, or expired THEN THE SYSTEM
    SHALL accept no non-local SSH connection; local listeners are unaffected.
    tier:   T0
    verify: cargo nextest run -p minimald expired_host_certificate_disables_the_mesh_ingress
  - WHERE a renewal endpoint is configured THE SYSTEM SHALL renew the host
    certificate at 50% of its lifetime, authenticating with the current one,
    and present the new one without a restart.
    tier:   T0
    verify: cargo nextest run -p minimald host_certificate_renewed_at_half_life

- **MMI-031** THE SYSTEM SHALL close a `Certified` connection at its
  certificate's `valid_before`, within 1 s and with no grace, leaving every
  session it was attached to running and detached and ending each attached
  channel with `EXPIRED@minimal.dev` (MMI-053; Gatehouse §5.7).
  tier:     T1
  verify:   cargo nextest run -p minimald reaper_closes_at_valid_before_and_the_session_survives
  property: for every certificate c in the arch's user-certificate vectors and every clock t in {1750000000, valid_before(c) − 1 s, valid_before(c), valid_before(c) + 1 s}, the reaper decision closes c's connection iff t ≥ valid_before(c), and schedules wall warnings at T-15 min and T-1 min iff valid_before(c) − valid_after(c) > 1 h; walked over the vectors at those clocks
  - WHILE the certificate lifetime exceeds 1 h THE SYSTEM SHALL write wall
    warnings to the attached terminal at T-15 min and T-1 min, and for a
    shorter lifetime none (the daemon-side rule of Gatehouse §5.7 for the
    browser client's 15-minute certificate).
    tier:   T0
    verify: cargo nextest run -p minimald wall_warnings_only_for_long_lived_certificates

- **MMI-033** THE SYSTEM SHALL answer the first refused authentication
  attempt on a non-local connection within 100 ms, delay each later refusal
  on the same connection by at least 1 s, and close the connection after its
  third refusal.
  tier:     T0
  verify:   cargo nextest run -p minimald rejection_delay_zero_initial_then_one_second

- **MMI-034** THE SYSTEM SHALL read a KRL in OpenSSH PROTOCOL.krl format
  with its certificates section and reproduce gominimal/arch
  spec/vectors/krl/expected-revoked.json for krl/krl-v1.bin.
  tier:     T0
  verify:   cargo nextest run -p minimald krl_reader_reproduces_expected_revoked
  - IF a KRL contains a section or subsection the reader does not implement
    THEN THE SYSTEM SHALL refuse the whole KRL and keep the previous one.
    tier:   T0
    verify: cargo nextest run -p minimald krl_unsupported_section_fails_closed

- **MMI-035** WHERE a KRL feed is configured THE SYSTEM SHALL poll it at
  least every 60 s, accept only a response whose JWS verifies under the
  issuer's keys with `typ` `gatehouse-krl+jws`, whose `td` is its own, and
  whose `seq` exceeds its persisted high-water mark, persist the new
  `(seq, issued_at)` before applying, and after a restart keep enforcing the
  last accepted KRL and that mark until a fresh one is fetched (Gatehouse
  §8.2).
  tier:     T1
  verify:   cargo nextest run -p minimald krl_feed_rejects_a_regressed_seq_across_restart
  property: for every KRL response varying signature validity, `typ`, `td` and `seq` against the persisted high-water mark, accepted iff the signature verifies under the issuer's keys and `typ` = `gatehouse-krl+jws` and `td` is the daemon's own and `seq` exceeds the mark, before and after a restart; walked over every combination of the four
  - IF the newest accepted KRL's `issued_at` is older than the staleness
    bound (default 5 min) THEN THE SYSTEM SHALL raise an alarm in its log
    and status and, where configured, refuse new non-local connections until
    a fresh KRL arrives.
    tier:   T0
    verify: cargo nextest run -p minimald krl_staleness_alarm_fires

- **MMI-037** WHEN a KRL is applied THE SYSTEM SHALL close every live
  `Certified` connection whose serial it revokes within 1 s, ending each
  attached channel with `REVOKED@minimal.dev` (MMI-053).
  tier:     T1
  verify:   cargo nextest run -p minimald revoked_serial_terminates_a_live_connection
  property: for every KRL in the arch's KRL vectors and every live `Certified` connection under a certificate from the certificate vectors, the connection is closed within 1 s with `REVOKED@minimal.dev` iff the KRL revokes that certificate's serial; walked over every (KRL, certificate) pair

- **MMI-038** WHEN no authentication configuration is present THE SYSTEM
  SHALL refuse every public-key offer before any signature exchange, accept
  no non-local connection, and serve local listeners exactly as today.
  tier:     T1
  verify:   cargo nextest run -p minimald absent_auth_config_refuses_every_publickey_offer
  property: for every key and certificate in the arch's vectors offered as a public key on a non-local connection with no authentication configuration present, the offer is refused before any signature exchange; walked over the vectors

- **MMI-039** THE SYSTEM SHALL read its trust anchors, host certificate, KRL
  source, owner subject, mesh identity, peers, relay, and ingress options
  from exactly one operator-controlled source — a file named on its command
  line, or, in a microVM, the configuration the VM daemon places on the
  state volume — and from no environment variable or socket, starting the
  mesh from that configuration.
  tier:     T0
  verify:   cargo nextest run -p minimald microvm_reads_auth_config_from_the_state_volume

### Terminal state

- **MMI-051** WHEN a client attaches to a session whose shell process is
  already running THE SYSTEM SHALL write, before any new output, a repaint
  reproducing the current visible screen, the cursor's position and
  visibility, and every private mode the session has turned on (alternate
  screen, application keypad and cursor keys, bracketed paste, mouse
  reporting and its encoding, focus reporting), sized to the attaching
  terminal and wrapped in a synchronized-update pair (DEC private mode
  2026), so that a client's first bytes at its first attach and after every
  renewal are the current screen (MCC-063).
  tier:     T0
  verify:   cargo nextest run -p minimald reattach_lands_on_the_current_screen_in_one_frame

- **MMI-053** WHEN a second client attaches to an attached session THE SYSTEM
  SHALL move the session to the new client whatever either transport is and
  whoever either principal is — a renewed certificate of the same principal
  is a second client — restore the superseded client's terminal modes, write
  it a notice, and end its channel with an exit signal named
  `SUPERSEDED@minimal.dev`, distinct from the shell's own exit status and
  from a closed transport.
  tier:     T0
  verify:   cargo nextest run -p minimald second_attach_supersedes_the_first_with_a_signal
  - IF the daemon ends a channel for a reason of its own THEN THE SYSTEM
    SHALL name it the same way: `EXPIRED@minimal.dev` for the certificate
    reaper (MMI-031), `REVOKED@minimal.dev` for a KRL hit (MMI-037),
    `SHUTDOWN@minimal.dev` for daemon shutdown; a shell exit, including one
    `StopSession` causes, carries the process's exit status and no signal;
    a transport loss carries neither (MMI-054).
    tier:   T0
    verify: cargo nextest run -p minimald daemon_initiated_closes_carry_a_named_signal

- **MMI-054** WHEN the transport under an attached client ends without a
  detach THE SYSTEM SHALL keep the session's process running, raise no exit
  prompt, treat the session as detached within 5 s, running its `on_detach`
  hooks as an explicit detach does, keep advancing its screen model while
  detached, and accept a later attach that lands on the screen as it is
  then.
  tier:     T0
  verify:   cargo nextest run -p minimald transport_loss_leaves_the_session_running_and_reattachable

- **MMI-055** THE SYSTEM SHALL report for every session, in `ListSessions`
  and `GetSessionRecord`, an attachment state of attached, detached, or
  exited — exited from the moment its process ends by shell exit or
  `StopSession` until an attach starts a new one — and the time of its last
  output or input.
  tier:     T0
  verify:   cargo nextest run -p minimald list_sessions_reports_attachment_state_and_last_activity

### Heartbeats

- **MMI-060** WHERE a control-plane issuer is configured THE SYSTEM SHALL
  send a heartbeat to `POST /v1/nodes/heartbeat` (Gatehouse §8.2) every 60 s
  by default (configurable within 30 s, the server-enforced floor, to 300 s,
  up to 10% jitter), authenticated with its node identity (`sshpop-host`,
  `aud` the advertised URL), and within 5 s of its relay connection, direct
  ingress or gateway association changing state or of a box address being
  assigned or released.
  tier:     T0
  verify:   cargo nextest run -p minimald heartbeat_interval_and_state_change_within_bounds
  - IF the heartbeat endpoint is unreachable THEN THE SYSTEM SHALL keep
    serving every connection unchanged against its cached anchors and last
    KRL, retry at the next interval, and log the failure at most once per
    minute.
    tier:   T0
    verify: cargo nextest run -p minimald heartbeat_failure_does_not_affect_serving

- **MMI-061** THE SYSTEM SHALL carry in a heartbeat exactly the payload of
  Gatehouse §8.2: a `seq` that increases with every heartbeat it sends; the
  `reachability` members `direct_endpoint` where direct ingress is enabled,
  `relay` naming its home relay, `mesh_addresses`, and, while a gateway
  association is up, `egw` (gateway id, the node's WireGuard key,
  transport); and `addresses`, one `{box_id, addr, epoch}` for each box
  address it has assigned, carrying the allocation epoch of the block the
  address came from (Gatehouse §6.9). `GetMeshStatus` SHALL answer with
  only its node id, daemon version, mesh public key, tunnel address, direct
  endpoints, relay name and connection state, gateway id and association
  state, host-certificate serial and expiry, KRL `seq`, and the number of
  live sessions. Neither SHALL carry a session name, project path, or
  screen content.
  tier:     T1
  verify:   cargo nextest run -p minimald heartbeat_carries_no_session_data
  property: for every heartbeat the daemon emits, its members are a subset of {seq, reachability.direct_endpoint, reachability.relay, reachability.mesh_addresses, reachability.egw, addresses}, with `egw` present iff a gateway association is up; for every `GetMeshStatus` answer, its members are a subset of {node id, daemon version, mesh public key, tunnel address, direct endpoints, relay name, relay connection state, gateway id, gateway association state, host-certificate serial, host-certificate expiry, KRL seq, live session count}; and no value in either equals a session name, a project path or a screen line of any live session; walked over the emitter vocabulary, with and without a gateway association, against sessions whose names, paths and screens carry sentinel strings
  - THE SYSTEM SHALL persist the heartbeat `seq` so that a restart never
    regresses it (Gatehouse §8.2 rejects a regression).
    tier:   T0
    verify: cargo nextest run -p minimald heartbeat_seq_never_regresses_across_restart

### Relay

- **MMI-070** THE SYSTEM SHALL accept a node registration only over TLS with
  an `sshpop-host` assertion whose `aud` is the relay's URL as advertised in
  the tenant's `gatehouse_node_endpoints` `relays` member (Gatehouse §6.9;
  architecture D7) and whose certificate chains to a configured tenant Host
  CA, keyed by the node id the certificate names.
  tier:     T0
  verify:   cargo nextest run -p minrelay node_registration_requires_sshpop_host
  - IF a second registration arrives for the same node THEN THE SYSTEM SHALL
    replace the earlier one and close it with the `replaced` code.
    tier:   T0
    verify: cargo nextest run -p minrelay newer_registration_replaces_older

- **MMI-071** THE SYSTEM SHALL accept a client connection only with a
  Gatehouse-issued relay ticket presented at WebSocket open (the
  `gatehouse-relay-ticket+jws` of Gatehouse §6.9) that verifies statelessly
  under the issuer's published keys, names one node, is unexpired, and is
  bound by `cnf.jkt` to a key whose DPoP proof over the ticket the client
  presents with it, together with the client's own §6.9 mesh binding, from
  which the relay takes the client's mesh public key (the shared interim
  with MCC-071; Open questions); otherwise it closes with no body and the
  `expired` code for a ticket past `exp` or the `refused` code for every
  other failure. The ticket authorizes routing only (Gatehouse T29).
  tier:     T0
  verify:   cargo nextest run -p minrelay ticket_bound_to_dpop_key_required
  - IF the ticket's node has no live registration THEN THE SYSTEM SHALL close
    with the `offline` code.
    tier:   T0
    verify: cargo nextest run -p minrelay ticket_for_unregistered_node_refused

- **MMI-072** THE SYSTEM SHALL forward each binary frame between a client
  connection and its node's registration unchanged and in order, reading
  nothing of a frame beyond its length and, on the node leg, its address
  prefix (MMI-077).
  tier:     T1
  verify:   cargo nextest run -p minrelay frames_forwarded_verbatim_in_order
  property: for every sequence of datagrams sent on either leg, the paired leg receives the same datagrams, byte-identical, in the same order, the node leg's frames differing from the client leg's only by the address prefix; the test draws its sample from every frame length in {0, 1, 64, 1420, 65535}, counts up to 1,000, sent in order and interleaved on both legs
  - WHEN one leg of a pairing closes THE SYSTEM SHALL close the other within
    1 s.
    tier:   T0
    verify: cargo nextest run -p minrelay leg_close_propagates_within_one_second

- **MMI-073** THE SYSTEM SHALL hold no state that outlives a connection
  and write nothing to disk; after a restart every connection is gone and
  nothing is recovered.
  tier:     T0
  verify:   cargo nextest run -p minrelay restart_recovers_with_no_persisted_state

- **MMI-075** THE SYSTEM SHALL bound unauthenticated opens per source
  address to a configured budget (default 30 per minute; Gatehouse N8
  parity), refusing beyond it with the `over_cap` code.
  tier:     T0
  verify:   cargo nextest run -p minrelay rate_limit_closes_abusive_connection

- **MMI-076** THE SYSTEM SHALL log only node id, ticket key thumbprint,
  client mesh public key, source address, open and close times, close
  reason, and frame and byte counts, never a frame payload (the traffic
  metadata Gatehouse T29 names as the relay's residual).
  tier:     T1
  verify:   cargo nextest run -p minrelay relay_logs_metadata_only
  property: for every log line the relay writes at every log site, its fields are a subset of {node id, ticket key thumbprint, client mesh public key, source address, open time, close time, close reason, frame count, byte count}, and no field contains a byte sequence of any frame payload; walked over every log site against frames carrying sentinel bytes

- **MMI-077** THE SYSTEM SHALL address every frame on a node's registration
  with the 32-byte mesh public key of the client it belongs to: a frame from
  a client leg reaches the node prefixed with the key the client's mesh
  binding names (MMI-071), and a frame from the node reaches, prefix
  stripped, the client leg bound to the key its prefix names.
  tier:     T1
  verify:   cargo nextest run -p minrelay frames_are_addressed_by_client_mesh_key
  property: for every registered node n, every client leg bound to a mesh key k on n, and every frame f: a frame from that leg reaches n's registration prefixed with exactly k, and a frame from n prefixed with k' reaches, prefix stripped, exactly the leg bound to k' or is dropped when none is; walked over every (leg, key) pairing the relay holds
  - IF a second client leg opens for the same node and mesh public key THEN
    THE SYSTEM SHALL replace the earlier one and close it with the
    `replaced` code.
    tier:   T0
    verify: cargo nextest run -p minrelay newer_client_leg_replaces_older

## Non-goals

- The client core, the credential module's client half, and the browser
  contract, the peer document and relay ticket as consumed: the client core
  spec (MCC, gominimal/minimal#1355). `min`'s own use of this ingress and
  its listing of mesh nodes: MCC-051, MCC-054.
- The browser page: the browser client spec (WMC, gominimal/webapp#763).
- The `public` client kind, relay-ticket issuance, the node listing and
  heartbeat endpoints, the peer document, the mesh-attach host principal and
  the session-operation decisions: Gatehouse v1.11 to v1.16 (gominimal/arch#16
  to #22, closed); the address plan, the egress-policy feed and the
  `gateway` node class: Gatehouse v1.17. All are implemented in the
  identity plane.
- Enrolling a daemon with the identity plane and the provenance of its
  owner subject: Gatehouse §6.2; MMI-023 and MMI-025 read the subject from
  configuration meanwhile.
- The UDP mesh between daemons, its switch routing and its refusal logging:
  03-spec-networking Unit 4 (R4.2, R4.5), which MMI-003 to MMI-011 extend
  and otherwise leave as specified. MMI-004 (switch routing unchanged) and
  MMI-012 (no topology in a drop's log line) restated that spec and are
  retired; their IDs are not reused.
- Scrollback retention and replay on attach: no v1 client consumes it
  (MCC-061 declares none), and no criterion or decision asks for it.
  MMI-050 and MMI-052 are retired; the behaviour returns under a later id
  when a client asks.
- Relay capacity, per-node connection caps, per-connection frame and byte
  budgets, and keepalive timeouts: the relay's deployment configuration
  (Rollout), owned by its operator. MMI-074 is retired.
- Repaint and forwarding latency bounds: the proof of concept's loopback
  numbers are in gominimal/inbox#606; no bound was decided. MMI-N01 and
  MMI-N02 are retired; a benchmark owner is nobody's yet.
- Session recording (Gatehouse §14.4(1)): the direction plan's S9.
- Teammate access and `SshConnect` for non-owners: the direction plan's S8.
- A native mobile app and an in-process netstack: the direction plan's S13.
- The owner's own remote create, destroy, compose, `exec`, sftp and port
  forwarding, the remainder of the One Grammar story: local-only here
  (MMI-027) and in Gatehouse §7.4's v1 mapping, and bound by no spec yet.
- Copying files into or out of a box over the mesh, the epic's Sync Files
  Out story: bound by no spec yet; sftp stays local-only here.
- HTTP access to services inside boxes through a browser's tunnel: UC2b
  of the networking requirements, a product decision not yet taken.
- Inter-relay forwarding and relay-assisted hole punching: owned by no spec
  or issue yet; v1 is single-hop, and the relay-to-gateway leg is an open
  question.
- The gateway association, box address assignment, and the transport a
  Box Host is reached over in each deployment style: the deployment design
  (§4.1, §4.2, §4.5, §7) over the networking requirements v2
  (`specs/networking/networking-requirements.md`), implemented daemon-side
  by the networking spec in preparation (Open questions).

## Non-functional requirements

- **MMI-N05** WHILE no mesh, relay, or ingress is configured THE SYSTEM SHALL
  open no socket it does not open today (03-spec-networking R4.7).
  tier:   T0
  verify: cargo nextest run -p minimald unconfigured_daemon_opens_no_mesh_socket

## Design reasoning

**One spec for the daemon and the relay** (decided 2026-09-04). They share
the wire contract, and the relay is a new binary in this workspace,
`minrelay`, beside `min`, `mip`, `minimald` and `minvmd`. Separate documents
were considered and declined because the relay's only contract is what the
daemon and the client core send it. The identity plane's side is bound by
section since its v1.11 to v1.16.1 stack landed on 2026-09-07 and v1.17
added the address plan, the `gateway` node class and the heartbeat's
gateway and address members on 2026-09-10; the direction plan's decisions
of 2026-09-03 stand, and the v1 browser command set is owner-only list,
show, attach, rename and stop.

**Own-address termination on the existing TLS listener** (2026-09-03). The
daemon's WireGuard peer routes every decrypted packet to the box switch;
MMI-003 adds one destination, the daemon's own tunnel address, whose streams
enter the SSH server as non-local, so local-versus-remote stays a property
of the listener and is never inferred from transport type. The `/wg` route
lives on the TLS listener because 03-spec-networking R4.4 already proxies
WebSocket there, exempt from that listener's client certificate because the
WireGuard handshake is the authentication (MMI-002). A separate listener was
the alternative; it would have doubled the surface for no isolation gain.
Per-peer destination policy (MMI-005) keeps a browser peer off the switch
subnet until UC2b decides.

**Outbound-only by default, a Minimal-run relay for the rest** (2026-09-03;
architecture D7, Gatehouse §6.9 since v1.12). A page has no UDP and cannot
hole-punch, so a daemon behind NAT is reachable from a tab only through a
forwarder the daemon dials out to. A server hop that terminates anything was
ruled out; the relay carries WireGuard ciphertext wrapping SSH ciphertext,
holds no key and no session state, and reads nothing (MMI-072, MMI-073).
Nodes authenticate with `sshpop-host` as Gatehouse §10.2 prescribes for
outbound daemon connections; tabs present a per-node ticket bound to their
DPoP key, issued only where `ReadNode` admits the subject, so the relay
decides statelessly and the ticket authorizes routing only.

**On a pinned host the gateway forwards in the relay's role** (2026-09-10;
deployment design §4.5, architecture D8). The fabric pin admits one
destination, the node's Egress Gateway, so mesh and attach traffic transit
it, and the design makes that forwarding role exactly a D7 relay:
ciphertext frames, nothing terminated or read, nodes admitted by their
association and clients by relay ticket, over WireGuard on UDP or on a
WebSocket on 443 in the relay's framing where only TCP/443 leaves the host
(§4.1). The gateway is then the node's home relay and, for that node, the
direct path. MMI-071 to MMI-077 are the contract the role keeps; MMI-070's
`sshpop-host` registration is the relay's form of node admission, which
the association replaces. How a relay reaches a pinned node is open (Open
questions), and so is whether `minrelay` and the gateway become one binary
with roles (deployment design §12, item 1; gominimal/arch#43).

**Relay pairing and close codes** (the direction plan's S12). Each node
registers with one relay, its home, so v1 stays single-hop. Frames on a
registration are addressed by the client's mesh public key (MMI-077), the
one field the relay reads. The ticket's claim set carries no mesh key, so
the client presents its §6.9 binding beside the ticket and the relay takes
the key from it (MMI-071); asking the architecture for a `wg_pub` claim is
the open question. The close codes are a contract the client core acts on
(MCC-071, MCC-064): `expired` for a ticket past `exp`, `offline` for a node
with no live registration, `replaced` for a leg or registration superseded
by a newer one, `over_cap` beyond MMI-075's budget, `refused` for every
other failure. Capacity limits, keepalives and per-connection budgets were
drafted as requirements and retired on 2026-09-09 as operator configuration
with no decision behind them; only the N8-parity budget on unauthenticated
opens stays, because the architecture names it.

**`Certified` is an allowlist, and ownership is the ratified interim**
(2026-09-04; Gatehouse §7.4 since v1.16). No request is gated by
authentication today, so admitting a remote principal through the
session-channel gate alone would expose shutdown, cache, client-cert
issuance, exec, sftp and the create pipeline. Sessions are boxes, with no
parallel action family: attach is the cached `SshConnect`, show and each
listed row `BoxRead`, stop `StopBox`, rename `RenameBox`, a node-level
listing `ReadNode`. Reads were first admitted to every `Certified` subject
and made owner-only on 2026-09-09, because `BoxRead`'s shipped baselines are
ownership-shaped and teammate reads arrive with the S8 follow-up (MMI-027).
With no decision endpoint, MMI-025 admits only the configured owner subject.
Ownership needs a field the record lacks (MMI-023); every v1 session is
created locally and owned by the node's subject, whose provenance is open.
`StopSession` (MMI-028) reuses the internal stop daemon shutdown already
applies, keeping the record; mapping stop onto destroy, which deletes, or
abort, which acts only on a pending session, were the alternatives, and
destroy stays local-only because deletion is the one action a stolen tab
could not undo. The username is the box login principal (MMI-024, plan
Stage 3 option (i)); whether it must equal the record's sandbox user is
open.

**Rejection delay** (2026-09-04). The proof of concept inherited a 1 s
refusal delay meant to slow password guessing; a refused certificate gives
an attacker nothing to iterate on, and only a peer that completed a
WireGuard handshake reaches the SSH server at all. MMI-033 answers the first
refusal at once, so a client whose certificate expired at the reaper
boundary reconnects without dead time, and keeps the delay for repeated
attempts on one connection.

**Reaper without grace, warnings only for long certificates** (Gatehouse
§5.7 since v1.11). The cap at `valid_before` is exact (MMI-031); T-15 and
T-1 warnings are written only for certificates over an hour, since the
browser client renews at T-2 min and reconnects transparently. Renewal is
invisible to the daemon: the core attaches on a new connection under the
fresh certificate and closes its old channel, and a same-principal second
attach supersedes like any other (MMI-053).

**The host certificate names the node, never its tunnel address**
(Gatehouse §5.3 since v1.15). A mesh client dials the tunnel address and
verifies against the canonical `<node_id>.box.<td>` name the peer document
carries, so a change of tunnel address forces no renewal (MMI-029); the
first draft's tunnel-address principal is superseded.

**KRL** (Gatehouse §8.2). No Rust crate reads PROTOCOL.krl, so the reader
implements the certificates section the tenant CA emits and refuses anything
else (MMI-034); a KRL that parses but revokes nothing is the worse failure.

**Terminal state** (the direction plan's repaint decision; cross-spec close
causes). Today's re-attach restores the visible rows, the cursor and the
input modes and supersedes an earlier attacher with a notice and exit status
0. New are DEC 2026 framing and re-entering the alternate screen and focus
reporting (MMI-051), detached-not-exited semantics when a transport dies,
which today goes unnoticed (MMI-054), and a named close reason (MMI-053) so a
client core can tell supersession from tunnel loss and from the shell
exiting; MCC-065 is authoritative for the client-side names. Supersession is
last-attach-wins regardless of transport or principal, and skips `on_detach`
for a documented deadlock, while transport-loss detach runs it; whether the
deadlock applies there is open. Scrollback retention and replay were drafted
and retired on 2026-09-09: no v1 client declares a request for them.

**Heartbeats go to the identity plane** (2026-09-03; Gatehouse §8.2 since
v1.13), because the node set the tab lists and the peer document's
reachability are the identity plane's. The cadence is the architecture's
60 s working value with a 30 s floor (MMI-060); `seq` is monotonic on the
§8.2 anti-rollback discipline and persisted beside the KRL high-water mark
(MMI-061). Since v1.17 the heartbeat also carries the gateway association
and the per-box address assignments with their allocation epochs, the
inputs the egress-policy feed keys each `own_ip` box's entry by (Gatehouse
§6.9, §6.11), so a change to either is reported within MMI-060's 5 s. The
heartbeat now carries exactly the §8.2 payload; the daemon status that rode
on it as an interim superset answers `GetMeshStatus` alone. A provider's
readiness never implies liveness here (BPA-015 in the box-provider
abstraction spec states the provider's side).

**Tiers.** MMI-005, MMI-022, MMI-027 and MMI-072 were T1 from the first
draft; MMI-002, MMI-007, MMI-021, MMI-023, MMI-024, MMI-025, MMI-031,
MMI-035, MMI-037, MMI-038, MMI-061, MMI-076 and MMI-077 joined them on
2026-09-09 when review found the security invariants resting on example
tests. Each is a universal over a finite domain — a route table, an option
set, a method or principal vocabulary, the certificate and KRL vectors at a
fixed clock, a field allowlist, or every (leg, key) pairing — that the test
walks exhaustively, so no property-testing crate is added; the tier buys pure
decision functions over owned values, separate from the transport. MMI-072
ranges over unbounded sequences, so its test draws the sample its property
names. Everything else is T0 because it reaches a socket, a daemon or a
browser: MMI-006, MMI-020, MMI-026, MMI-028, MMI-053, MMI-054 and MMI-073 are
scenarios whose invariants are held by the T1 decisions beside them. Nothing
is T2 or T3: no proof project exists, and a harness over certificate parsing
is out of proportion.

**Generality:** a second WireGuard implementation on the peer side fits
MMI-001 to MMI-011 unchanged, though interop is proven boringtun-to-boringtun
only; an OpenSSH client inside the mesh fits the authentication surface,
whose rules are OpenSSH's own; a provider-run relay fits MMI-070 to MMI-077,
which need only the tenant Host CA and issuer keys, and a gateway's
forwarding role keeps MMI-071 to MMI-077 with its association in MMI-070's
place. What does not generalise is the owner rule (MMI-023, MMI-025): a
multi-user node needs the Cedar decisions Gatehouse §7.4 names, which is
why that phase is interim.

## Security considerations

- **Invariant:** THE SYSTEM SHALL let no party other than the client and
  the daemon read SSH or WireGuard plaintext.
  enforced by: the relay forwarding frames unchanged, reading only the
  address prefix, and holding no key (Gatehouse T29; architecture D7).
  covered by: MMI-072, MMI-073, MMI-076, MMI-077
- **Invariant:** THE SYSTEM SHALL admit no peer and no user on a
  forwarder's word, so a compromised relay or gateway on the attach path
  holds ciphertext and traffic metadata only.
  enforced by: peer admission against a valid §6.9 binding and user
  admission on a certificate, both decided at the daemon; a gateway
  forwarding in the relay's role (deployment design §4.5) is bounded as the
  relay is (Gatehouse T29, T30).
  covered by: MMI-005, MMI-010, MMI-020, MMI-022
- **Invariant:** THE SYSTEM SHALL open no channel on a non-local connection
  without an accepted certificate decision and an authorization decision
  for its subject.
  enforced by: `Certified` reached only through the decision function;
  `none` refused; no public-key path without configuration; the owner rule
  or the cached `SshConnect` decision before the channel opens.
  covered by: MMI-020, MMI-021, MMI-022, MMI-025, MMI-026, MMI-038
- **Invariant:** THE SYSTEM SHALL admit under `Certified` no capability
  outside its allowlist, and no read or mutation of a session by a subject
  other than its owner.
  enforced by: the per-auth-state allowlist with the ownership check
  against the recorded owner (Gatehouse §7.4 baselines).
  covered by: MMI-023, MMI-027, MMI-028
- **Invariant:** THE SYSTEM SHALL use no canonical-subject string as a
  sandbox user.
  enforced by: the username rule refusing subject-form names before any
  channel opens.
  covered by: MMI-024
- **Invariant:** THE SYSTEM SHALL keep no `Certified` connection alive past
  its certificate's expiry or revocation, and never accept a KRL older than
  the one it enforces.
  enforced by: the reaper, KRL application, and the persisted high-water
  mark (Gatehouse §5.7, §8.2).
  covered by: MMI-031, MMI-035, MMI-037
- **Invariant:** THE SYSTEM SHALL keep a session's process running through
  any loss of the transport attached to it and any daemon-initiated close of
  its channel other than daemon shutdown (MMI-053).
  enforced by: transport loss, supersession, expiry and revocation closes
  detaching, never destroying.
  covered by: MMI-006, MMI-031, MMI-037, MMI-053, MMI-054
- **Invariant:** THE SYSTEM SHALL expose no inbound mesh listener without
  explicit configuration.
  enforced by: the outbound-only default (Gatehouse §10.2); MMI-N05 states
  the unconfigured daemon's socket set.
  covered by: MMI-002, MMI-007
- **Invariant:** THE SYSTEM SHALL write no session name, project path, or
  screen content into a heartbeat, a mesh-status answer, or a relay log.
  enforced by: the fixed metadata vocabulary of the heartbeat and of the
  relay's log lines.
  covered by: MMI-061, MMI-076

## Rollout

- **Deploy:** `minrelay` per region behind Minimal's DNS, with the Host CA
  and issuer keys of the tenants it serves in its configuration and its URL
  published in the `relays` member of each tenant's
  `gatehouse_node_endpoints` (Gatehouse §8.2); its caps, budgets and
  keepalives are deployment configuration. The daemon side needs no rollout
  step: every ingress, authentication and relay behaviour is off without
  configuration (MMI-N05). The terminal-state group (MMI-051 to MMI-055) is
  on for every transport: a local client sees the DEC 2026 repaint, the
  attachment state, and a named exit signal on supersession where today's
  `min` sees exit status 0.
- **Rollback:** redeploy the previous image; connections drop and daemons
  reconnect within the MMI-008 backoff; no state to migrate.
- **Blast radius:** browser sessions to NAT'd daemons in that region; direct
  paths and every local session are unaffected.

## Open questions

- [NEEDS CLARIFICATION (HIGH): the networking spec in preparation
  implements, daemon-side, the deployment design's gateway association and
  forwarding role (§4.1, §4.5) over the networking requirements v2 (the
  five deployment styles, UC2b's browser with no installed client, UC5's
  escape-surviving floor, UC8 outbound-only operation, UC12 encryption in
  transit). Do the daemon's relay leg and path choice (MMI-008, MMI-009)
  move into it, and does the relay group follow `minrelay` if it
  consolidates with the gateway (deployment design §12, item 1)?] Survives
  because the networking spec does not exist yet and the consolidation is
  open in the architecture; the authentication surface, terminal state and
  heartbeats stay here either way.
- [NEEDS CLARIFICATION (HIGH): 03-spec-networking Unit 4 has no own-address
  termination and no WireGuard-over-WebSocket ingress; R4.2's path ends at a
  box, and R4.3 and B6 still name wireguard-go. MMI-001 to MMI-003 extend
  Unit 4, whose text should say so.] Survives because it is an amendment to
  a shipped spec in this workspace, and the networking spec above may make
  it moot.
- [NEEDS CLARIFICATION (MEDIUM): the relay ticket's claim set in Gatehouse
  §6.9 carries no mesh public key, which the relay needs to address frames
  (MMI-077); MMI-071 takes it from the §6.9 binding presented beside the
  ticket, which makes the relay verify two JWS at open. Should the ticket
  carry a `wg_pub` claim instead?] Survives because it is a change to the
  architecture of record and belongs with its owner.
- [NEEDS CLARIFICATION (MEDIUM): the deployment design names a pinned
  node's gateway its home relay and admits nodes there by association
  (§4.5), yet keeps the relays in every node's baseline set (§5.1), and a
  relay ticket names the pinned node, which then holds no relay
  registration of its own (MMI-071's `offline` close). Does a pinned node
  also register with the relay through its gateway (MMI-008), does the
  gateway register for its nodes, or do clients dial the gateway
  directly?] Survives because the design leaves the relay-to-gateway leg
  of §4.5 unshaped.
- [NEEDS CLARIFICATION (MEDIUM): the interim owner rule. Every v1 session is
  created over a local connection; MMI-023 assigns it to the node's owner
  subject, read from configuration until enrollment (Gatehouse §6.2)
  exists. Is that subject written by `min auth login`, by enrollment, or by
  hand?] Survives because enrollment is the identity plane's and has no
  daemon-side shape yet.
- [NEEDS CLARIFICATION (MEDIUM): under `Certified`, today's attach path
  passes the connection's username to the host launch as the sandbox user
  while the record carries the creating user's name. MMI-024 admits the box
  login principal; must it equal the record's username, or does the
  record's win on attach?] Survives because the two readings build
  different things and nobody has chosen.
- [NEEDS CLARIFICATION (MEDIUM): should `GetMeshStatus` open under
  `Certified` for the owner? MMI-027 keeps it local-only.] Survives because
  no client asks for it yet.
- [NEEDS CLARIFICATION (MEDIUM): MMI-054 runs `on_detach` hooks on a
  transport-loss detach while supersession skips them for a documented
  deadlock. Does the same deadlock apply when the binding is torn down from
  a dead channel?] Survives because it needs a test against the daemon, not
  a decision.
- [NEEDS CLARIFICATION (LOW): MMI-022 recognises the `source-address`
  critical option but no requirement enforces it against the peer's tunnel
  address, which OpenSSH would. Should MMI-022 gain that edge?] Survives
  because no tenant policy pins `source-address` today.
