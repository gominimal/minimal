---
id: MMI
title: "minimald as a mesh-reachable session host: WireGuard ingress, certificate auth, terminal state, relay"
status: draft
owner: mitodrummer
epic: gominimal/inbox#513
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-09
---

# MMI — minimald as a mesh-reachable session host: WireGuard ingress, certificate auth, terminal state, relay

## Context

A session daemon today answers only its Unix socket or vsock and trusts
whoever reaches it; nothing outside the machine can attach. The
remote-sessions epic needs a browser tab to attach to a session on any of a
developer's daemons with SSH ending in the tab, and to leave the session
running when the tab closes. The daemon already has a WireGuard peer that
routes tunnel packets onto its box switch (started only under test today), a
TLS listener, and a screen model per session; it lacks a way for a page with
no UDP to hand it datagrams, SSH terminating at its own tunnel address, an
authentication decision for a non-local peer, an authorization rule for any
request such a peer makes, and a path to a daemon behind NAT.

After this ships a daemon accepts WireGuard over a TLS WebSocket, terminates
SSH inside its own tunnel, admits a connection only on a Gatehouse-shaped
certificate, reaches the outside through an outbound connection to a
Minimal-run relay by default, reports its liveness to the control plane, and
repaints the current screen on every re-attach. This document covers the
daemon and the relay, `minrelay`, a fifth binary of this workspace beside
`min`, `mip`, `minimald`, and `minvmd`; the client core is
[13-spec-min-client-core](../13-spec-min-client-core/13-spec-min-client-core.md).

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

The initiative's sixth done-when step, boxes and sessions seen from both the
shell and the browser (gominimal/inbox#494), is the context this split was
made in, not a criterion of this epic.

## Requirements

Configuration vocabulary. The control-plane issuer is one configuration
item; every node-scoped endpoint this document names, the KRL feed
(MMI-035), the decision endpoint (MMI-026), host-certificate renewal
(MMI-029), the heartbeat (MMI-060), the peer document's mirror (MMI-010)
and the relay set (MMI-008), is discovered from that issuer's
`gatehouse_node_endpoints` (Gatehouse §8.2), so "WHERE … is configured" in
each of them means the issuer is configured and advertises that endpoint.
"Direct ingress" (MMI-007) is the one opt-in that opens the UDP mesh socket
and the `/wg` route on a non-loopback address; the WebSocket ingress of
MMI-001 is that route, one of the direct-ingress options, and on a loopback
address it needs no opt-in.

### Mesh ingress

- **MMI-001** WHERE the WebSocket ingress is enabled THE SYSTEM SHALL accept
  WireGuard datagrams as binary frames, one datagram per frame, over a
  WebSocket at the direct endpoint it advertises, the `/wg` route of its TLS
  listener (03-spec-networking R4.4, port 7655; the endpoint the peer
  document carries, MMI-010), and a peer's tunnel SHALL behave identically
  on that carrier and on UDP.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_ingress_ws_frames_reach_the_same_tunnels

- **MMI-002** THE SYSTEM SHALL serve the `/wg` route without a TLS client
  certificate; the WireGuard handshake is that route's authentication (R4.4,
  R4.5).
  tier:     T1
  verify:   cargo nextest run -p minimald wg_route_needs_no_client_certificate
  property: for every route r the TLS listener registers and every request to r that carries no client certificate, r is served iff r = `/wg`, and every other r answers the existing empty 401; walked over the listener's route table
  - THE SYSTEM SHALL keep answering every other route on that listener
    without a client certificate with the existing empty 401.
    tier:   T0
    verify: cargo nextest run -p minimald other_routes_still_require_a_client_certificate

- **MMI-003** WHEN a decrypted packet from an admitted peer is addressed to
  the daemon's own tunnel address THE SYSTEM SHALL answer it itself rather
  than route it to the switch, serving a TCP connection that completes on
  its SSH port there as a non-local SSH connection.
  tier:     T0
  verify:   cargo nextest run -p minimald own_address_terminates_at_the_ssh_server

- **MMI-004** WHEN a decrypted packet from an admitted peer is addressed to
  the daemon's advertised switch subnet THE SYSTEM SHALL route it to the
  switch as before (R4.2).
  tier:     T0
  verify:   cargo nextest run -p minimald switch_bound_packets_still_reach_the_sink

- **MMI-005** THE SYSTEM SHALL drop a decrypted packet whose source address
  is outside the sending peer's allowed addresses or whose destination is
  outside the destinations that peer's configuration admits, counting the
  drop without logging an address (R4.5).
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
  (SSHPOP.md §5.1.1(b), `aud` the relay's canonical URL from the `relays`
  member of `gatehouse_node_endpoints`; Gatehouse §6.9, §8.2; architecture
  D7), and treat each frame received there as a datagram from its UDP socket
  whose source is the mesh public key the frame is addressed with (MMI-077).
  tier:     T0
  verify:   cargo nextest run -p minimald relay_client_registers_with_sshpop_host
  - IF the relay connection fails or closes THEN THE SYSTEM SHALL reconnect
    with backoff from 1 s doubling to a 60 s cap, each delay jittered by up
    to 10%, until it succeeds.
    tier:   T0
    verify: cargo nextest run -p minimald relay_client_reconnects_with_bounded_backoff

- **MMI-009** THE SYSTEM SHALL send to a peer over a direct endpoint whenever
  that endpoint has authenticated a datagram from the peer within 180 s, and
  otherwise over the relay connection addressed to that peer (direct paths
  preferred, the relay the fallback — Gatehouse §6.9, architecture D7).
  tier:     T0
  verify:   cargo nextest run -p minimald direct_endpoint_preferred_over_relay

- **MMI-010** WHERE a peer document is configured THE SYSTEM SHALL fetch the
  daemon's mirror view of it — `GET /v1/mesh/peers` under `sshpop-host`, the
  node-scoped endpoint advertised in `gatehouse_node_endpoints`, a
  `gatehouse-mesh-peers+jws` feed carrying the keys to admit with their
  bindings, tunnel addresses per `MeshNetwork` and the node's relay
  assignment (Gatehouse §6.9 v1.14, §8.2) — and admit a peer only while the
  document holds a valid, unexpired mesh binding for that peer's key,
  re-checked at every rekey; the document configures and never authorizes,
  so a forged or stale one can mis-route but never admit.
  tier:     T0
  verify:   cargo nextest run -p minimald peer_admitted_only_against_a_valid_binding
  - IF a binding expires or is revoked, by TTL or by the document's in-band
    `revoked_bindings[]` delta, THEN THE SYSTEM SHALL refuse the peer's next
    handshake and end its carried connections within 60 s.
    tier:   T0
    verify: cargo nextest run -p minimald revoked_binding_ends_the_peer
  - IF a document's `seq` regresses below the last accepted for its
    (audience, mesh), or its `issued_at` is older than the 5 min staleness
    bound, THEN THE SYSTEM SHALL keep the last accepted document, admit no
    peer it did not already admit, and leave established tunnels to ride
    their bindings' TTLs (the §8.2 anti-rollback discipline).
    tier:   T0
    verify: cargo nextest run -p minimald stale_or_regressed_peer_document_admits_no_new_peer

- **MMI-011** WHERE a static peer table is configured and no peer document is
  THE SYSTEM SHALL admit exactly the listed keys (R4.1); the static table and
  `min net mesh join`'s manual key exchange are the proof-of-concept interim
  the peer document retires (Gatehouse §6.9, v1.14).
  tier:     T0
  verify:   cargo nextest run -p minimald static_peer_table_admits_listed_keys_only

- **MMI-012** WHEN a datagram from an unrecognised source or a failed
  handshake is dropped THE SYSTEM SHALL log at most the bare source address,
  never a peer name, tunnel, switch, or session name (R4.5).
  tier:     T1
  verify:   cargo nextest run -p minimald mesh_auth_failure_logs_no_topology
  property: for every drop reason the mesh layer emits and every dropped datagram d, the log line written for d carries at most d's source address and none of the names in the peer table, the tunnel, the switch or any session; walked over every drop reason against a topology whose names are sentinel strings

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
  validity, critical options, revocation, principal — one of
  `bad_signature`, `unknown_ca`, `wrong_cert_type`, `cert_not_yet_valid`,
  `cert_expired`, `unknown_critical_option`, `cert_revoked`,
  `principal_mismatch` — the same decision and order as the client core's
  (MCC-034).
  tier:     T1
  verify:   cargo nextest run -p minimald cert_decision_matches_the_arch_vectors_at_the_fixed_clock
  property: for every case in gominimal/arch spec/vectors/ssh-certs/invalid/manifest.json at clock 1750000000 with krl/krl-v1.bin loaded, the decision is Err(expected_error); for user-interactive-valid.cert it is Ok for username `dev` and Err(principal_mismatch) for `nobody`
  - IF a certificate reaches the decision THEN THE SYSTEM SHALL log the
    outcome with the serial and `key_id`, never the certificate bytes.
    tier:   T0
    verify: cargo nextest run -p minimald refusal_codes_are_logged_with_serial_and_key_id

- **MMI-023** THE SYSTEM SHALL hold on every session record an owner
  subject — the certificate subject of the connection that created it, or,
  for a session created over a local connection, the node's enrolled
  subject, the `local`-class linkage of Gatehouse §6.2 F16(a), held in
  configuration as the owner subject of MMI-025 until enrollment exists —
  and SHALL compare that owner, never the record's sandbox username, when
  an ownership-gated request arrives; a record created before a subject was
  configured is owned by no subject and refuses every ownership-gated
  request.
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
  opens, and with no owner subject configured SHALL admit no certificate —
  the ownership interim Gatehouse §7.4 (v1.16) ratifies rather than
  replaces, its shipped baselines being ownership-shaped.
  tier:     T1
  verify:   cargo nextest run -p minimald owner_subject_rule_admits_only_the_owner
  property: for every subject s in the arch's user-certificate vectors and every configured owner o drawn from the same set or absent, admitted(s) iff o is present and s = o; walked over the vectors' subject set

- **MMI-026** WHERE a decision endpoint is configured THE SYSTEM SHALL open a
  session channel for a `Certified` connection only on an allow `SshConnect`
  decision for (subject, session) cached within 60 s, fetching a missing one
  with a 2 s deadline and denying on deadline or unreachability (Gatehouse
  §6.3.1), and SHALL evaluate the other admitted requests on the same cache
  as Gatehouse §7.4 (v1.16) maps them — sessions are boxes: `BoxRead` for
  `GetSessionRecord`, `GetSessionScreen` and each `ListSessions` row,
  `ReadNode` over (subject, node) for the listing itself and for
  `GetVersion`, `StopBox` for `StopSession`, `RenameBox` for
  `RenameSession`. The daemon's RPC evaluation point is that evaluation,
  and it lands with this requirement; until a decision endpoint is
  configured, MMI-025 and MMI-027 govern: every read, attach and mutation
  is admitted for the record's owner and refused to every other subject.
  tier:     T0
  verify:   cargo nextest run -p minimald decision_cache_miss_fails_closed_when_the_sts_is_unreachable

- **MMI-027** THE SYSTEM SHALL admit a channel request, subsystem, exec
  request, or direct-tcpip open by auth state: under `Local`, everything;
  under `Certified`, `GetVersion`, and, for a session the connection's
  subject owns (MMI-023; the creator baseline of `BoxRead`, `RenameBox` and
  `StopBox`, Gatehouse §7.4, owner-only in v1), the shell attach path
  including the attach that restarts a stopped session (MMI-028),
  `GetSessionRecord`, `GetSessionScreen`, `RenameSession` and
  `StopSession`, with `ListSessions` returning only the rows the subject
  owns; under `Pending`, nothing; refusing with channel failure or an
  administratively-prohibited open. Every request outside that list stays
  local-only in v1, as §7.4 keeps exec, direct-tcpip, sftp, shutdown,
  cache, diagnostics, client-cert issuance, create and destroy.
  tier:     T1
  verify:   cargo nextest run -p minimald rpc_allowlist_by_auth_state
  property: for every auth state s, every request r in the daemon's dispatched subsystem, exec, sftp and direct-tcpip vocabulary, and every ownership o in {owner, other}: admit(s, r, o) iff s = Local, or s = Certified and r = GetVersion, or s = Certified and o = owner and r in {attach, GetSessionRecord, GetSessionScreen, RenameSession, StopSession}; and every `ListSessions` row returned under Certified has o = owner; walked exhaustively
  - IF a `Certified` connection sends `exec`, `sftp`, `direct-tcpip`, or a
    subsystem outside the allowlist — `Shutdown`, `CleanCache`,
    `DiagBundleTarZst`, `IssueClientCert`, `GetMeshStatus`, the create
    pipeline (`CreateSession`, `ConfigureLoadout`, `SubmitVerdict`,
    `FinalizeSession`), `DestroySession`, `AbortSession`, `SessionDelta`,
    `GetSessionPolicy`, `GetSessionHooks`, and the workspace streams — THEN
    THE SYSTEM SHALL refuse it without side effects.
    tier:   T0
    verify: cargo nextest run -p minimald local_only_requests_refused_under_certified

- **MMI-028** WHEN `StopSession` is admitted (the `StopBox` decision of
  Gatehouse §7.4, whose stop-the-process-keep-the-record semantics it
  carries) THE SYSTEM SHALL end the session's process without the exit
  prompt, keep the record, end any
  attached channel with the process's exit status as for a shell exit
  (MMI-053 names no signal for it), list the session as exited with no
  running attributes (MMI-055), answer a screen read as not active, and
  start a fresh shell in the same workspace on the next attach.
  tier:     T0
  verify:   cargo nextest run -p minimald stop_session_ends_the_process_and_keeps_the_record

- **MMI-029** WHERE a host certificate is configured THE SYSTEM SHALL present
  it on every non-local connection, with principals covering the node's
  canonical `<node_id>.box.<td>` name and the per-node wildcard
  `*.<node_id>.box.<td>`, and never the daemon's tunnel address (Gatehouse
  §5.3 mesh attaches, v1.15: a mesh client dials the tunnel address and
  verifies against the canonical name the peer document carries).
  tier:     T0
  verify:   cargo nextest run -p minimald host_certificate_presented_on_mesh_ingress
  - IF the host certificate is absent, unparsable, or expired THEN THE SYSTEM
    SHALL accept no non-local SSH connection; local listeners are unaffected.
    tier:   T0
    verify: cargo nextest run -p minimald expired_host_certificate_disables_the_mesh_ingress
  - WHERE a renewal endpoint is configured THE SYSTEM SHALL renew the host
    certificate at 50% of its lifetime, authenticating with the current one,
    requesting no tunnel address as a principal, and present the new one
    without a restart; a change of tunnel address forces no renewal.
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
    shorter lifetime none — the daemon-side rule Gatehouse §5.7 (v1.11)
    names for the browser min client's 15-minute certificate, whose client
    renews at T-2 min (§6.1.7).
    tier:   T0
    verify: cargo nextest run -p minimald wall_warnings_only_for_long_lived_certificates

- **MMI-033** THE SYSTEM SHALL answer the first refused authentication
  attempt on a non-local connection within 100 ms, delay each later refusal
  on the same connection by at least 1 s, and close the connection after its
  third refusal.
  tier:     T0
  verify:   cargo nextest run -p minimald rejection_delay_zero_initial_then_one_second

- **MMI-034** THE SYSTEM SHALL read a KRL in OpenSSH PROTOCOL.krl format
  with its certificates section (explicit serials and serial ranges) and
  reproduce gominimal/arch spec/vectors/krl/expected-revoked.json for
  krl/krl-v1.bin.
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
  - IF a private key file is readable by group or others THEN THE SYSTEM
    SHALL refuse to start the mesh and every non-local listener.
    tier:   T0
    verify: cargo nextest run -p minimald world_readable_key_file_refuses_mesh_start

### Terminal state

- **MMI-050** THE SYSTEM SHALL retain, per live session, at least the last
  1,000 lines scrolled off the visible screen.
  tier:     T0
  verify:   cargo nextest run -p minimald scrollback_retains_one_thousand_lines

- **MMI-051** WHEN a client attaches to a session whose shell process is
  already running — every attach but the one that starts the shell — THE
  SYSTEM SHALL write, before any new output, a repaint reproducing the
  current visible screen, the cursor's position and visibility, and every
  private mode the session has turned on (alternate screen, application
  keypad and cursor keys, bracketed paste, mouse reporting and its encoding,
  focus reporting), sized to the attaching terminal and wrapped in a
  synchronized-update pair (DEC private mode 2026), so that a client's first
  bytes at its first attach and after every renewal are the current screen
  (MCC-063).
  tier:     T0
  verify:   cargo nextest run -p minimald reattach_lands_on_the_current_screen_in_one_frame

- **MMI-052** WHERE an attach declares a scrollback request — an `env`
  channel request naming `MINIMAL_SCROLLBACK=<lines>` before the shell
  request, the interim carrier while no client core declares one (MCC-061)
  — THE SYSTEM SHALL write up to the requested number of scrollback lines as
  plain lines ahead of the repaint, and otherwise write none; no v1 client
  declares one.
  tier:     T0
  verify:   cargo nextest run -p minimald reattach_replays_the_requested_scrollback_tail

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
  hooks as an explicit detach does, keep advancing its screen model and
  scrollback while detached, and accept a later attach that lands on the
  screen as it is then.
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
  send a heartbeat to `POST /v1/nodes/heartbeat` (Gatehouse §8.2, v1.13; the
  node-scoped endpoint advertised in `gatehouse_node_endpoints`) every 60 s
  by default (configurable within 30 s, the server-enforced floor, to
  300 s, up to 10% jitter), authenticated with its node identity (SSHPOP.md
  §5.1.1(b), `aud` the advertised URL), and within 5 s of its relay
  connection or direct ingress changing state.
  tier:     T0
  verify:   cargo nextest run -p minimald heartbeat_interval_and_state_change_within_bounds
  - IF the heartbeat endpoint is unreachable THEN THE SYSTEM SHALL keep
    serving every connection unchanged against its cached anchors and last
    KRL, retry at the next interval, and log the failure at most once per
    minute.
    tier:   T0
    verify: cargo nextest run -p minimald heartbeat_failure_does_not_affect_serving

- **MMI-061** THE SYSTEM SHALL carry in a heartbeat a `seq` that increases
  with every heartbeat it sends and the `reachability` the identity plane
  consumes — `direct_endpoint` where direct ingress is enabled, `relay` where
  registered, and `mesh_addresses` (the payload of Gatehouse §8.2:
  `{seq, reachability: {direct_endpoint?, relay?, mesh_addresses[]}}`, the
  peer document's input) — and, in the heartbeat and in `GetMeshStatus`,
  only its node id, daemon version, mesh public key, tunnel address, direct
  endpoints, relay name and connection state, host-certificate serial and
  expiry, KRL `seq`, and the number of live sessions — a superset of the
  §8.2 payload, sent on the interim assumption that the endpoint ignores
  unknown members (Open questions); never a session name, project path, or
  screen content.
  tier:     T1
  verify:   cargo nextest run -p minimald heartbeat_carries_no_session_data
  property: for every heartbeat and every `GetMeshStatus` answer the daemon emits, its member set is a subset of {seq, reachability, node id, daemon version, mesh public key, tunnel address, direct endpoints, relay name, relay connection state, host-certificate serial, host-certificate expiry, KRL seq, live session count}, and no value in it equals a session name, a project path or a screen line of any live session; walked over the emitter vocabulary against sessions whose names, paths and screens carry sentinel strings
  - THE SYSTEM SHALL persist the heartbeat `seq` so that a restart never
    regresses it, a regression being rejected by the identity plane
    (Gatehouse §8.2).
    tier:   T0
    verify: cargo nextest run -p minimald heartbeat_seq_never_regresses_across_restart

### Relay

- **MMI-070** THE SYSTEM SHALL accept a node registration only over TLS with
  an `sshpop-host` assertion whose `aud` is the relay's canonical URL as
  advertised in the tenant's `gatehouse_node_endpoints` `relays` member
  (Gatehouse §6.9, §8.2; architecture D7) and whose certificate chains to a
  configured tenant Host CA, keyed by the node id the certificate names.
  tier:     T0
  verify:   cargo nextest run -p minrelay node_registration_requires_sshpop_host
  - IF a second registration arrives for the same node THEN THE SYSTEM SHALL
    replace the earlier one and close it with the `replaced` code (Design
    reasoning names the close codes).
    tier:   T0
    verify: cargo nextest run -p minrelay newer_registration_replaces_older
  - IF a registration or a client connection answers no keepalive for 90 s
    THEN THE SYSTEM SHALL close it.
    tier:   T0
    verify: cargo nextest run -p minrelay idle_leg_closed_after_missed_keepalives

- **MMI-071** THE SYSTEM SHALL accept a client connection only with a
  Gatehouse-issued relay ticket, presented at WebSocket open — a
  `gatehouse-relay-ticket+jws` over `{td, sub, node_id, cnf.jkt, iat, exp,
  jti}` (Gatehouse §6.9, §14.1) — that verifies statelessly under the
  issuer's published keys with no call to the issuer, names one node, is
  unexpired, and is bound by `cnf.jkt` to a key whose DPoP proof over the
  ticket the client presents with it, together with the client's own §6.9
  mesh binding, from which the relay takes the client's mesh public key
  (the ticket carries none; MMI-077, MCC-071) — the interim this document
  shares with MCC-071 until the architecture answers whether the ticket
  should carry the key (Open questions); otherwise it closes with no body
  and the `expired` code for a ticket past `exp` or the `refused` code for
  every other failure (Design reasoning names the close codes). The ticket
  authorizes routing only (§6.9, T29).
  tier:     T0
  verify:   cargo nextest run -p minrelay ticket_bound_to_dpop_key_required
  - IF the ticket's node has no live registration THEN THE SYSTEM SHALL close
    with the `offline` code.
    tier:   T0
    verify: cargo nextest run -p minrelay ticket_for_unregistered_node_refused

- **MMI-072** THE SYSTEM SHALL forward each binary frame between a client
  connection and its node's registration unchanged and in order, reading
  nothing of a frame beyond its length and, on the node leg, its address
  prefix (MMI-077) — the "cannot read box traffic" invariant box-provider-api
  v0.6 §1 and §10 state for a ciphertext relay, and Gatehouse T29.
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

- **MMI-074** THE SYSTEM SHALL cap concurrent client connections per node
  (default 16) and per ticket key (default 4), refusing beyond the cap with
  the `over_cap` code.
  tier:     T0
  verify:   cargo nextest run -p minrelay per_node_connection_cap_enforced

- **MMI-075** THE SYSTEM SHALL bound each connection to a configured budget
  (default 2,000 frames/s and 20 MiB/s), close one that exceeds it for 10 s,
  and bound unauthenticated opens per source address to a configured budget
  (default 30 per minute; Gatehouse N8 parity).
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

- The client core, the credential module's client half, and the browser JS
  contract, including the peer document and relay ticket as consumed:
  [13-spec-min-client-core](../13-spec-min-client-core/13-spec-min-client-core.md).
- `min`'s own use of this ingress from the shell, and the CLI's listing of
  mesh nodes: MCC-051 and MCC-054.
- The browser page: the browser client spec in gominimal/webapp (WMC,
  gominimal/webapp#763).
- The `public` client kind and certify for it (Gatehouse §6.1.7, §5.7,
  v1.11), relay-ticket issuance (§6.9, v1.12), the node listing and
  heartbeat endpoints (§8.2, v1.13), the peer document (§6.9, v1.14), the
  mesh-attach host principal (§5.3, v1.15), the session-operation decisions
  (§7.4, v1.16) and mesh binding (§6.9): recorded in the architecture of
  record on 2026-09-07 (gominimal/arch#16 to #22), implemented in the
  identity plane, gominimal/gatehouse `01-spec-*` lineage.
- Enrolling a daemon with the identity plane and the provenance of its
  owner subject: Gatehouse §6.2 F16(a) and gominimal/gatehouse; MMI-023 and
  MMI-025 read the subject from configuration meanwhile.
- Session recording (Gatehouse §14.4(1)): the plan's S9, a separate epic.
- Teammate access and `SshConnect` for non-owners: the plan's S8.
- Mobile and an in-process netstack app: the plan's S13.
- The UDP mesh between daemons (03-spec-networking Unit 4) except where
  MMI-003 to MMI-011 change it.
- The owner's own remote create, destroy, compose, `exec`, sftp and port
  forwarding, the remainder of the One Grammar story: local-only here
  (MMI-027) and in Gatehouse §7.4's v1 mapping, and bound by no spec yet;
  per-principal rules for them once they open are the plan's S8.
- Copying files into or out of a box over the mesh, the epic's Sync Files
  Out story: bound by no spec yet; sftp stays local-only here (MMI-027) and
  neither the client core nor the browser page consumes it.
- HTTP access to services inside boxes through a browser's tunnel:
  03-spec-networking UC2b, a product decision not yet taken.
- Inter-relay forwarding and relay-assisted hole punching: owned by no spec
  or issue yet; v1 is single-hop.

## Non-functional requirements

- **MMI-N01** WHILE a session's screen is 80×24 with 1,000 scrollback lines
  THE SYSTEM SHALL complete the attach repaint, first byte to
  synchronized-update end, within 100 ms on the daemon side.
  tier:   T0
  verify: cargo nextest run -p minimald bench_reattach_repaint_under_100ms

- **MMI-N02** WHILE forwarding 1,000 frames/s on one connection over loopback
  THE SYSTEM SHALL add at most 1 ms p50 and 5 ms p99 per frame.
  tier:   T0
  verify: cargo nextest run -p minrelay bench_forwarding_overhead

- **MMI-N05** WHILE no mesh, relay, or ingress is configured THE SYSTEM SHALL
  open no socket it does not open today (R4.7).
  tier:   T0
  verify: cargo nextest run -p minimald unconfigured_daemon_opens_no_mesh_socket

## Design reasoning

**One spec for the daemon and the relay** (decided 2026-09-04): they share
the wire contract, and the relay is a new binary in this workspace,
`minrelay`, the fifth beside `min`, `mip`, `minimald`, and `minvmd`; the pull
request that adds its crate extends AGENTS.md's binaries table and crate map
and docs/architecture.md §3 (plan S5). The client core, the browser page, and
Gatehouse have their own documents; this one binds them by section since the
Gatehouse v1.11 to v1.16.1 stack landed on 2026-09-07 (arch#16 to #22
closed), so A4 — identity-plane capabilities as named dependencies — is no
longer an assumption. Working assumptions, defaults rather than decisions:
the plan's 2026-09-03 decisions stand (A2); the browser is on its own origin
(A3); the v1 browser command set is owner-only list, show, attach, rename,
and stop (A1; Gatehouse §7.4 since v1.16 maps them onto existing decisions,
below).

**What exists today, and what is new** (verified against the tree,
2026-09-04). The daemon dispatches the `minimald-v1-` subsystems
`GetVersion`, `ListSessions`, `GetSessionRecord`, `CreateSession`,
`ConfigureLoadout`, `SubmitVerdict`, `FinalizeSession`, `RenameSession`,
`DestroySession`, `Shutdown`, `AbortSession`, `GetSessionPolicy`,
`GetSessionHooks`, `SessionDelta`, `GetSessionScreen`, `GetMeshStatus`, the
three workspace streams, `DiagBundleTarZst`, `CleanCache`, and
`IssueClientCert` (feature-gated); `DynamicPortMap` is declared, never
dispatched, and stays so; sftp is its own subsystem; exec is a channel
request with the `min://` vocabulary, not a subsystem. No request is gated by
authentication: the one gate is the session-channel open, which refuses
anything but `Local`, both listeners are `Local`, the auth states are
`Pending` and `Local`, and only `none` authentication exists. A session record
carries the creating user's name as its sandbox user and no owner; nothing
compares a caller to it. `GetSessionScreen` returns the visible grid and the
cursor. A re-attach resizes the screen model to the client and writes the
visible rows with attributes, the cursor's position and visibility, and the
input modes (application keypad and cursor keys, bracketed paste, mouse mode
and encoding); it does not re-enter the alternate screen (its contents are
replayed, the mode is not set), restore focus reporting, or replay
scrollback (the parser keeps none), and nothing frames output with DEC 2026;
`on_attach` hooks run on every attach; the PTY is resized only when the size
changed. A second attach supersedes the first with the mode-unwind codes, the
notice "Disconnecting - session attached to from a different connection",
EOF, exit status 0, and close — no exit signal, and no `on_detach` hooks (a
documented deadlock). A binding never notices its transport dying: it keeps
writing into the dead channel, and the session runs on with no detach, no
hooks, and no prompt. The exit prompt (Keep / Save-then-delete / Delete)
fires only when the shell process exits; Keep runs `on_detach`. `ListSessions`
reports lifecycle (Pending, Materializing, Active) and liveness attributes
only. `StopSession` does not exist: `DestroySession` deletes the record,
`AbortSession` acts only on a pending session, and the one
end-process-keep-record primitive is the internal stop daemon shutdown uses.
The mesh is started only by tests, as a UDP subnet router into the switch.
New here, therefore: the `Certified` state and every rule under it (MMI-020
to MMI-027), the owner field (MMI-023), the `StopSession` RPC (MMI-028), the
attachment state (MMI-055), scrollback, DEC 2026 framing and alternate-screen
and focus-reporting re-assertion (MMI-050, MMI-051), the named exit signals
(MMI-053), transport-loss detach (MMI-054), starting the mesh from
configuration (MMI-039), the WebSocket ingress and own-address termination
(MMI-001 to MMI-004), and the whole relay group.

**Own-address termination is a routing split; the mesh ingress is the
non-local ingress** (plan Stage 3, 2026-09-03). The existing peer routes
every decrypted packet to the switch sink; MMI-003 adds one destination,
the daemon's own tunnel address, whose streams enter the SSH server as
non-local. Local-versus-remote stays a property of the listener, never
inferred from transport type. The route lives on the existing TLS listener
because R4.4 already proxies WebSocket there, exempt from that listener's
client certificate because the WireGuard handshake is the authentication
(MMI-002). Per-peer destination policy (MMI-005) keeps a browser peer off
the switch subnet until UC2b decides. The mesh, started only under test
today, starts from the same configuration file as the trust anchors
(MMI-039).

**Outbound-only by default, a Minimal-run relay for the rest** (decisions 18,
23, 24, 2026-09-03). A page has no UDP and cannot hole-punch, so a daemon
behind NAT is reachable from a tab only through a forwarder the daemon dials
out to. That relay is the one hop that cannot be designed away for a page
with no UDP; it carries WireGuard ciphertext wrapping SSH ciphertext, holds
no key and no session state, and can read nothing (MMI-072, MMI-073). The
architecture recorded it as D7 on 2026-09-06 (Gatehouse v1.12, §6.9 relay
tickets, T29): box-provider-api v0.6 §1 and §10 now name "cannot read box
traffic" as the invariant that survives relaying, and the Cloudflare sketch
v0.6 keeps its cloudflared tunnel control-plane only. Nodes authenticate
with `sshpop-host` as §10.2 prescribes for outbound daemon connections, the
`aud` being a relay URL the issuer advertises in `gatehouse_node_endpoints`;
tabs present a per-node ticket bound to their DPoP key, issued only where
`ReadNode` admits the subject to the node, so the relay decides statelessly
from the issuer's published keys and the ticket authorizes routing only.

**The relay as the S12 record.** Each node registers with exactly one relay,
its home, named in its configuration until the peer document names it
(MMI-008); a client always dials the node's home relay (MCC-014, MCC-070),
which is what lets v1 stay single-hop with no inter-relay forwarding. Frames
on a node's registration are addressed by the client's mesh public key
(MMI-077), the one field the relay reads, so the relay pairs legs without
parsing WireGuard. The ticket's claim set (Gatehouse §6.9: `td, sub,
node_id, cnf.jkt, iat, exp, jti`) carries no mesh key, so the client
presents its §6.9 mesh binding beside the ticket and the relay takes the
key from the binding (MMI-071); the pairing is still decided at open and
the daemon sees the key as it would a UDP source address (MMI-008). Whether
the ticket should carry a `wg_pub` claim instead is asked of the
architecture below. The relay's close codes are a contract the client core
acts on (MCC-071, MCC-064), so they are named here: `expired` for a ticket
past `exp`, `offline` for a node with no live registration, `replaced` for
a leg or registration superseded by a newer one (MMI-070, MMI-077),
`over_cap` for a connection beyond MMI-074's caps, and `refused` for every
other verification failure. Scale is horizontal: add relays, reassign
homes through
the peer
document, and daemons follow at their next reconnect, MMI-008's backoff
bounding the gap. Direct paths are preferred at both ends (MMI-009, MCC-014),
so the relay carries only what cannot go direct. The relay's own identity is
a publicly trusted TLS certificate at its canonical URL; it holds the Host CA
and issuer public keys of the tenants it serves and no private key of
anyone's. Minimal operates it; a provider-run relay is the generality case
below. The daemon never sees a ticket, and its mirror peer document (the
daemon's view of `GET /v1/mesh/peers`, Gatehouse §6.9 v1.14) is the server
half of MCC-070's: admitted keys with their bindings, each peer's tunnel
address, and the node's own relay assignment — configuration, never
authorization, on the same `seq` and staleness discipline (MMI-010).

**`Certified` is an allowlist, and ownership is the ratified interim for
Cedar** (2026-09-04; Gatehouse §7.4 since v1.16). No request is gated by
authentication today (above); admitting a remote principal through the
session-channel gate alone would expose `Shutdown`, `CleanCache`,
`IssueClientCert`, `exec`, sftp, and the create pipeline. The owner ruling
of 2026-09-07 is that sessions are boxes, with no parallel action family:
attach is the cached `SshConnect`, show and each listed row `BoxRead`, stop
`StopBox`, rename the one new action `RenameBox` (baselines creator,
chain-ancestor, org-admin, deny by default until the daemon's RPC
evaluation point lands), and a node-level listing `ReadNode`; every other
RPC stays local-only in v1. Under A1, attach, reads, rename and stop are
admitted for the session's owner (MMI-027), which is those baselines'
creator arm, and refused to every other `Certified` subject; a decision
endpoint, once configured, evaluates the same requests through `SshConnect`
and the §7.4 mappings on one cache (MMI-026), and a `ListSessions` row or a
node-level `GetVersion` is decided over the node rather than a session.
The first draft admitted reads to every `Certified` subject; the owner-only
reading was chosen on 2026-09-09 because `BoxRead`'s shipped baselines are
ownership-shaped and teammate reads arrive with the S8 follow-up. With no
endpoint, MMI-025 admits only the configured owner subject,
the `local`-class linkage of Gatehouse §6.2 F16(a) written into config —
the interim §7.4 ratifies rather than replaces, its shipped baselines being
ownership-shaped. Ownership needs a field the record does not have
(MMI-023); because `CreateSession` stays Local-only, every v1 session is
created locally and owned by the node's subject, which is what owner-only
v1 means, and the provenance of that subject is an open question.
`StopSession` is a new RPC (MMI-028) carrying `StopBox`'s
stop-the-process-keep-the-record semantics: it reuses the internal stop
that daemon shutdown already applies to every session, without the exit
prompt, and keeps the record; the alternatives were mapping stop onto
`DestroySession`, which deletes, or `AbortSession`, which acts only on a
pending session. Destroy stays Local-only, as §7.4 keeps it, because
deletion is the one action a prompt-injected agent holding a stolen tab
could not undo.
The username convention is plan Stage 3 option (i) (MMI-024): the presented
name is the box login principal and must be among the certificate's
principals; whether it must also equal the record's sandbox user is open.
The attachment state (MMI-055) is new: today's listing carries lifecycle
only, and the browser's list (WMC-013) and the core's (MCC-072) consume
attached, detached, or exited and a last-activity time.

**Rejection delay** (2026-09-04): the POC inherited russh's 1 s default and
measured refusals at about 1.3 s. That delay slows password guessing; a
refused certificate gives an attacker nothing to iterate on, and only a peer
that completed a WireGuard handshake against an admitted key reaches the SSH
server at all. MMI-033 answers the first refusal at once, so a client whose
certificate expired at the reaper boundary reconnects without dead time, and
keeps the delay plus a three-attempt cap for repeated attempts on one
connection, which a legitimate client never makes.

**Reaper without grace, warnings only for long certificates** (decision 22;
Gatehouse §5.7 since v1.11). Gatehouse §5.7's cap at `valid_before` is exact
(MMI-031). Its T-15/T-1 warnings are meaningless under a 15-minute
certificate whose client renews at T-2 and reconnects transparently, so
they are written only for the interactive profile — the rule §5.7 now
states for the browser min client's certificate, naming MMI-031 as the
daemon side. Renewal is invisible to the daemon (cross-spec
decision 1): the core attaches on a new connection under the fresh
certificate and then closes its old channel; if the new attach or the reaper
reaches the old channel first, the client consumes `SUPERSEDED` or `EXPIRED`
(MMI-053). A second attach by the same principal supersedes the first like
any other, and the daemon does not distinguish renewal. A transport-initiated
loss, by contrast, ends the attachment (MMI-006, MMI-054), and the next
attach is a new one by the head.

**The host certificate names the node, never its tunnel address**
(Gatehouse §5.3 since v1.15, the arch#21 ruling). A mesh client dials the
daemon's tunnel address and verifies the host certificate against the
node's canonical `<node_id>.box.<td>` name, which the peer document names
in its expected-principal field; the first draft's tunnel-address principal
(MMI-029) is superseded and must not be emitted. The daemon therefore
requests nothing new at renewal, a change of tunnel address forces no
out-of-cycle renewal of the 30-day certificate, and no stability guarantee
is owed for tunnel addressing. The canonical name must be among the
certificate's own principals, since the per-node wildcard covers only the
names beneath it; OpenSSH clients get the check from stock `HostKeyAlias`,
the core natively (MCC-032).

**KRL** (Gatehouse §8.2, §12.1): no Rust crate reads PROTOCOL.krl, so the
reader implements the certificates section the tenant CA emits and refuses
anything else (MMI-034); a KRL that parses but revokes nothing is the worse
failure.

**Terminal state.** Today's re-attach already restores the visible rows, the
cursor, and the input modes from the screen model, and already supersedes an
earlier attacher with a notice (above). New are scrollback (depth zero
today, MMI-050); DEC 2026 framing so a phone renders the repaint once, and
re-entering the alternate screen and focus reporting, which today's repaint
replays the contents of but does not set (MMI-051); detached-not-exited
semantics when a transport dies, which today goes unnoticed (MMI-054); and a
machine-readable close reason (MMI-053), which turns supersession's exit
status 0 into a named exit signal so a client core can tell supersession
from tunnel loss and from the shell exiting. The signal names map onto the
core's close causes one to one (MCC-065): `SUPERSEDED` to `superseded`,
`EXPIRED` to `credential_expired`, `REVOKED` to `revoked`, `SHUTDOWN` to
`daemon_shutdown`, a shell exit to `exit` with its status, a transport loss
to `tunnel_lost`, and a close the head itself made to `closed`; MCC-065 is
authoritative for the client-side names. Supersession is last-attach-wins
regardless of transport or principal: a CLI and a browser are the same
developer, and a renewed certificate is a second client. Hooks: `on_attach`
runs on every attach today and keeps doing so; supersession keeps skipping
`on_detach`, its deadlock rationale standing; transport-loss detach runs
`on_detach` as the detach chord does (MMI-054), with the deadlock caveat an
open question. MMI-052's scrollback replay is a daemon capability no v1 head
requests (cross-spec decision 3): the repaint alone is what the browser and
the CLI consume.

**Heartbeats go to Gatehouse** (decision 21; `POST /v1/nodes/heartbeat`,
Gatehouse §8.2 since v1.13), because the node set the tab lists is
Gatehouse's (`nodes.last_seen`, `advertised_reachability`, `heartbeat_seq`,
§9) and the peer document consumes the advertised reachability. The
Cloudflare sketch v0.6 keeps a separate provider-plane ops heartbeat on its
Tunnel channel (usage counters, misconfiguration detection); this is the
identity-plane liveness heartbeat, and a provider's `READY` never implies
liveness here. The cadence is the architecture's 60 s working value with a
server-enforced 30 s floor (MMI-060), from which Gatehouse derives
`reachable` within 150 s, `stale` within 15 min and `offline` beyond; the
`seq` is monotonic on the §8.2 anti-rollback discipline (MMI-061) and is
stored beside the KRL high-water mark (MMI-035), one persisted pair. The
payload is metadata only, and the browser's 30 s liveness refresh (WMC-012)
re-reads the derived state, not the heartbeat.

**Tiers.** MMI-005, MMI-022, MMI-027 and MMI-072 were T1 from the first
draft; MMI-002, MMI-007, MMI-012, MMI-021, MMI-023, MMI-024, MMI-025,
MMI-031, MMI-035, MMI-037, MMI-038, MMI-061, MMI-076 and MMI-077 joined them
on 2026-09-09, when the review found the security invariants resting on
example tests. Each is a universal over a finite domain — a route table, an
option set, a method or principal vocabulary, the certificate and KRL
vectors at a fixed clock, a field allowlist, or every (leg, key) pairing the
relay holds — that the test walks exhaustively, so no property-testing crate
is added to `minimald` or `minrelay` (MCC confines one to `min-core`'s
development dependencies). The tier buys pure decision functions over owned
values, separate from the transport; MMI-022's decision is the one MCC-034
defines, exercised here through the daemon's authentication hook, and
MMI-031's reaper decision follows it at the same fixed clock. MMI-072's
universal ranges over unbounded sequences, so its test draws the sample its
property names rather than walking a domain. Everything else is T0 because
it reaches a socket, a daemon or a browser: MMI-006, MMI-020, MMI-026,
MMI-028, MMI-053, MMI-054 and MMI-073 are scenarios — a transport dying, a
connection arriving, a decision fetched, a process ended, a channel closed,
a restart — and the invariants that name them are held by the T1 decisions
beside them (MMI-027 for the allowlist, MMI-025 and MMI-038 for admission,
MMI-031 and MMI-037 for expiry and revocation, MMI-077 for addressing), so
one example each is what a scenario needs. Nothing is T2 or T3: there is no
proof project, and a Kani harness over certificate parsing is out of
proportion.

**Generality:** a second WireGuard implementation on the peer side (kernel
WireGuard, wireguard-go) fits MMI-001 to MMI-011 unchanged, though interop is
proven boringtun-to-boringtun only. An OpenSSH client inside the mesh fits
the authentication surface, whose rules are OpenSSH's own. A provider-run
relay fits MMI-070 to MMI-077, which need only the tenant Host CA and issuer
keys. In a guest only the config path differs (MMI-039). What does not
generalise is the owner rule (MMI-023, MMI-025): a multi-user node needs the
Cedar decisions Gatehouse §7.4 now names, which is why that phase is
interim.

## Security considerations

- **Invariant:** THE SYSTEM SHALL let no party other than the client and
  the daemon read SSH or WireGuard plaintext.
  enforced by: the relay forwarding frames unchanged, reading only the
  address prefix, and holding no key (Gatehouse T7, T29; architecture AT14,
  D7).
  covered by: MMI-072, MMI-073, MMI-076, MMI-077
- **Invariant:** THE SYSTEM SHALL open no channel on a non-local connection
  without an accepted certificate decision and an authorization decision
  for its subject.
  enforced by: `Certified` reached only through the decision function;
  `none` refused; no public-key path without configuration; the owner rule
  or the cached `SshConnect` decision before the channel opens.
  covered by: MMI-020, MMI-021, MMI-022, MMI-025, MMI-026, MMI-038
- **Invariant:** THE SYSTEM SHALL admit under `Certified` no capability
  outside its allowlist, and no mutation of a session by a subject other
  than its owner.
  enforced by: the per-auth-state allowlist with the ownership check
  against the recorded owner, the creator arm of the `StopBox` and
  `RenameBox` baselines (Gatehouse §7.4).
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
  mark (Gatehouse §5.7, §8.2, T14).
  covered by: MMI-031, MMI-035, MMI-037
- **Invariant:** THE SYSTEM SHALL keep a session's process running through
  any loss of the transport attached to it and any daemon-initiated close of
  its channel other than daemon shutdown, which ends every session's process
  and is the one close that carries `SHUTDOWN@minimal.dev` (MMI-053).
  enforced by: transport loss, supersession, expiry and revocation closes
  detaching, never destroying.
  covered by: MMI-006, MMI-031, MMI-037, MMI-053, MMI-054
- **Invariant:** THE SYSTEM SHALL expose no inbound mesh listener without
  explicit configuration, and no topology in any refusal.
  enforced by: the outbound-only default (Gatehouse §10.2) and R4.5 logging.
  covered by: MMI-002, MMI-007, MMI-012
- **Invariant:** THE SYSTEM SHALL write no session name, project path, or
  screen content into a heartbeat, a mesh-status answer, or a relay log.
  enforced by: the fixed metadata vocabulary of the heartbeat and of the
  relay's log lines.
  covered by: MMI-061, MMI-076

## Rollout

- **Deploy:** `minrelay` per region behind Minimal's DNS, with the Host CA
  and issuer keys of the tenants it serves in its configuration and its
  canonical URL published in the `relays` member of each tenant's
  `gatehouse_node_endpoints` (Gatehouse §8.2). The
  daemon side needs no rollout step: every ingress, authentication and relay
  behaviour here is off without configuration (MMI-N05). The terminal-state
  group (MMI-050 to MMI-055) is the exception, on for every transport: a
  local client sees the DEC 2026 repaint, the attachment state, and a named
  exit signal on supersession where today's `min` sees exit status 0.
- **Rollback:** redeploy the previous image; connections drop and daemons
  reconnect within the MMI-008 backoff; no state to migrate.
- **Blast radius:** browser sessions to NAT'd daemons in that region; direct
  paths and every local session are unaffected.

## Open questions

- [NEEDS CLARIFICATION (HIGH): 03-spec-networking Unit 4 has no own-address
  termination and no WireGuard-over-WebSocket ingress; R4.2's path ends at a
  box, and R4.3 and B6 still name wireguard-go. MMI-001 to MMI-004 extend
  Unit 4, whose text should say so; this is this repository's spec to
  amend, not the architecture's (arch#18 closed with the relay tier as D7
  and left Unit 4 untouched).]
- [NEEDS CLARIFICATION (MEDIUM): The relay ticket's claim set in Gatehouse
  §6.9 — `td, sub, node_id, cnf.jkt, iat, exp, jti` — carries no mesh public
  key, which the relay needs to address frames (MMI-077). MMI-071 takes the
  key from the §6.9 mesh binding the client presents beside the ticket,
  which changes nothing in the architecture but makes the relay verify two
  JWS at open. Should the ticket carry a `wg_pub` claim instead, so one
  document decides the pairing?]
- [NEEDS CLARIFICATION (MEDIUM): The interim owner rule. A session record
  has no owner today, and every v1 session is created over a local
  connection with no subject; MMI-023 assigns those to the node's enrolled
  subject, read from configuration until enrollment (Gatehouse §6.2 F16(a))
  exists. Whether that subject is written by `min auth login`, by
  enrollment, or by hand, and what a record created before the subject was
  configured is owned by, are undecided.]
- [NEEDS CLARIFICATION (MEDIUM): Under `Certified`, today's attach path
  passes the connection's username to the host launch as the sandbox user,
  while the record carries the creating user's name. MMI-024 admits the box
  login principal; whether it must equal the record's username, or the
  record's username wins on attach, is undecided.]
- [NEEDS CLARIFICATION (MEDIUM): How does an un-enrolled daemon learn its
  owner subject for MMI-025 before client-mediated enrollment (Gatehouse
  §6.2 F16(a)) exists: a config value the CLI writes, or enrollment only?]
- [NEEDS CLARIFICATION (MEDIUM): Should `GetMeshStatus` open under
  `Certified` for the owner? MMI-027 keeps it Local-only.]
- [NEEDS CLARIFICATION (MEDIUM): MMI-054 runs `on_detach` hooks on a
  transport-loss detach, as the detach chord does, while supersession skips
  them for a documented deadlock. Whether the same deadlock applies when the
  binding is torn down from a dead channel, and whether hooks should run
  there at all, is unverified.]
- [NEEDS CLARIFICATION (LOW): Gatehouse §8.2's heartbeat payload is
  `{seq, reachability: {direct_endpoint?, relay?, mesh_addresses[]}}`;
  MMI-061 sends a superset (daemon version, certificate serial and expiry,
  KRL `seq`, live session count) for `GetMeshStatus` parity. Whether the
  endpoint ignores or refuses unknown members is unverified.]
- [NEEDS CLARIFICATION (LOW): MMI-022 recognises the `source-address`
  critical option but no requirement enforces it against the peer's tunnel
  address, which OpenSSH would; should MMI-022 gain that edge?]
- [NEEDS CLARIFICATION (LOW): MMI-052's scrollback replay is kept as a
  daemon capability with an interim `env` carrier that no v1 head declares
  (cross-spec decision 3). Which head first consumes it, and whether the
  carrier moves into the client core's configuration document (MCC-061), is
  open.]
