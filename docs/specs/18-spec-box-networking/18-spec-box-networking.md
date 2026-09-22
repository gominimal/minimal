---
id: NET
title: Box networking on the local host: preview by name and bounded egress
owner: norrietaylor
epic: gominimal/inbox#646
arch: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
updated: 2026-09-18
---

# NET — Box networking on the local host: preview by name and bounded egress

## Context

A developer on a stock install reaches a box through one surface today, the
Host-header hostname proxy, and nothing else the networking design promises
exists: no box name in a browser without proxy configuration, no egress
enforcement, hidden network-mode and ingress flags, and no proof that a fresh
Linux install with KVM activates a VM-backed box. The architecture of record
defines what a box host must enforce in every deployment style and, for
un-enrolled local hosts, a degraded-mode profile that is buildable with no
identity plane ([design §7.1 and §7.4][design]). This document binds that
profile on the box host: the `min` CLI, the session daemon, the VM host daemon,
the installer, and the release manifests, on a laptop running VM-backed boxes
and on a Linux machine where the client and the box host share the machine. On
that host the default path carries no WireGuard: the pin, the Egress Gateway
contract, and the Box Egress Proxy are all machine-internal ([design §7.1 and
§11][design]).

The scope is local by decision (local-first ordering, 2026-09-15): the
un-enrolled local host is the deployment target first, and the architecture
does not change with it, only what is built first. The box host's obligations
that exist only once a host is enrolled, holds a gateway association, has
joined a mesh, or serves a remote session are bound in three sibling documents
written from the same epic:
[EHE](https://github.com/gominimal/minimal/pull/1418) for the enrolled host's
egress, [GWI](https://github.com/gominimal/minimal/pull/1419) for gateway
ingress, and [MRF](https://github.com/gominimal/minimal/pull/1420) for the mesh
and the remote forward. The identity plane's side of all of it is
[NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md).

After this ships, a developer previews a box's server at `<name>.min.internal`
in any browser on the machine, chooses a box's network posture on the command
line, declares what the box may reach and has that enforced outside the box
even after an escape into the VM, and forwards a box port to the laptop over
the session, all through one `min net` grammar. The constraint holds in both
directions: nothing reaches a box and nothing leaves it unless declared, and a
hostname-routing surface is never a policy side door.

The node-local Box Egress Proxy ([architecture D6][arch]; [Gatehouse
§6.10][gatehouse], v1.20.1), which on a local host runs beside the switch
outside the VM and, un-enrolled, redeems store references from the host's own
secret stores and GitHub grants the `min` client minted from its own GitHub
sign-in (no Gatehouse-brokered grants; Gatehouse §6.10's un-enrolled bullet,
ruled 2026-09-17), is the next thing built and is a separate document,
[BEP](https://github.com/gominimal/minimal/pull/1426), that cites this one. It
depends on five behaviours bound here: box-zone resolution (NET-072, NET-073)
and the resolver advisory that makes its default `dns` steering buildable
(NET-122), `egress.allow_dns_hosts` with DNS-pinned admission (NET-066,
NET-067), the hostname-proxy parity rule (NET-069 to NET-071), and the relay's
source-address check (NET-084), which on a VM-backed host is what lets the
proxy attribute a box by its switch source address: each own-address box holds
one lease there. On a co-resident host the host-address boxes share the host's
address and are attributed as one cohort outside the box host (NET-078), while
each box's own declaration is enforced inside it (NET-079) on the box's own
cgroup ([design §4.1][design]). HTTP/3 to a steered host is governed by the
`quic443` field ([design §5.3][design]), bound in that document; NET-064 covers
the box that declared TCP only.

**Success:** on a stock install, a browser opens
`http://<name>.min.internal:<port>` with no proxy configuration; an own-address
box declared deny-all reaches nothing; and a process that gains root inside the
VM and spoofs another box's address reaches nothing outside the union of
resident boxes' declared egress.

**First slice:** `<name>.min.internal` and `host.min.internal` routed through
the hostname proxy that already ships, own-address sessions on the VM host
included, with every refusal logged (NET-001 to NET-004).

## Users and stories

**Roles:** developer previewing a box on my own machine, developer running a dev server in a box on my own machine, developer running two boxes that both listen on port 3000, developer previewing a box by name, developer who just started a server inside a box, developer on a host where names resolve natively and box ports are published by identity, developer relying on box hostnames, developer running a native box host and a VM box host on the same machine, developer activating a session, developer on a fresh macOS or Linux install, developer who just started a server inside a box I am attached to, developer on a Linux workstation, developer on an arm64 Linux machine, developer who wants strong isolation between two projects, developer with two VMs, developer running an agent in a box, developer who wants to allow `github.com` and nothing else, developer who has restricted a box's ingress, platform engineer, developer on macOS or Linux running VM-backed boxes, developer with a service in a remote box, maintainer, platform engineer running box hosts for several teams

- AS A developer previewing a box on my own machine, I WANT boxes to answer at `<name>.min.internal` and the host at `host.min.internal` on an un-enrolled laptop, with the same names carrying over when the host enrols, SO THAT the names in my recipes stay valid from first install through enrolment.
- AS A developer running a dev server in a box on my own machine, I WANT `http://<name>.min.internal:<port>` to resolve in any browser without a proxy, PAC file, or `HTTP_PROXY`, SO THAT previewing my work is one URL, not a browser-profile recipe.
- AS A developer running two boxes that both listen on port 3000, I WANT each box to be published at its own `127.0.0.N` address at the box's own port, SO THAT `http://web.min.internal:3000` and `http://api.min.internal:3000` both work with no translation and no collision.
- AS A developer previewing a box by name, I WANT `<name>.min.internal` to answer the box's loopback address from `activate` until `destroy`, SO THAT the name works whether or not a client is attached right now.
- AS A developer who just started a server inside a box, I WANT its port published on the box's address the moment it listens, subject to the box's ingress rules, SO THAT I never type an `--ingress` mapping for a port I am allowed to expose.
- AS A developer on a host where names resolve natively and box ports are published by identity, I WANT the proxy to stop being the UC2a surface on that host, SO THAT there is one way to reach a box by name, not two.
- AS A developer relying on box hostnames, I WANT routing to come back by itself when the port it needs frees up, and to be told at `activate` and `ls` while it is down, SO THAT I never have to `min stop` and restart to get hostnames back.
- AS A developer running a native box host and a VM box host on the same machine, I WANT each daemon to keep a working hostname surface, SO THAT the second daemon to start does not silently lose routing.
- AS A developer activating a session, I WANT `--network none|host_ip|own_ip` and `--ingress` in `--help` and the CLI reference, SO THAT I can find them without reading the source.
- AS A developer on a fresh macOS or Linux install, I WANT `--network own_ip --ingress 8080:8080` to publish `127.0.0.1:8080` on the host, SO THAT I can isolate a box without a dev checkout.
- AS A developer who just started a server inside a box I am attached to, I WANT `min net expose <port>` from inside the box to publish it on the host loopback, subject to policy, SO THAT I stay in flow instead of re-activating with a new `--ingress`.
- AS A developer on a Linux workstation, I WANT the stock install to include the VM stack so I can run boxes in a microVM like macOS users do, SO THAT the strongest isolation tier is not a macOS-only feature.
- AS A developer on an arm64 Linux machine, I WANT the same VM stack the amd64 install gets, SO THAT architecture does not decide my isolation tier.
- AS A developer who wants strong isolation between two projects, I WANT to create a second named VM box host with its own state, socket, and daemon, SO THAT one project's boxes cannot see the other's network or files.
- AS A developer with two VMs, I WANT `min ls`, attach, and `min net` commands to address boxes across VMs without a global flag, SO THAT one grammar covers both.
- AS A developer running an agent in a box, I WANT to declare an egress allowlist of subnets and protocols for the box and have it enforced, SO THAT a prompt-injected agent cannot exfiltrate to undeclared destinations.
- AS A developer who wants to allow `github.com` and nothing else, I WANT hostname allow rules enforced as the addresses the name actually resolved to, SO THAT an attacker cannot use DNS rebinding to turn an allowed name into an arbitrary destination.
- AS A developer who has restricted a box's ingress, I WANT the `:7654` proxy to honour the target box's ingress rules and the caller's egress rules, SO THAT a peer session cannot reach my box's undeclared ports by going through the proxy.
- AS A platform engineer, I WANT `own_ip` boxes to deny all egress and ingress unless declared, SO THAT isolation is the safe default and every allowed destination is in the reviewed spec.
- AS A platform engineer, I WANT `host_ip` boxes with a deny-all egress declaration to reach nothing, while the host's own maintenance traffic still flows, SO THAT sharing the host's network namespace does not mean inheriting the host's reach.
- AS A developer on macOS or Linux running VM-backed boxes, I WANT per-box egress rules applied by the switch and filter on my laptop's host OS, outside the VM, SO THAT a workload that breaks out of its box into the VM still reaches only what the resident boxes declared.
- AS A developer with a service in a remote box, I WANT `min net forward <box> <local>:<port>` to open a local listener that tunnels to the box over my existing SSH session, SO THAT I can hit a remote service on `localhost` with nothing else installed or configured.
- AS A maintainer, I WANT every VM lane to assert that a session can reach the network and that a box's egress policy is enforced, SO THAT a lane that silently loses its switch or filter can no longer report green.
- AS A platform engineer running box hosts for several teams, I WANT box and host addresses allocated per tenant from a plan that cannot collide with my RFC 1918 networks and can be renumbered without breaking identity or audit, SO THAT two teams' hosts never collide and a renumbering never invalidates a certificate or an audit trail.
- AS A maintainer, I WANT the retired per-daemon mTLS/OIDC reverse proxy and its CLI removed from the tree, with the `direct-tcpip` handler kept, SO THAT a surface the architecture has ruled out does not persist unowned behind a feature gate.

## Requirements

- **NET-001** WHEN a request arrives at the hostname proxy for the `<name>.min.internal` name of an active box THE SYSTEM SHALL route it to that box, own-address sessions on the VM host included.
  tier:     T0
  verify:   cargo nextest run -p minimald proxy_routes_min_internal_for_own_ip_session_on_vm_host
  <!-- S1a/AC1; prose 1; event-driven -->
  - IF the hostname proxy refuses a request THEN THE SYSTEM SHALL log the refusal with its reason.
    tier:   T0
    verify: cargo nextest run -p minimald proxy_refusal_is_logged_with_reason
    <!-- S1a/AC1; prose 1; unwanted -->

- **NET-002** WHEN a request arrives for `<name>.<host-id>.min.internal`, the shipped zone whose default host id is `local` THE SYSTEM SHALL route it as `<name>.min.internal` and emit a deprecation notice.
  tier:     T0
  verify:   cargo nextest run -p minimald legacy_local_zone_routes_with_deprecation
  <!-- S1a/AC1; prose 2; event-driven; "for one release" is a plan fact -->

- **NET-003** THE SYSTEM SHALL resolve `host.min.internal` from host-address, own-address, and VM-backed boxes to the address that reaches the host's loopback: `127.0.0.1` on the host, the switch's host-gateway address inside boxes.
  tier:     T0
  verify:   cargo nextest run -p minimald host_min_internal_resolves_to_host_reach_address_per_mode
  <!-- S1a/AC2; prose 3; ubiquitous; "inside boxes" per design §7.1 without qualification: an own-address box on a native host sits on the switch too; a host-address box on a native host shares the host's namespace and its answer; resolution only: reach over the name is local reach under the box's egress rules (NET-079; design §7.1 local names), so a deny-all box resolves it and reaches nothing -->
  - WHERE the host is VM-backed, WHILE a box is a host-address box THE SYSTEM SHALL resolve its lookups through the node's DNS layer and never through the host's own resolver.
    tier:   T0
    verify: cargo nextest run -p minimald host_ip_box_resolves_through_node_dns_layer
    <!-- design §5.3; state-driven; the node's DNS layer forwards the box's allowed names under its rules (NET-066), so the resolver Minimal owns is also the one that enforces names -->

- **NET-004** WHEN a box connects to the literal `100.64.255.254` THE SYSTEM SHALL route the connection as `host.min.internal` and emit a deprecation notice.
  tier:     T0
  verify:   cargo nextest run -p minimald legacy_host_literal_routes_with_deprecation
  <!-- S1a/AC2; prose 3; event-driven; "for one release" is a plan fact -->

- **NET-006** THE SYSTEM SHALL answer `*.min.internal` names only to lookups that originate on the machine.
  tier:     T0
  verify:   cargo nextest run -p minimald min_internal_zone_not_served_off_host
  <!-- S1a/AC3; prose 4; ubiquitous; "local-only" sharpened to "not served to other hosts" -->

- **NET-007** THE SYSTEM SHALL issue no certificate and write no audit record that names a `*.min.internal` name.
  tier:     T0
  verify:   cargo nextest run -p minimald min_internal_absent_from_certs_and_audit
  <!-- S1a/AC3; prose 4; ubiquitous -->

- **NET-009** WHERE the host's native resolver is configured for the box zone THE SYSTEM SHALL resolve `<name>.min.internal` for any process on the host with no proxy, PAC file, or proxy environment variable.
  tier:     T0
  verify:   ./scripts/session-e2e.sh native_resolution_without_proxy_env
  <!-- S1b-1; prose 5; optional-feature; "any browser" sharpened to "any process resolving through the host resolver" -->

- **NET-010** WHERE the reserved local range is present on the host, WHEN an own-address or `none` box is published THE SYSTEM SHALL assign it a host loopback address of its own from the host-global allocation and publish its ports at the box's own port numbers.
  tier:     T2
  verify:   cargo nextest run -p minimald each_box_gets_own_loopback_address
  property: for every host with the reserved local range present and every sequence of publish and withdraw operations from every daemon on it, up to 8 live boxes, no two live own-address or `none` boxes hold the same loopback address
  harness:  kani_loopback_alloc_injective, exhaustive to 8 live boxes across daemons; requires the allocator to be a pure function over one host-wide owned set of leased addresses, separate from the publish call and from any daemon's own state
  <!-- S1b-2a; prose 6; event-driven; the no-collision clause is the universal for spec-tiers; "host-global" per design §7.1: allocation is arbitrated through the answerer's authenticated channel and no daemon self-assigns; host-address boxes mirror their node's address (NET-129); a host without the range publishes at `127.0.0.1` under NET-123's interim, outside this requirement -->

- **NET-011** WHEN a session is finalised THE SYSTEM SHALL register `<name>.min.internal` for the box's loopback address.
  tier:     T0
  verify:   cargo nextest run -p minimald name_registered_at_finalize
  <!-- S1b-2b/AC1; prose 7; event-driven -->

- **NET-012** WHEN a box is destroyed THE SYSTEM SHALL answer every later lookup of its name with NXDOMAIN.
  tier:     T0
  verify:   cargo nextest run -p minimald destroyed_box_name_is_nxdomain
  <!-- S1b-2b/AC1+AC3; prose 7, 9; event-driven -->

- **NET-013** WHILE a box exists THE SYSTEM SHALL answer its name whether or not a client is attached.
  tier:     T0
  verify:   cargo nextest run -p minimald name_answers_without_attached_client
  <!-- S1b-2b/AC1; prose 7; state-driven -->

- **NET-014** IF a connection targets a port a box has not published THEN THE SYSTEM SHALL refuse it with a connection-refused error rather than a timeout.
  tier:     T0
  verify:   cargo nextest run -p minimald unpublished_port_connection_refused
  <!-- S1b-2b/AC2; prose 8; unwanted; "in 0 ms" sharpened to "refused, not timed out" -->

- **NET-015** WHILE a box exists THE SYSTEM SHALL keep it running whether or not a client is attached.
  tier:     T0
  verify:   cargo nextest run -p minimald box_survives_without_client
  <!-- S1b-2c; prose 10; state-driven; interview decision -->
  - IF the attached client of a PTY box is lost abruptly THEN THE SYSTEM SHALL keep the box's entrypoint running and accept a later attach.
    tier:   T0
    verify: cargo nextest run -p minimald abrupt_client_loss_keeps_task
    <!-- S1b-2c; prose 10; unwanted; client loss splits on the PTY, not on the verb: a lost PTY attach is a detach; in this tree the entrypoint is the session's shell -->
  - IF the client of a non-PTY exec (`min session exec`, and the `min task run` or `min session run` command it carries) is lost abruptly THEN THE SYSTEM SHALL end the command that exec spawned and keep the box running; a box created for that run then ends under NET-131.
    tier:   T0
    verify: cargo nextest run -p minimald lost_exec_client_kills_only_its_own_process
    <!-- S1b-2c; unwanted; a pty-req on the exec channel is refused at the channel, so no exec in this tree runs with a PTY and the rule as scoped is the shipped behaviour; the PTY exec the architecture defines is a re-attachable attach and falls under the sub-requirement above -->
  - THE SYSTEM SHALL stop a box only when its client issues stop, destroy, or delete, when its entrypoint exits (subject to the exit prompt), or, for a box created for a run, when the run's command exits (NET-131), or when the box host tears it down by force: daemon shutdown, an abandoned launch, or the host reclaiming the VM.
    tier:   T0
    verify: cargo nextest run -p minimald box_has_no_idle_stop
    <!-- S1b-2c; ubiquitous within the WHILE; the idle and stop policy is the client's (Design reasoning); a declared execution timeout is the client's policy, set at creation, and is not built here; "end" is this tree's destroy, and the architecture retains a completed box's record until reaped so a wait can read the exit code after the client is gone -->

- **NET-131** WHILE a box was created for a non-detached run, WHEN the run's command exits THE SYSTEM SHALL end the box, whether or not the client that started the run is still present.
  tier:     T0
  verify:   cargo nextest run -p minimald run_box_ends_when_its_run_ends
  <!-- S1b-2c; event-driven within the WHILE; `min task run` creates a session for the run, execs the task into it, and today destroys it from the client; the destroy moves to the daemon side of the exec's exit so a lost client strands no session; the abandoned-launch reap covers only un-finalized sessions and does not reach this case -->

- **NET-016** WHILE a box is running, WHEN a process in it starts listening on a port its ingress rules permit and no declaration names THE SYSTEM SHALL publish that port on the box's address.
  tier:     T0
  verify:   cargo nextest run -p minimald listen_publishes_permitted_port
  <!-- S1b-2c/AC1-2; prose 11; state+event; declared ports are bound at publish (NET-121) -->
  - IF a process in a box listens on a port its ingress rules do not permit THEN THE SYSTEM SHALL leave the port unpublished.
    tier:   T2
    verify: cargo nextest run -p minimald listen_on_undeclared_port_not_published
    property: for every box and every port its ingress rules do not permit, a listener on that port is never published
    harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
    <!-- S1b-2c/AC2; prose 11; unwanted -->

- **NET-017** WHEN a published listener closes THE SYSTEM SHALL withdraw its publication.
  tier:     T0
  verify:   cargo nextest run -p minimald listener_close_withdraws_publication
  <!-- S1b-2c/AC3; prose 11; event-driven -->

- **NET-018** WHERE host-OS resolution and published addresses are both deployed on the host THE SYSTEM SHALL report native DNS as the live name surface in `min session activate` and `min ls`.
  tier:     T0
  verify:   cargo nextest run -p minimal activate_and_ls_report_native_surface
  <!-- S1b-3; prose 12; optional-feature; WHERE per design §7.1 v0.5 supersession condition -->

- **NET-019** WHERE host-OS resolution and published addresses are both deployed on the host THE SYSTEM SHALL keep the hostname proxy serving.
  tier:     T0
  verify:   cargo nextest run -p minimald proxy_keeps_serving_after_supersession
  <!-- S1b-3; prose 12; optional-feature; interview decision; WHERE per design §7.1 v0.5 -->

- **NET-020** IF the host-side hostname listener cannot bind or publish THEN THE SYSTEM SHALL print the reason and the remedy in `min session activate` and `min ls`.
  tier:     T0
  verify:   cargo nextest run -p minimal listener_failure_reported_with_remedy
  <!-- S2a/AC1; prose 13; unwanted -->

- **NET-021** IF the host-side hostname listener cannot bind or publish THEN THE SYSTEM SHALL retry with backoff until it succeeds.
  tier:     T0
  verify:   cargo nextest run -p minimald listener_retries_with_backoff
  <!-- S2a/AC1; prose 13; unwanted -->

- **NET-022** WHEN the hostname listener recovers THE SYSTEM SHALL clear the warning from `min ls` without a daemon restart.
  tier:     T0
  verify:   cargo nextest run -p minimal ls_warning_clears_on_recovery
  <!-- S2a/AC2; prose 14; event-driven -->

- **NET-023** IF the switch datapath inside a running VM is lost THEN THE SYSTEM SHALL emit a daemon warning within one minute.
  tier:     T0
  verify:   cargo nextest run -p minvmd lost_datapath_warns_within_one_minute
  <!-- S2a/AC3; prose 15; unwanted -->

- **NET-024** WHEN a daemon starts with a configured hostname-proxy port THE SYSTEM SHALL listen on that port.
  tier:     T0
  verify:   cargo nextest run -p minimald proxy_listens_on_configured_port
  <!-- S2b/AC1; prose 16; event-driven -->

- **NET-025** WHEN a daemon starts with no hostname-proxy port configured THE SYSTEM SHALL select a free port.
  tier:     T0
  verify:   cargo nextest run -p minimald proxy_auto_selects_free_port
  <!-- S2b/AC1; prose 16; event-driven -->

- **NET-026** WHEN `min` connects to a daemon THE SYSTEM SHALL discover the hostname-proxy port in use and print it.
  tier:     T0
  verify:   cargo nextest run -p minimal min_prints_discovered_proxy_port
  <!-- S2b/AC1; prose 16; event-driven -->

- **NET-027** WHILE two daemons run on one machine THE SYSTEM SHALL route both daemons' box hostnames at the same time.
  tier:     T0
  verify:   cargo nextest run -p minimald two_daemons_route_hostnames_concurrently
  <!-- S2b/AC2; prose 17; state-driven; both daemons' addresses come from the host-global allocation NET-010 binds -->

- **NET-035** THE SYSTEM SHALL show `--network none|host_ip|own_ip` and `--ingress` in `min session activate --help`.
  tier:     T0
  verify:   cargo nextest run -p minimal activate_help_shows_network_flags
  <!-- S4a/AC1; prose 23; ubiquitous -->

- **NET-036** THE SYSTEM SHALL document `--network` and `--ingress` in the CLI reference.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reference_documents_network_flags
  <!-- S4a/AC1; prose 23; ubiquitous -->

- **NET-037** WHEN `--network no-net`, `--network host-net`, or `--network own-ip` is given THE SYSTEM SHALL accept it as a legacy spelling and print a hint naming the new spelling.
  tier:     T0
  verify:   cargo nextest run -p minimal legacy_network_spellings_parse_with_hint
  <!-- S4a/AC2; prose 24; event-driven; "for one release" is a plan fact -->

- **NET-038** WHILE a box runs with `--network none` THE SYSTEM SHALL refuse every socket the box opens to a destination outside itself.
  tier:     T0
  verify:   cargo nextest run -p minimald network_none_blocks_all_outside_sockets
  <!-- S4a/AC3; prose 25; state-driven -->

- **NET-039** WHILE a box runs with `--network none` THE SYSTEM SHALL accept attach.
  tier:     T0
  verify:   cargo nextest run -p minimald network_none_attach_works
  <!-- S4a/AC3; prose 25; state-driven -->

- **NET-040** WHEN `min session activate --network own_ip --ingress 8080:8080` is run on a fresh install THE SYSTEM SHALL publish `127.0.0.1:8080` on the host so that a request to it returns the in-box server's response.
  tier:     T0
  verify:   ./scripts/session-e2e.sh fresh_install_own_ip_ingress_publishes_loopback
  <!-- S4b/AC1-2; prose 26; event-driven; Linux and macOS both -->

- **NET-041** WHEN the installer completes THE SYSTEM SHALL verify that the switch binary is present and executable.
  tier:     T0
  verify:   just test-installer installer_switch_binary_executable
  <!-- S4b/AC3; prose 27; event-driven -->

- **NET-043** WHERE the host is un-enrolled, WHEN `min net expose <port>` is run inside a box THE SYSTEM SHALL send the same request shape to the local daemon and evaluate it against the box's `dynamic_ingress` setting.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_unenrolled_local_rpc_evaluates_dynamic_ingress
  <!-- S5/AC1; prose 28; feature+event; `dynamic_ingress` is design §7.1's name and supersedes 03-spec R2.3's `dynamic_allowed_ports`, which no crate implements (Design reasoning, field names) -->

- **NET-044** WHEN a dynamic ingress request is decided `allow` THE SYSTEM SHALL publish the port and show the mapping in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_allow_publishes_and_lists
  <!-- S5/AC2; prose 29; event-driven -->
  - IF a dynamic ingress request is decided `deny` THEN THE SYSTEM SHALL refuse it with a typed error.
    tier:   T0
    verify: cargo nextest run -p minimald expose_deny_typed_error
    <!-- S5/AC2; prose 29; unwanted -->

- **NET-045** WHEN a dynamic ingress request is decided `ask` THE SYSTEM SHALL prompt the attached human and apply their answer.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_ask_prompts_attached_human
  <!-- S5/AC2; prose 29; event-driven -->
  - IF a dynamic ingress request is decided `ask` while no client is attached THEN THE SYSTEM SHALL refuse it with a typed error saying no one is attached to answer.
    tier:   T0
    verify: cargo nextest run -p minimald expose_ask_without_client_refused
    <!-- S5/AC2; prose 29; unwanted; a box outlives its client (NET-015), so `ask` can arrive with nobody to prompt; fail closed, NET-046 records it -->

- **NET-046** WHERE the host is un-enrolled THE SYSTEM SHALL record each dynamic ingress decision in the local audit log.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_unenrolled_decision_audited
  <!-- S5/AC3; prose 30; optional-feature -->

- **NET-047** IF a dynamic ingress request is out of range or not permitted THEN THE SYSTEM SHALL leave no partial mapping.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_rejected_leaves_no_partial_mapping
  <!-- S5/AC4; prose 31; unwanted -->

- **NET-048** THE SYSTEM SHALL ship the VM host daemon and the guest payload in the Linux amd64 install.
  tier:     T0
  verify:   just test-installer linux_amd64_manifest_ships_vm_stack
  <!-- S6a/AC1; prose 32; ubiquitous -->

- **NET-049** WHEN `min session activate --provider local-minvmd` is run on a fresh Linux install with KVM THE SYSTEM SHALL activate the session.
  tier:     T0
  verify:   ./scripts/session-e2e.sh fresh_linux_kvm_activate_local_minvmd
  <!-- S6a/AC2; prose 32; event-driven -->

- **NET-050** THE SYSTEM SHALL ship the VM host daemon and the guest payload in the Linux arm64 install.
  tier:     T0
  verify:   just test-installer linux_arm64_manifest_ships_vm_stack
  <!-- S6b; prose 34; ubiquitous -->

- **NET-051** WHEN `min session activate --provider local-minvmd` is run on a fresh arm64 Linux install with KVM THE SYSTEM SHALL activate the session.
  tier:     T0
  verify:   ./scripts/session-e2e.sh fresh_arm64_kvm_activate_local_minvmd
  <!-- S6b; prose 34; event-driven -->

- **NET-052** WHEN `min` is asked to create a named VM THE SYSTEM SHALL give it its own state directory, socket, and box-host daemon.
  tier:     T0
  verify:   cargo nextest run -p minvmd named_vm_has_own_state_socket_daemon
  <!-- S7a/AC1; prose 35; event-driven -->

- **NET-053** THE SYSTEM SHALL keep every path of the `default` VM unchanged.
  tier:     T0
  verify:   cargo nextest run -p minvmd default_vm_paths_unchanged
  <!-- S7a/AC2; prose 35; ubiquitous -->

- **NET-054** THE SYSTEM SHALL place a named VM's state under a per-name subdirectory of the provider directory.
  tier:     T0
  verify:   cargo nextest run -p minvmd named_vm_under_per_name_subdirectory
  <!-- S7a/AC2-3; prose 35; ubiquitous -->

- **NET-055** WHEN one VM is stopped THE SYSTEM SHALL leave every other VM running.
  tier:     T0
  verify:   cargo nextest run -p minvmd stop_one_vm_leaves_other_running
  <!-- S7a/AC4; prose 36; event-driven -->

- **NET-056** THE SYSTEM SHALL scope process reaping to the checkout's own VMs.
  tier:     T0
  verify:   cargo nextest run -p minvmd reap_scoped_per_checkout
  <!-- S7a/AC4; prose 36; ubiquitous -->

- **NET-057** WHILE two VMs run THE SYSTEM SHALL show the VM per box in `min ls`.
  tier:     T0
  verify:   cargo nextest run -p minimal ls_shows_vm_per_box
  <!-- S7b/AC1; prose 37; state-driven -->

- **NET-058** WHILE two VMs run, WHEN attach or `min net expose` names a box THE SYSTEM SHALL resolve the VM from the box name without a global flag.
  tier:     T0
  verify:   cargo nextest run -p minimal box_name_resolves_vm_without_flag
  <!-- S7b/AC1; prose 37; state+event -->

- **NET-059** WHILE two VMs run THE SYSTEM SHALL route hostnames from both through the host's hostname surface at the same time.
  tier:     T0
  verify:   cargo nextest run -p minimald two_vms_hostnames_route_concurrently
  <!-- S7b/AC2; prose 38; state-driven -->

- **NET-060** THE SYSTEM SHALL accept `egress.allow_subnets`, `egress.allow_protocols`, `egress.allow_dns_hosts`, and `egress.deny_subnets` in the box spec.
  tier:     T0
  verify:   cargo nextest run -p sessions spec_accepts_egress_fields
  <!-- S8a/AC1 + S8b/AC1; prose 39; ubiquitous; NET-066 and NET-067 require `allow_dns_hosts` and the local Box Egress Proxy validates its grants against it; `deny_subnets` is the box's half of NET-067's denied range (design §5.3) -->

- **NET-061** THE SYSTEM SHALL show a box's effective egress rules in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimal policy_shows_effective_egress
  <!-- S8a/AC1; prose 39; ubiquitous -->

- **NET-062** WHILE a box runs with an own address, IF it opens a connection to a destination its egress rules do not allow THEN THE SYSTEM SHALL drop the connection without resetting it.
  tier:     T2
  verify:   cargo nextest run -p minimald disallowed_egress_dropped_not_reset
  property: for every own-address box and every destination its rules do not allow, the connection is dropped and never reset
  harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
  <!-- S8a/AC2; prose 40; state+unwanted -->
  - IF a box's connection is dropped by its egress rules THEN THE SYSTEM SHALL log a rate-limited structured warning.
    tier:   T0
    verify: cargo nextest run -p minimald egress_drop_logged_rate_limited
    <!-- S8a/AC2; prose 40; unwanted -->

- **NET-063** WHILE a box runs with an own address, WHEN it opens a connection its egress rules allow THE SYSTEM SHALL complete it.
  tier:     T0
  verify:   cargo nextest run -p minimald allowed_egress_succeeds
  <!-- S8a/AC2; prose 40; state+event -->

- **NET-064** WHILE a box's egress allows only TCP, IF the box sends UDP THEN THE SYSTEM SHALL drop it.
  tier:     T2
  verify:   cargo nextest run -p minimald udp_dropped_when_only_tcp_allowed
  property: for every rule set allowing only TCP and every UDP datagram, the datagram is dropped
  harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
  <!-- S8a/AC2; prose 40; state+unwanted -->

- **NET-065** IF a box spec declares `egress` on a `none` box THEN THE SYSTEM SHALL reject it as a validation error.
  tier:     T0
  verify:   cargo nextest run -p sessions egress_on_none_box_is_validation_error
  <!-- S8a/AC3; prose 41; unwanted; `none` only: a host-address box's `egress` is accepted (NET-120) -->

- **NET-066** WHEN a box resolves a name matched by its `egress.allow_dns_hosts` THE SYSTEM SHALL admit the answer's addresses for that box for the admission window the architecture defines.
  tier:     T0
  verify:   cargo nextest run -p minimald dns_pinned_admission_window
  <!-- S8b/AC1; prose 42; event-driven -->

- **NET-067** IF an allowed name resolves into the box's `egress.deny_subnets` or the infrastructure deny set THEN THE SYSTEM SHALL refuse the connection.
  tier:     T2
  verify:   cargo nextest run -p minimald denied_range_resolution_refused
  property: for every resolved answer set and every allow, deny, and infrastructure-deny CIDR set, the admitted set contains no denied address
  harness:  kani_rebinding_intersection_admits_no_denied_address, exhaustive to an unwind bound of 4 over IPv4 answers with at most 4 CIDRs per set; requires the intersection to be a pure function over owned addresses and CIDRs, separate from resolver I/O
  <!-- S8b/AC2; prose 43; unwanted; the infrastructure deny set is design §5.3's: link-local and metadata ranges, loopback space, the `100.64.0.0/10` plane, the gateway's own addresses (un-enrolled, the helper's and the answerer's), and RFC 1918 unless `egress.allow_subnets` covers the answer -->
  - IF an allowed name resolves into a denied range THEN THE SYSTEM SHALL log the name and the answer.
    tier:   T0
    verify: cargo nextest run -p minimald denied_range_resolution_logged
    <!-- S8b/AC2; prose 43; unwanted -->

- **NET-068** WHILE a box's egress is a hostname-only allowlist naming every host that `apt`, `git clone`, `npm install`, `pip`, and a container pull contact THE SYSTEM SHALL complete those operations.
  tier:     T0
  verify:   cargo nextest run -p minvmd hostname_allowlist_toolchain_completes
  <!-- S8b/AC3; prose 44; state-driven -->

- **NET-069** IF a request through the hostname proxy targets a port the target box did not declare THEN THE SYSTEM SHALL refuse it with the same refusal as a direct connection.
  tier:     T2
  verify:   cargo nextest run -p minimald proxy_undeclared_port_refused_like_direct
  property: for every target box, every undeclared port, and every proxied request to it, the refusal equals the direct-connection refusal
  harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
  <!-- S8c/AC1; prose 45; unwanted -->

- **NET-070** IF a request through the hostname proxy comes from a caller whose egress rules deny the target THEN THE SYSTEM SHALL refuse it.
  tier:     T2
  verify:   cargo nextest run -p minimald proxy_caller_egress_denied
  property: for every caller whose egress rules deny the target, every proxied request is refused
  harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
  <!-- S8c/AC1; prose 45; unwanted -->

- **NET-071** THE SYSTEM SHALL apply the hostname proxy's ingress and egress refusals to host-address and own-address targets alike.
  tier:     T1
  verify:   cargo nextest run -p minimald proxy_parity_across_network_modes
  property: for every network mode, every rule set, and every request, the hostname proxy's verdict equals the direct connection's verdict
  <!-- S8c/AC2; prose 45; ubiquitous -->

- **NET-072** THE SYSTEM SHALL resolve box-zone names with no `egress.allow_dns_hosts` entry.
  tier:     T0
  verify:   cargo nextest run -p minimald box_zone_resolution_needs_no_allow_entry
  <!-- S8c/AC3; prose 46; ubiquitous; one spelling for the field throughout; the architecture's canonical Box Spec spelling is `egress_allow_dns` (box.toml), reconciled by the box-spec schema work (Design reasoning) -->

- **NET-073** WHEN a box connects to a box-zone name THE SYSTEM SHALL enforce the target's ingress rules and the source's egress rules at connection time.
  tier:     T0
  verify:   cargo nextest run -p minimald box_zone_connection_enforced_at_connect
  <!-- S8c/AC3; prose 46; event-driven -->

- **NET-074** WHERE the deny-all default is in force and the opt-out flag is not set, WHEN an own-address box is created with no `egress` section THE SYSTEM SHALL give it no reach to any external address.
  tier:     T0
  verify:   cargo nextest run -p minimald own_ip_default_deny_all
  <!-- S9a/AC1; prose 47; feature+event; supersedes the shipped 03-spec R2.1 default of allow-all for absent `egress` fields; NET-076 binds the announcement window and NET-077 the opt-out -->

- **NET-075** WHERE the deny-all default is in force and the opt-out flag is not set, WHILE an own-address box has no `egress` section THE SYSTEM SHALL show `deny-all` in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimal policy_shows_deny_all_default
  <!-- S9a/AC1; prose 47; feature+state -->

- **NET-076** WHILE the deny-all default is announced but not yet in force THE SYSTEM SHALL print the coming change at activate.
  tier:     T0
  verify:   cargo nextest run -p minimal deny_all_announcement_printed
  <!-- S9a/AC2; prose 48; state-driven; interview decision -->

- **NET-077** WHERE the deny-all opt-out flag is set THE SYSTEM SHALL keep the shipped allow-all default for a box with no `egress` section.
  tier:     T0
  verify:   cargo nextest run -p minimald deny_all_opt_out_keeps_prior_default
  <!-- S9a/AC2; prose 48; optional-feature; the shipped default is 03-spec R2.1's -->

- **NET-078** THE SYSTEM SHALL classify node-plane traffic and the host-address cohort separately with distinct source identities.
  tier:     T0
  verify:   cargo nextest run -p minimald node_plane_and_cohort_distinct_sources
  <!-- S9b/AC1; prose 49; ubiquitous -->

- **NET-079** WHILE a host-address box is declared deny-all THE SYSTEM SHALL refuse every outbound connection it opens, deciding inside the box host on the box's own declaration.
  tier:     T0
  verify:   cargo nextest run -p minimald host_ip_deny_all_no_outbound
  <!-- S9b/AC2; prose 50; state-driven; the per-box decision for host-address boxes is the box host's classifier (design §4.1, UC3), matching the box's own cgroup before any source translation; outside the box host the cohort is one identity (NET-078) and the resident union is the floor; the last sub-requirement below states the one host where no per-box decision exists and what the box does there -->
  - WHILE a host-address box is declared deny-all THE SYSTEM SHALL admit the box's connections to the resolver Minimal owns for it, at that resolver's address and port, and to no other loopback destination.
    tier:   T0
    verify: cargo nextest run -p minimald host_ip_deny_all_reaches_only_the_answerer
    <!-- design §4.1; state-driven; the one carve-out from a deny-all verdict, by address and port, never loopback-wide: a loopback baseline exception for every box is rejected in the design reasoning; with the resolver rule below (and NET-003's inside a VM-backed host) a deny-all box resolves exactly the names that resolver holds and reaches nothing else -->
  - WHERE the host is not VM-backed, WHILE a host-address box is declared deny-all THE SYSTEM SHALL resolve its lookups through the box zone's answerer and never through the host's own resolver.
    tier:   T0
    verify: cargo nextest run -p minimald host_ip_box_resolves_through_answerer
    <!-- design §4.1 (the deny-all carve-out) and §7.1; state-driven; sits here rather than under NET-003 because it is the deny-all carve-out's other half and lands with the classifier, not with host name resolution; on a native host the stub a host-address box would otherwise reach is the host's resolver, which forwards any name upstream, so a deny-all box would resolve arbitrary names through the carve-out; the answerer forwards nothing and holds only the zone, which is the whole answer for a deny-all box; a native host-address box that is not deny-all (NET-074 scopes the deny-all default to own-address boxes) is bound by nothing here and belongs to the open question on native forwarding, whose interim is the host's resolver -->
  - WHILE a box is a host-address box, whatever its declaration, THE SYSTEM SHALL keep every process of that box inside the cgroup its verdict is decided on, so that no process in the box can move itself or a child out of it.
    tier:   T0
    verify: cargo nextest run -p minimald host_ip_box_cannot_leave_its_cgroup
    <!-- design §4.1; state-driven, and not inherited from the deny-all WHILE above: the classifier decides every host-address box's verdict on its cgroup, so an allow-list box that could leave its leaf would take a sibling's verdict; the box host's obligation, not a property of the kernel: the box is confined by a cgroup namespace rooted at its own placement on a mount that treats namespaces as delegation boundaries, with the host's cgroup mount kept out of the box's mount namespace; a box as the daemon's user with write access to a common ancestor can otherwise migrate itself -->
  - WHERE the host is not VM-backed, WHILE the box host cannot decide per box, WHEN a session starts THE SYSTEM SHALL print an advisory naming the cause, with the exact command that installs the classifier's privileged step when that step is what is missing, with no privilege prompt, and record that host-address boxes have no per-box enforcement on that host.
    tier:   T0
    verify: cargo nextest run -p minimald native_host_advises_classifier_install_without_prompt
    <!-- design §7.4; state+event; the causes are the privileged step not installed, or the host unable to confine a box as above (cgroup2 mounted without delegation-boundary namespaces, or the host's cgroup mount not keepable out of the box's mount namespace); installing the step clears only the first, so the command is named only for it; the ruleset needs a capability the native daemon lacks, so a native host takes one privileged install step in NET-122's advisory pattern; until then the host has no per-box host-address enforcement and says so at session start, visible to policy; refusing host-address egress declarations until then, and scoping the classifier to VM-backed hosts, are the shapes the architecture's ruling on the native install step rejected (design §7.4 and its v0.8 change history); the enforcement the host records covers addresses, never names, while the open question on native forwarding is open -->
  - WHERE the host is not VM-backed, WHILE the box host cannot decide per box, WHILE a host-address box is declared deny-all or carries an `egress` section, THE SYSTEM SHALL run the box with no per-box verdict and its declaration unenforced, recorded as such, and never refuse the box or its connections on that ground.
    tier:   T0
    verify: cargo nextest run -p minimald unenforcing_native_host_runs_host_ip_box_unenforced
    <!-- design §7.4; state-driven; the explicit exception to this requirement's deny and to NET-080's node-plane record: on that host there is no classifier, so there is no verdict to fail closed on, and the architecture's ruling on the native install step rejected turning the missing step into a hard failure for a mode whose chooser accepted the reduced tier; whether such a box may run there is policy's call on the recorded attribute, not the box host's; the box's declaration is enforced the moment the host can decide per box -->

- **NET-080** WHILE a host-address box is declared deny-all THE SYSTEM SHALL complete the daemon's own package fetch on the same host and record it as node-plane traffic.
  tier:     T0
  verify:   cargo nextest run -p minimald daemon_fetch_survives_cohort_deny
  <!-- S9b/AC2; prose 50; state-driven; un-enrolled, the node-plane set is NET-130's -->

- **NET-081** WHERE the host is VM-backed THE SYSTEM SHALL apply per-box source-addressed egress rules derived from the expanded box specs outside the VM.
  tier:     T0
  verify:   cargo nextest run -p minvmd host_side_rules_applied_outside_vm
  <!-- S10a/AC1; prose 51; optional-feature -->
  - IF a frame leaves the VM from a source address that belongs to no box THEN THE SYSTEM SHALL drop it.
    tier:   T2
    verify: cargo nextest run -p minvmd unknown_source_default_deny
    property: for every frame leaving the VM whose source belongs to no box, the frame is dropped
    harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
    <!-- S10a/AC1; prose 51; unwanted -->

- **NET-082** WHERE the host is VM-backed THE SYSTEM SHALL boot the guest with IPv6 disabled so that no IPv6 route ever appears in the guest.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_ipv6_disabled_no_v6_route
  <!-- S10a/AC2; prose 52; optional-feature; the v1 posture: design §4.2 keeps IPv6 ULA dual-stack as a later additive (design §12 item 5), which retires this requirement when it lands -->

- **NET-083** THE SYSTEM SHALL run every box without `CAP_NET_RAW`.
  tier:     T0
  verify:   cargo nextest run -p sandbox2 boxes_lack_cap_net_raw
  <!-- S10a/AC3; prose 53; ubiquitous -->

- **NET-084** IF a frame on the egress relay carries a source address other than the box's lease THEN THE SYSTEM SHALL reject it.
  tier:     T2
  verify:   cargo nextest run -p minimald relay_rejects_non_lease_source
  property: for every frame and every lease, a frame whose source is not the lease is rejected
  harness:  kani_frame_verdict_admits_nothing_undeclared; bound and purity constraint under Tiers in Design reasoning
  <!-- S10a/AC3; prose 53; unwanted -->

- **NET-085** WHERE the host is VM-backed, IF a process with root inside the VM spoofs another box's address THEN THE SYSTEM SHALL confine its reach to the union of resident boxes' declared egress plus the node-plane baseline set the architecture enumerates in design §5.1.
  tier:     T0
  verify:   cargo nextest run -p minvmd vm_escape_bounded_to_resident_union
  <!-- S10a/AC4; prose 54; feature+unwanted; the union bound is design §4.3 rule 0 and §8; un-enrolled, the baseline set is NET-130's -->

- **NET-102** WHERE the host is un-enrolled THE SYSTEM SHALL self-allocate box addresses from the default plan.
  tier:     T0
  verify:   cargo nextest run -p switch unenrolled_self_allocates_default_plan
  <!-- S17/AC1, its un-enrolled clause; prose 64; optional-feature; the enrolled clauses are EHE's (formerly NET-100, NET-101, NET-103) -->

- **NET-104** WHEN `min net forward <box> <local>:<port>` is run THE SYSTEM SHALL open a local listener relayed over the session's SSH channel so that a request to `localhost:<local>` returns the in-box server's response.
  tier:     T0
  verify:   cargo nextest run -p minimal net_forward_relays_over_ssh_channel
  <!-- S12/AC1-2; prose 66; event-driven -->

- **NET-105** WHEN the session closes THE SYSTEM SHALL close the forward's listener.
  tier:     T0
  verify:   cargo nextest run -p minimal net_forward_closes_with_session
  <!-- S12/AC2; prose 66; event-driven -->

- **NET-107** WHILE a session runs with network access THE SYSTEM SHALL complete an outbound request from inside it.
  tier:     T0
  verify:   ./scripts/session-e2e.sh session_outbound_request
  <!-- S16/AC1-2; prose 68, 69; state-driven; the lanes also run the per-mode allow and deny tests NET-038, NET-062, NET-063, and NET-079 name -->

- **NET-109** THE SYSTEM SHALL offer no HTTPS reverse proxy, no daemon-issued client certificate, and no `min ssh-forward`.
  tier:     T0
  verify:   cargo nextest run -p minimal retired_surfaces_absent
  <!-- S18/AC1; prose 70; ubiquitous; retires the surface, not a verb: `min login` is the GitHub sign-in, the alias for `min auth login` the Box Egress Proxy document binds; identity-plane certificates for remote attach are CRA's -->

- **NET-110** THE SYSTEM SHALL serve SSH direct-tcpip channel requests in release builds.
  tier:     T0
  verify:   cargo nextest run -p minimald direct_tcpip_served_in_release
  <!-- S18/AC2; prose 71; ubiquitous -->

- **NET-111** THE SYSTEM SHALL document no retired command in the CLI reference.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reference_has_no_retired_commands
  <!-- S18/AC3; prose 72; ubiquitous; "just ci passes" is process -->

- **NET-120** THE SYSTEM SHALL accept an `egress` section on a host-address box.
  tier:     T0
  verify:   cargo nextest run -p sessions egress_on_host_ip_box_accepted
  <!-- S9b/AC2; ubiquitous; supersedes the shipped 03-spec R2.1 rule that `egress` on a HostNet PTask is a parse-time error, which the daemon's session RPC still enforces; NET-079 and NET-080 presuppose this; NET-065 keeps the `none` rejection -->

- **NET-121** WHEN a box is published THE SYSTEM SHALL bind a forwarder for each ingress port its declaration names before its name is registered, and hold that forwarder until the box stops.
  tier:     T0
  verify:   cargo nextest run -p minimald declared_ports_bound_before_name_registered
  <!-- S1b-2c; design §7.1 (enforcement parity, bind discipline); event-driven; NET-016 covers ports a permit range allows and no declaration names -->
  - IF a declared port's ingress is revoked THEN THE SYSTEM SHALL unbind its forwarder and terminate the connections it holds.
    tier:   T0
    verify: cargo nextest run -p minimald ingress_revocation_unbinds_forwarder_and_terminates_connections
    <!-- design §7.1: "ingress revocation unbinds and terminates established connections"; unwanted -->
  - IF a declared port's forwarder cannot bind THEN THE SYSTEM SHALL report the failure with the reason and publish neither the name nor a substitute address for that port.
    tier:   T0
    verify: cargo nextest run -p minimald failed_forwarder_bind_is_reported_not_substituted
    <!-- design §7.1: a failed bind is "a surfaced error, never a silent fallback or a standing-capability grant"; unwanted; NET-020 covers the hostname listener -->

- **NET-122** WHILE the host's native resolver is not configured for the box zone, WHEN a session starts THE SYSTEM SHALL print an advisory naming the exact command that configures it, with no privilege prompt.
  tier:     T0
  verify:   cargo nextest run -p minimal session_start_advises_resolver_command_without_prompt
  <!-- S1b-1; design §7.1 (host-OS resolution per OS); state+event; `/etc/resolver/min.internal` with its `port` directive on macOS, the systemd-resolved routing-domain link on Linux; NET-009's WHERE presupposes it and the Box Egress Proxy document's default `dns` steering needs it -->

- **NET-123** WHEN a session starts THE SYSTEM SHALL verify by a bind probe that the reserved local range is present before publishing.
  tier:     T0
  verify:   cargo nextest run -p minimald session_start_probes_reserved_range
  <!-- S1b-2a; design §7.1 (macOS per-box addresses, the privileged step); event-driven; on Linux the range is always present on `lo` and the probe is a macOS concern; the routing-domain link carries the §4.2 hook carve-out address, not the range -->
  - IF the reserved range is absent THEN THE SYSTEM SHALL publish the box at `127.0.0.1`, re-surface the advisory of NET-122, and neither prompt nor hang.
    tier:   T0
    verify: cargo nextest run -p minimald absent_range_publishes_interim_and_readvises
    <!-- design §7.1; unwanted; the interim is a per-host state that the privileged step supersedes -->

- **NET-124** WHEN a lookup asks for a record type other than A for a name a box or node holds in the box zone THE SYSTEM SHALL answer NODATA.
  tier:     T0
  verify:   cargo nextest run -p minimald non_a_in_zone_query_is_nodata
  <!-- S1b-2b; design §7.1 (answer semantics); event-driven; never NXDOMAIN, since negative caching is name-wide and browsers pair A with HTTPS-type queries -->
  - WHEN the answerer returns NODATA or NXDOMAIN THE SYSTEM SHALL carry the zone's SOA record in the authority section of the response so that the host resolver can cache the negative.
    tier:   T0
    verify: cargo nextest run -p minimald negative_answers_carry_zone_authority
    <!-- design §7.1; event-driven; a scoped answerer whose negatives the host resolver cannot cache stalls every lookup on a macOS host, scoped or not, for the resolver's timeout per query, and reloading the resolver does not clear it; the host resolver also asks for AAAA, HTTPS and its discovery names, so every such negative needs the record -->

- **NET-125** WHEN a lookup asks for a name in the box zone that no box or node holds THE SYSTEM SHALL answer NXDOMAIN.
  tier:     T0
  verify:   cargo nextest run -p minimald unknown_in_zone_name_is_nxdomain
  <!-- S1b-2b; design §7.1; event-driven; NET-012 is the destroyed-box case -->

- **NET-126** THE SYSTEM SHALL answer box-zone lookups with a TTL of at most 15 seconds.
  tier:     T0
  verify:   cargo nextest run -p minimald zone_answers_carry_short_ttl
  <!-- S1b-2b; design §7.1 working value; ubiquitous -->

- **NET-127** WHEN a lookup originates on the host OS THE SYSTEM SHALL answer an A lookup in the box zone only with addresses in the reserved local range, the node's addresses, or `127.0.0.1`.
  tier:     T0
  verify:   cargo nextest run -p minimald host_zone_a_answers_confined_to_local_addresses
  <!-- S1a/AC3; design §7.1 (host-OS resolution of the local zone): the host answerer's rule; event-driven; in-guest the node's DNS layer answers the zone with switch addresses, the host-gateway address for `host.min.internal` (NET-003) and sibling boxes' switch addresses (NET-072, NET-073) -->

- **NET-128** WHILE a box published on a shared address is not running THE SYSTEM SHALL answer an A lookup of its name NODATA.
  tier:     T0
  verify:   cargo nextest run -p minimald stopped_shared_address_box_is_nodata
  <!-- S1b-2b; design §7.1; state-driven; the host-address lane and the macOS interim; the name stays in-zone, so no name-wide negative caching -->

- **NET-129** WHEN a host-address box is published THE SYSTEM SHALL answer its name with its node's published host-loopback address at the box's own port numbers.
  tier:     T0
  verify:   cargo nextest run -p minimald host_ip_box_answers_node_loopback_address
  <!-- S1b-2a; design §7.1 (namespace-mirror rule); event-driven; `127.0.0.1` on a native node, one allocated address per VM node; NET-010 covers own-address and `none` boxes -->
  - IF two boxes on one shared address publish the same port THEN THE SYSTEM SHALL report the collision at session start and in listings, and translate neither port.
    tier:   T0
    verify: cargo nextest run -p minimald shared_address_port_collision_reported_not_translated
    <!-- design §7.1; unwanted; same-port collisions are intrinsic to the mode -->

- **NET-130** WHERE the host is un-enrolled THE SYSTEM SHALL take the node-plane baseline set from the host-side helper's built-in enumeration of the categories design §5.1 names, configurable on the host within those categories.
  tier:     T0
  verify:   cargo nextest run -p minvmd unenrolled_baseline_set_from_helper_enumeration
  <!-- S9b/AC2, S10a/AC4; design §5.1 (the set is carried in the feed) and §7.1 (no feed un-enrolled); optional-feature; NET-080 and NET-085 presuppose it -->
  - THE SYSTEM SHALL keep the daemon's own registry and cache endpoints in the enumeration, configurable as to which registry and never absent.
    tier:   T0
    verify: cargo nextest run -p minvmd baseline_enumeration_always_carries_registry_and_cache
    <!-- ubiquitous within the WHERE; NET-080's package fetch is node-plane traffic under a deny-all host-address box only because these endpoints are always members -->
  - WHEN a box's effective egress is shown THE SYSTEM SHALL show the baseline set beside it.
    tier:   T0
    verify: cargo nextest run -p minimal policy_shows_baseline_set
    <!-- event-driven; `min session policy` (NET-061) -->

## Non-goals

- Public exposure, gateway ingress, and the enrolled dynamic-ingress path over
  the box's identity socket (formerly NET-028 to NET-034 and NET-042):
  [GWI](https://github.com/gominimal/minimal/pull/1419).
- The gateway association, the signed policy feed, the pin and the ceiling,
  address blocks from the control plane and their heartbeat reporting, relay
  reach and WireGuard over WebSocket, renumbering, and local names under
  enrolment (formerly NET-005, NET-008, NET-086 to NET-101, and NET-103):
  [EHE](https://github.com/gominimal/minimal/pull/1418).
- Mesh join, peer documents, remote box names, and `min net forward` against a
  remote session (formerly NET-106 and NET-112 to NET-119):
  [MRF](https://github.com/gominimal/minimal/pull/1420).
- Box-to-box reach across hosts by named-network grant: MRF's non-goal, blocked
  on an architecture ruling that has not been made.
- An operator recipe for pods as box hosts: EHE's non-goal, destined for the Box
  Provider API's operator documentation.
- Choosing how a box's credentialed traffic finds the Box Egress Proxy (steering
  mode and HTTP/3 posture), store references, and the client's
  `[secret-store-rules]` consent: the node-local Box Egress Proxy document; the
  fields live in the box spec's `[network]` and `[secrets]` sections but the
  behaviour is the proxy's ([Gatehouse §6.10][gatehouse]).
- Host enrolment, the node record's creation, host listing, and revocation: the
  host-enrolment work
  ([gominimal/inbox#648](https://github.com/gominimal/inbox/issues/648)). No
  requirement here assumes an enrolled host.
- Certificate-authenticated remote attach from the CLI:
  [CRA](https://github.com/gominimal/minimal/pull/1374).
- The daemon as a mesh-reachable session host, the relay tier, and the browser
  client: [MMI](https://github.com/gominimal/minimal/pull/1356) and
  [MCC](https://github.com/gominimal/minimal/pull/1355).
- Sealed secrets and the hosted Box Egress Proxy: the broker document
  ([gominimal/inbox#625](https://github.com/gominimal/inbox/issues/625)).
- BareMetalVM, the sixth deployment style ([architecture, Deployment
  Styles][arch]): a metal host's obligations are EHE's; the host-side
  enforcement this document binds (NET-081 to NET-085) is what such a host
  reuses per VM.
- The schema of the box spec's `[network]` fields: the box-spec document
  ([gominimal/inbox#570](https://github.com/gominimal/inbox/issues/570)).
  NET-060 binds acceptance of four fields, not the schema.
- Creating, listing, and choosing VMs as box providers: the Box Provider
  abstraction ([gominimal/arch#45](https://github.com/gominimal/arch/pull/45)).
  NET-052 to NET-059 bind only the box-host obligations of a named VM.
- The policy feed, ingress-entry authorization, node attributes, address
  allocation, mesh bindings, and peer documents on the identity plane:
  [NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md).
- Release notes stating the install-size growth, and documentation naming the
  exact outbound destinations a box host needs: deliverables of the plan for the
  VM-stack slices.
- Retiring the `<name>.<host-id>.min.internal` zone (`<name>.local.min.internal`
  by default), the literal host address, the legacy flag spellings, and the
  deny-all opt-out after one release: ordering facts recorded in the plan; the
  requirements here bind the compatibility behaviour while it exists.

## Design reasoning

**Four documents from one epic.** Local-first ordering (2026-09-15): the
un-enrolled local host, a laptop with VM-backed boxes or a Linux machine where
the client and the box host are co-resident, is the deployment target for the
near term, and the local Box Egress Proxy that follows depends on the resolver
and DNS-pinned egress work here. The previous shape, every deployment style in
one document scoped by WHERE, was replaced: it made the local slices wait on an
association contract the architecture still marks as a working shape, and it
put a CRITICAL open question in the document the proxy cites. The cut is by
precondition: a requirement whose WHERE or WHILE names enrolment, a gateway
association, a mesh, a remote session, or a cloud style moved to a sibling;
everything buildable with no identity plane stayed, with its ID unchanged. The
identity plane's halves remain in
[NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md)
for the reason they always did: a single document would bind identity-plane
behaviour in a repository that does not implement it.

**Ordering after the first slice.** Egress enforcement (NET-060 to NET-085)
precedes named VMs (NET-052 to NET-059): the Box Egress Proxy depends on the
former, and the work that creates and manages VMs as providers is owned
elsewhere, so this document keeps only the box-host obligations of a named VM.

**Host-OS resolution is decided in the architecture.** NET-009 binds the
outcome and NET-122 to NET-128 bind the answerer's contract; the mechanism is
[design §7.1][design]: a per-OS resolver hook routes the zone to an always-on
loopback answerer held by the host's service manager, published addresses come
from a reserved local range (`127.0.64.0/24`), Linux uses a systemd-resolved
routing domain on a dedicated link of routable scope, and macOS uses
`/etc/resolver/min.internal` with a `port` directive, written once by the
advisory command NET-122 names at session start. On macOS the same command
reserves the local range: it installs a root-held boot step that re-applies
exactly the reserved range at each start, at root-owned paths no user can
write, so the range is present before any session starts and no daemon
re-applies it. NET-123's bind probe with its `127.0.0.1` interim is what holds
on a host until that step is installed, so session start never prompts. The
answerer's negatives are cacheable by the host resolver (NET-124): an
uncacheable negative stalls every lookup on a macOS host, not only the zone's.
NET-018 and NET-019 take their WHERE from the same ruling: the proxy
is superseded only when host-OS resolution and published addresses are both
deployed on that host, and identity plays no part in the condition. Allocation
from the reserved range is host-global, arbitrated through the answerer's
authenticated channel, and no daemon self-assigns (design §7.1); that is why
NET-010's no-collision property ranges over every daemon on the host and why
NET-027 and NET-059 can route two daemons' names at once. Host-address boxes
mirror their node's address instead (NET-129), which is why NET-010 ranges over
own-address and `none` boxes only: same-port collisions on a shared address are
intrinsic to the mode and are reported, never translated. **Declared ports are
bound before the name; permitted ports follow the listener.** Design §7.1's
bind discipline holds for every port a declaration names: NET-121 binds its
forwarder before the name is registered and holds it until stop or revocation,
so a connection to a declared port that nothing is listening on yet is refused
by the box, not timed out at the host. A permit range that names no port cannot
be pre-bound, so there the story's port-on-listen shape applies: NET-016
publishes when the process listens and NET-017 withdraws when it closes. Two
alternatives were considered. Binding only declared ports narrows the story to
ports the developer typed. Letting publication follow the listener in every
case registers a name before its forwarder exists and turns NET-014's refusal
into a timeout for declared ports.

**A box outlives its client.** NET-015 states that a box runs from activation
until destroy whether or not a client is attached. Two alternatives were
considered: leaving box lifetime an open question and scoping port-on-listen to
a running box, or tying box lifetime to the attached client as today. The first
would have left the unattended-box story unsized; the second makes "the name
works whether or not a client is attached" narrower than the epic wrote it. The
chosen shape makes port publication unconditional and coheres with the
closed-laptop story elsewhere. **Idle and stop are the client's.** A box ends
only when its client issues stop, destroy, or delete, when its entrypoint exits
subject to the exit prompt, when the run it was created for ends (NET-131), or
when the box host tears it down by force: daemon shutdown, an abandoned launch,
or the host reclaiming the VM. A declared
execution ceiling is the client's policy, set at creation. There is no
daemon-side idle timeout. A daemon idle timeout was
considered and rejected: it stops a box nobody asked to stop, and it breaks the
closed-laptop story, which composes with the chosen shape with no extra rule
because a closed laptop issues no stop. Client loss splits on the terminal,
not on the verb: a lost PTY attach is a detach and the entrypoint keeps
running; a lost non-PTY exec ends the command it spawned, which would otherwise
block on a pipe nobody reads, and leaves the box untouched. In this tree each
exec is its own sandboxed process with its own lease, and a single argument is
reshelled; the architecture places an exec inside the box under the box's
identity, ceilings, and network posture, argv only, with a re-attachable PTY
form. Nothing bound here depends on the sibling-sandbox shape, and the exec
requirement is worded for the non-PTY exec so the PTY exec does not contradict
it when it lands. A box created for a run ends when the run ends, from the
daemon's side of the exec's exit (NET-131). Leaving the destroy to the client,
as the tree does today, was considered and rejected: a `min task run` client
lost mid-run would strand its session, since the abandoned-launch reap covers
only un-finalized sessions and there is no idle stop to catch it.

**The proxy keeps running after native resolution supersedes it.** NET-018 and
NET-019 make tooling report native DNS as the live surface while the hostname
proxy keeps serving. Stopping the listener was considered and rejected: it
breaks anything that captured a proxy URL, and two-daemon hosts would need port
discovery to handle an absent listener. The enforcement-parity rule applies to
the proxy for as long as it serves ([design §7.1][design]).

**Names through the shipped proxy are the first slice.** Retiring the reverse
proxy first was considered because it heads the epic's order of work, but a
removal runs nothing end to end. Unhiding the flags on a stock install was the
other candidate; the naming story is what the epic's summary leads with.

**The rollout window is bound, not just the end state.** NET-076 and NET-077
bind the announcement and the opt-out flag for the deny-all default because
both are observable; recording the window only in the plan was considered and
rejected as leaving the opt-out flag unbound. Precedence: before the default is
in force, and whenever the opt-out flag is set, an absent `egress` section
keeps the shipped allow-all default of 03-spec R2.1; once in force without the
opt-out, NET-074 and NET-075 apply. The release that brings it into force is a
plan fact.

**Bounds that were chosen here.** "Local-only" for `*.min.internal` means the
zone is answered only to lookups that originate on the machine (NET-006);
answering only loopback addresses was the weaker reading considered.
`host.min.internal` resolves from every box (NET-003) and reach over it is
local reach evaluated under the box's egress rules, default-deny except
configured host exposures ([design §7.1][design] local names): a deny-all box
resolves the name and reaches nothing (NET-079), and the daemon's own package
fetch is node-plane traffic, not the box's (NET-080). Making the host's
loopback a baseline exception for every box was considered and rejected: it
would give the shared-namespace lane a reach the box never declared. The name
answers the address that reaches the host's loopback from where the box stands
(NET-003): `127.0.0.1` on the host, the switch's host-gateway address inside a
VM-backed box, where `127.0.0.1` is the box's own loopback. A host-address
box's own declaration is enforced inside the box host by its classifier
([design §4.1][design], UC3): the box host places each host-address box in a
cgroup leaf of its own, beside the daemon's own leaf, and the packet filter
matches the box's cgroup before any source translation; the placement holds
because the box is confined by a cgroup namespace on a mount that treats
namespaces as delegation boundaries, which is the box host's obligation
(NET-079), not the kernel's default. The one carve-out from a deny-all verdict
is the address and port of the resolver Minimal owns for the box, and a
host-address box resolves through that resolver rather than the host's
(NET-003 inside a VM-backed host, NET-079 natively), so a deny-all box resolves exactly the names it holds and reaches
none of them. Inside a VM-backed host that resolver is the node's DNS layer,
which forwards a box's allowed names under its rules (NET-066), for every
host-address box. On a native host the resolver Minimal owns is the box zone's
answerer, which forwards nothing, so the rule binds only the deny-all box
there: a native host-address box that is not deny-all, which is any without an
`egress` section (NET-074) as much as one with a name allow list, has no
Minimal component that resolves its upstream names today. The open question
below names that gap and its interim: such a box resolves through the host's
resolver, the classifier decides its address rules, a name rule admits nothing
on that host, since admission comes only from resolution through the resolver
Minimal owns and a direct-to-address flow is admitted by address rules alone
([design §5.3][design]), and the per-box enforcement the host records covers
addresses, never names.
Host-address boxes on a co-resident Linux host are in scope: the ruleset needs
a capability the native daemon lacks, so a native host takes one privileged
install step in the resolver advisory's pattern and has no per-box enforcement
until then ([design §7.4][design]). Outside the box host the cohort is one
identity (NET-078) and the escape floor is the resident union. That is the split between
the first security invariant, per-box precision for traffic that leaves a box,
and the third, the floor for anything inside the escape boundary; the
invariants are not qualified by each other because the design splits them the
same way.

**An unanswered `ask` is a refusal.** A box outlives its client (NET-015), so a
dynamic ingress request decided `ask` can arrive with nobody attached to
prompt. NET-045's failure case refuses it with a typed error, and NET-046
records the refusal like every other decision. Queueing the request until a
client attaches was considered and rejected: the request would sit with no
owner and no bound on how long, and a port would appear on the host at a
moment nobody asked for it. The caller retries once a human is attached.

**Field names follow the shipped crate, and three shipped rules are
superseded.** `dynamic_ingress` (NET-043 to NET-047) is [design §7.1][design]'s
name for the setting the shipped 03-spec R2.3 called `dynamic_allowed_ports`; no
crate implements either, so the architecture's name is taken with no
compatibility clause. Three egress fields are bound in the nested spelling the
session crate's `EgressPolicy` carries, `egress.allow_subnets`,
`egress.allow_protocols` and `egress.allow_dns_hosts` (NET-060, NET-066,
NET-072); `egress.deny_subnets` (NET-060, NET-067) has no crate counterpart and
is introduced here, in the same spelling, from design §5.3's
`egress_deny_subnets`. The architecture's canonical Box Spec fields are the flat
`egress_allow_dns`, `egress_allow_subnets` and `egress_deny_subnets`
([box.toml](https://github.com/gominimal/arch/blob/main/box.toml); design §4.3,
§5.3, §7.1), and the box-spec schema work
([gominimal/inbox#570](https://github.com/gominimal/inbox/issues/570)) owns the
reconciliation. Three shipped rules are superseded: 03-spec R2.1's parse-time
error for `egress` on a HostNet PTask (NET-120), because the two-address
classifier (NET-078, design §4.1) gives the host-address cohort an enforcement
identity and the deny-all story for those boxes (NET-079, NET-080) needs the
declaration, while NET-065 keeps the rejection for `none` boxes, where there is
nothing to enforce; R2.1's allow-all default for absent `egress` fields
(NET-074, inside the window NET-076 and NET-077 bind); and R2.3's
`dynamic_allowed_ports` (NET-043). **Command tree.** This document binds the
shipped verbs `min session activate` and `min session policy`. The
architecture's command tree spells them `min session start` and `min box show
--network` with `min box port`, with `min net status [<box>]` for effective
rules; the migration to those names is a separate change, and the requirements
here follow it when it lands without changing meaning. `min ls` is the tree's
own alias for `min box list` and needs no migration. `min net expose` and `min
net forward` are the tree's own names and are new surfaces here. NET-109 retires
a surface, not a verb: the reverse proxy's daemon-issued client certificates and
`min ssh-forward` go, `min login` becomes the GitHub sign-in, the alias for `min
auth login` that the Box Egress Proxy document binds, and identity-plane
certificates for remote attach are CRA's.

**Lane stories are product behaviours.** The maintainer's lane-assertion story
became NET-107, whose named test is the lane's outbound-reach assertion; the
per-mode allow and deny assertions are the tests NET-038, NET-062, NET-063 and
NET-079 already name, and NET-107's comment records that the lanes run them. A
second requirement restating those four was considered and removed. Keeping the
story as a test-suite obligation outside the requirements was considered and
rejected because nothing in the document would then bind that the lanes assert
it.

**Tiers.** Every frame-level admit-or-drop decision (NET-016's failure case,
NET-062, NET-064, NET-069, NET-070, NET-081's failure case, NET-084), the
rebinding intersection (NET-067), and loopback allocation (NET-010) are T2:
each is a decision separable from its I/O, and the tier constrains the daemon
to keep it a pure function so a Kani harness can exhaust it on the lane that
runs today. The seven frame-level requirements share one harness,
`kani_frame_verdict_admits_nothing_undeclared`, exhaustive to an unwind bound
of 4 over a 40-byte IPv4+L4 header and at most 4 rules; it requires the
admit-or-drop decision to be a pure function over an owned frame summary and
owned rules, separate from the relay loop. Proxy parity (NET-071) is T1 and adds a property-test dependency
the workspace does not have; that cost was accepted. T3 was refused for every
candidate: the effect shells are async relay tasks, sockets, and a VM boundary,
which fail the no-concurrency constraint, and the repository has no Lean
project. The escape bound (NET-085) stays a T0 system test with a root-in-VM
spoofer; its universal is the invariant below, covered by the frame core. The
feed-regression harness moved to EHE with the requirement that owns it.

**Cross-cutting decisions live in the architecture.** The two-address
node-netns split, the residency clamp, DNS-pinned FQDN rules with the rebinding
defence, the degraded-mode profile with its host-OS resolution and
published-address rules, and the rule that on a host with a VM the node side of
any association is the VM together with its host-side helper are [design §4.1,
§4.3, §5.3, §7.1, and §7.4][design]; the WireGuard-free local path is [design
§11][design]. This document binds the box host's observable behaviour under
them and restates none of them.

**Generality:** a second local provider or platform fits without rewording:
every requirement names the box host, the daemon, the `min` client, or the
installer, and VM-specific behaviour is scoped WHERE the host is VM-backed.
What a native co-resident host cannot offer is an enforcement point outside its
escape boundary ([design §7.4][design]); its egress rules hold only while the
daemon does, and the attribute that makes that gap visible to policy is EHE's.

## Security considerations

- **Invariant:** THE SYSTEM SHALL admit no connection to a box, and no
  connection from a box, that the box's declared rules do not permit.
  enforced by: the frame-level admit-or-drop decision applied at the switch,
  the relay, and every hostname-routing surface
  covered by: NET-016, NET-038, NET-062, NET-064, NET-069, NET-070, NET-074,
  NET-079, NET-121
- **Invariant:** THE SYSTEM SHALL give a hostname-routing surface no reach that
  a direct connection would not have.
  enforced by: one decision function shared by the proxy and the relay
  covered by: NET-071, NET-073
- **Invariant:** THE SYSTEM SHALL bound the reach of any process inside the
  escape boundary, root included, to the union of resident boxes' declared
  egress plus the node-plane baseline set (design §5.1).
  enforced by: per-box source-addressed rules applied outside the VM, boxes
  without `CAP_NET_RAW`, the relay's source-address check, and guest IPv6
  disabled
  ([design §4.3 rule 0 and §8][design])
  covered by: NET-081, NET-082, NET-083, NET-084, NET-085, NET-130
- **Invariant:** THE SYSTEM SHALL admit for a name only addresses that name
  resolved to, intersected with the box's denies and the infrastructure deny
  set.
  enforced by: the rebinding intersection
  covered by: NET-066, NET-067
- **Invariant:** THE SYSTEM SHALL publish a dynamically requested port only
  under a recorded allow decision.
  enforced by: the local daemon evaluates the same request shape as the
  enrolled path against the box's `dynamic_ingress` setting and audits every
  decision
  covered by: NET-043, NET-044, NET-046, NET-047
- **Invariant:** THE SYSTEM SHALL keep local names out of every certificate
  and audit record and off every other host.
  enforced by: the host answerer serves on-machine lookups only and answers
  only local addresses; in-guest answers are switch addresses that never
  leave the node
  covered by: NET-006, NET-007, NET-127

## Open questions
- [NEEDS CLARIFICATION (MEDIUM): on a native host, which component forwards a
  non-deny-all host-address box's upstream name queries under the box's rules
  (NET-066, NET-079), or are native host-address allow lists CIDR-only until one
  exists? [Design §5.3][design] models a Minimal resolver that forwards a
  host-address box's queries and evaluates them against the cohort rules; the
  native answerer of [design §7.1][design] forwards nothing by design, and no
  native-host component forwards under cohort rules today. The deny-all case is
  settled: in-zone names resolve and nothing else does. The interim while this
  is open: a native host-address box that is not deny-all resolves through the
  host's resolver; the classifier decides its address rules; a name rule
  (NET-066) admits nothing on that host, since admission comes only from
  resolution through the resolver Minimal owns and a direct-to-address flow is
  admitted by address rules alone ([design §5.3][design]); and the per-box
  enforcement the host records under NET-079 covers addresses, never names.]
- [NEEDS CLARIFICATION (LOW): are HTTP/2 and HTTP/3 through any proxy surface in
  scope? [Design §5.3][design] governs QUIC for egress and leaves the proxy
  surfaces unaddressed; the local Box Egress Proxy document needs the answer for
  its steered hosts.]

[design]: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
[arch]: https://github.com/gominimal/arch/blob/main/architecture.md
[gatehouse]: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
