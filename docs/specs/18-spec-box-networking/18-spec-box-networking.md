---
id: NET
title: Box networking on the local host: preview by name and bounded egress
owner: norrietaylor
epic: gominimal/inbox#646
arch: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
updated: 2026-09-16
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
identity plane ([design §7.1 and
§7.4](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).
This document binds that profile on the box host: the `min` CLI, the session
daemon, the VM host daemon, the installer, and the release manifests, on a
laptop running VM-backed boxes and on a Linux machine where the client and the
box host share the machine.

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

The local Box Egress Proxy, the local form of the sealed-secrets design
([architecture
D6](https://github.com/gominimal/arch/blob/main/architecture.md)), is the next
thing built and is a separate document that cites this one. It depends on three
behaviours bound here: box-zone resolution (NET-072, NET-073),
`egress.allow_dns_hosts` with DNS-pinned admission (NET-066, NET-067), and the
hostname-proxy parity rule (NET-069 to NET-071); its default `dns` steering
mode needs the box-zone resolver and the DNS-pinned name path to exist. UDP a
box has not declared is dropped (NET-064), so HTTP/3 to a steered host falls
back to TCP ([design
§5.3](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).

**Success:** on a stock install, a browser opens
`http://<name>.min.internal:<port>` with no proxy configuration; an own-address
box declared deny-all reaches nothing; and a process that gains root inside the
VM and spoofs another box's address reaches nothing outside the union of
resident boxes' declared egress.

**First slice:** `<name>.min.internal` and `host.min.internal` routed through
the hostname proxy that already ships, own-address sessions on the VM host
included, with every refusal logged (NET-001 to NET-004).

## Users and stories

**Roles:** developer previewing a box on my own machine, developer running a dev server in a box on my own machine, developer running two boxes that both listen on port 3000, developer previewing a box by name, developer who just started a server inside a box, developer on a host where names resolve natively and box ports are published by identity, developer relying on box hostnames, developer running a native box host and a VM box host on the same machine, developer activating a session, developer on a fresh macOS or Linux install, developer who just started a server inside a box I am attached to, developer on a Linux workstation, developer on an arm64 Linux machine, developer who wants strong isolation between two projects, developer with two VMs, developer running an agent in a box, developer who wants to allow `github.com` and nothing else, developer who has restricted a box's ingress, platform engineer, platform engineer, developer on macOS or Linux running VM-backed boxes, developer with a service in a remote box, maintainer, maintainer

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

- **NET-002** WHEN a request arrives for `<name>.local.min.internal` THE SYSTEM SHALL route it as `<name>.min.internal` and emit a deprecation notice.
  tier:     T0
  verify:   cargo nextest run -p minimald legacy_local_zone_routes_with_deprecation
  <!-- S1a/AC1; prose 2; event-driven; "for one release" is a plan fact -->

- **NET-003** THE SYSTEM SHALL resolve `host.min.internal` from host-address, own-address, and VM-backed boxes to the host's loopback services.
  tier:     T0
  verify:   cargo nextest run -p minimald host_min_internal_reaches_host_loopback_from_each_mode
  <!-- S1a/AC2; prose 3; ubiquitous -->

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

- **NET-010** WHEN a box is published THE SYSTEM SHALL assign it a host loopback address of its own and publish its ports at the box's own port numbers.
  tier:     T2
  verify:   cargo nextest run -p minimald each_box_gets_own_loopback_address
  property: for every sequence of publish and withdraw operations up to 8 live boxes, no two live boxes hold the same loopback address
  harness:  kani_loopback_alloc_injective, exhaustive to 8 live boxes; requires the allocator to be a pure function over an owned set of leased addresses, separate from the publish call
  <!-- S1b-2a; prose 6; event-driven; the no-collision clause is the universal for spec-tiers -->

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
  - IF an attached client is lost abruptly THEN THE SYSTEM SHALL keep the box's task running.
    tier:   T0
    verify: cargo nextest run -p minimald abrupt_client_loss_keeps_task
    <!-- S1b-2c; prose 10; unwanted -->

- **NET-016** WHILE a box is running, WHEN a process in it starts listening on a port its ingress rules permit THE SYSTEM SHALL publish that port on the box's address.
  tier:     T0
  verify:   cargo nextest run -p minimald listen_publishes_permitted_port
  <!-- S1b-2c/AC1-2; prose 11; state+event -->
  - IF a process in a box listens on a port its ingress rules do not permit THEN THE SYSTEM SHALL leave the port unpublished.
    tier:   T2
    verify: cargo nextest run -p minimald listen_on_undeclared_port_not_published
    property: for every box and every port its ingress rules do not permit, a listener on that port is never published
    harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
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
  <!-- S2b/AC2; prose 17; state-driven -->

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
  <!-- S4a/AC2; prose 24; event-driven; "for one release" is a plan fact; legacy/new spelling corrected; `no-net` added to the enumeration -->

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
  <!-- S5/AC1; prose 28; feature+event -->

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

- **NET-060** THE SYSTEM SHALL accept `egress.allow_subnets` and `egress.allow_protocols` in the box spec.
  tier:     T0
  verify:   cargo nextest run -p sessions spec_accepts_egress_allow_fields
  <!-- S8a/AC1; prose 39; ubiquitous -->

- **NET-061** THE SYSTEM SHALL show a box's effective egress rules in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimal policy_shows_effective_egress
  <!-- S8a/AC1; prose 39; ubiquitous -->

- **NET-062** WHILE a box runs with an own address, IF it opens a connection to a destination its egress rules do not allow THEN THE SYSTEM SHALL drop the connection without resetting it.
  tier:     T2
  verify:   cargo nextest run -p minimald disallowed_egress_dropped_not_reset
  property: for every own-address box and every destination its rules do not allow, the connection is dropped and never reset
  harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
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
  harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
  <!-- S8a/AC2; prose 40; state+unwanted -->

- **NET-065** IF a box spec declares `egress` on a `none` box THEN THE SYSTEM SHALL reject it as a validation error.
  tier:     T0
  verify:   cargo nextest run -p sessions egress_on_none_box_is_validation_error
  <!-- S8a/AC3; prose 41; unwanted -->

- **NET-066** WHEN a box resolves a name matched by its `egress.allow_dns_hosts` THE SYSTEM SHALL admit the answer's addresses for that box for the admission window the architecture defines.
  tier:     T0
  verify:   cargo nextest run -p minimald dns_pinned_admission_window
  <!-- S8b/AC1; prose 42; event-driven -->

- **NET-067** IF an allowed name resolves into a denied range THEN THE SYSTEM SHALL refuse the connection.
  tier:     T2
  verify:   cargo nextest run -p minimald denied_range_resolution_refused
  property: for every resolved answer set and every allow, deny, and infrastructure-deny CIDR set, the admitted set contains no denied address
  harness:  kani_rebinding_intersection_admits_no_denied_address, exhaustive to an unwind bound of 4 over IPv4 answers with at most 4 CIDRs per set; requires the intersection to be a pure function over owned addresses and CIDRs, separate from resolver I/O
  <!-- S8b/AC2; prose 43; unwanted -->
  - IF an allowed name resolves into a denied range THEN THE SYSTEM SHALL log the name and the answer.
    tier:   T0
    verify: cargo nextest run -p minimald denied_range_resolution_logged
    <!-- S8b/AC2; prose 43; unwanted -->

- **NET-068** WHILE a box's egress is a hostname-only allowlist THE SYSTEM SHALL complete `apt`, `git clone`, `npm install`, `pip`, and a container pull.
  tier:     T0
  verify:   cargo nextest run -p minvmd hostname_allowlist_toolchain_completes
  <!-- S8b/AC3; prose 44; state-driven -->

- **NET-069** IF a request through the hostname proxy targets a port the target box did not declare THEN THE SYSTEM SHALL refuse it with the same refusal as a direct connection.
  tier:     T2
  verify:   cargo nextest run -p minimald proxy_undeclared_port_refused_like_direct
  property: for every target box, every undeclared port, and every proxied request to it, the refusal equals the direct-connection refusal
  harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
  <!-- S8c/AC1; prose 45; unwanted -->

- **NET-070** IF a request through the hostname proxy comes from a caller whose egress rules deny the target THEN THE SYSTEM SHALL refuse it.
  tier:     T2
  verify:   cargo nextest run -p minimald proxy_caller_egress_denied
  property: for every caller whose egress rules deny the target, every proxied request is refused
  harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
  <!-- S8c/AC1; prose 45; unwanted -->

- **NET-071** THE SYSTEM SHALL apply the hostname proxy's ingress and egress refusals to host-address and own-address targets alike.
  tier:     T1
  verify:   cargo nextest run -p minimald proxy_parity_across_network_modes
  property: for every network mode, every rule set, and every request, the hostname proxy's verdict equals the direct connection's verdict
  <!-- S8c/AC2; prose 45; ubiquitous -->

- **NET-072** THE SYSTEM SHALL resolve box-zone names with no `egress_allow_dns` entry.
  tier:     T0
  verify:   cargo nextest run -p minimald box_zone_resolution_needs_no_allow_entry
  <!-- S8c/AC3; prose 46; ubiquitous -->

- **NET-073** WHEN a box connects to a box-zone name THE SYSTEM SHALL enforce the target's ingress rules and the source's egress rules at connection time.
  tier:     T0
  verify:   cargo nextest run -p minimald box_zone_connection_enforced_at_connect
  <!-- S8c/AC3; prose 46; event-driven -->

- **NET-074** WHEN an own-address box is created with no `egress` section THE SYSTEM SHALL give it no reach to any external address.
  tier:     T0
  verify:   cargo nextest run -p minimald own_ip_default_deny_all
  <!-- S9a/AC1; prose 47; event-driven -->

- **NET-075** WHILE an own-address box has no `egress` section THE SYSTEM SHALL show `deny-all` in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimal policy_shows_deny_all_default
  <!-- S9a/AC1; prose 47; state-driven -->

- **NET-076** WHILE the deny-all default is announced but not yet in force THE SYSTEM SHALL print the coming change at activate.
  tier:     T0
  verify:   cargo nextest run -p minimal deny_all_announcement_printed
  <!-- S9a/AC2; prose 48; state-driven; interview decision -->

- **NET-077** WHERE the deny-all opt-out flag is set THE SYSTEM SHALL keep the prior default.
  tier:     T0
  verify:   cargo nextest run -p minimald deny_all_opt_out_keeps_prior_default
  <!-- S9a/AC2; prose 48; optional-feature -->

- **NET-078** THE SYSTEM SHALL classify node-plane traffic and the host-address cohort separately with distinct source identities.
  tier:     T0
  verify:   cargo nextest run -p minimald node_plane_and_cohort_distinct_sources
  <!-- S9b/AC1; prose 49; ubiquitous -->

- **NET-079** WHILE a host-address box is declared deny-all THE SYSTEM SHALL refuse every outbound connection it opens.
  tier:     T0
  verify:   cargo nextest run -p minimald host_ip_deny_all_no_outbound
  <!-- S9b/AC2; prose 50; state-driven -->

- **NET-080** WHILE a host-address box is declared deny-all THE SYSTEM SHALL complete the daemon's own package fetch on the same host and record it as node-plane traffic.
  tier:     T0
  verify:   cargo nextest run -p minimald daemon_fetch_survives_cohort_deny
  <!-- S9b/AC2; prose 50; state-driven -->

- **NET-081** WHERE the host is VM-backed THE SYSTEM SHALL apply per-box source-addressed egress rules derived from the expanded box specs outside the VM.
  tier:     T0
  verify:   cargo nextest run -p minvmd host_side_rules_applied_outside_vm
  <!-- S10a/AC1; prose 51; optional-feature -->
  - IF a frame leaves the VM from a source address that belongs to no box THEN THE SYSTEM SHALL drop it.
    tier:   T2
    verify: cargo nextest run -p minvmd unknown_source_default_deny
    property: for every frame leaving the VM whose source belongs to no box, the frame is dropped
    harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
    <!-- S10a/AC1; prose 51; unwanted -->

- **NET-082** WHERE the host is VM-backed THE SYSTEM SHALL boot the guest with IPv6 disabled so that no IPv6 route ever appears in the guest.
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_ipv6_disabled_no_v6_route
  <!-- S10a/AC2; prose 52; optional-feature -->

- **NET-083** THE SYSTEM SHALL run every box without `CAP_NET_RAW`.
  tier:     T0
  verify:   cargo nextest run -p sandbox2 boxes_lack_cap_net_raw
  <!-- S10a/AC3; prose 53; ubiquitous -->

- **NET-084** IF a frame on the egress relay carries a source address other than the box's lease THEN THE SYSTEM SHALL reject it.
  tier:     T2
  verify:   cargo nextest run -p minimald relay_rejects_non_lease_source
  property: for every frame and every lease, a frame whose source is not the lease is rejected
  harness:  kani_frame_verdict_admits_nothing_undeclared, exhaustive to an unwind bound of 4 over a 40-byte IPv4+L4 header and at most 4 rules; requires the admit/drop decision to be a pure function over an owned frame summary and owned rules, separate from the relay loop
  <!-- S10a/AC3; prose 53; unwanted -->

- **NET-085** WHERE the host is VM-backed, IF a process with root inside the VM spoofs another box's address THEN THE SYSTEM SHALL confine its reach to the union of resident boxes' declared egress plus the enumerated baseline set.
  tier:     T0
  verify:   cargo nextest run -p minvmd vm_escape_bounded_to_resident_union
  <!-- S10a/AC4; prose 54; feature+unwanted -->

- **NET-102** WHERE the host is un-enrolled THE SYSTEM SHALL self-allocate box addresses from the default plan.
  tier:     T0
  verify:   cargo nextest run -p switch unenrolled_self_allocates_default_plan
  <!-- S17/AC1; prose 64; optional-feature -->

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
  <!-- S16/AC1; prose 68; state-driven; reframed from a lane obligation, handed back as a question -->

- **NET-108** WHILE a box runs in any network mode THE SYSTEM SHALL admit the destinations its mode and rules allow and refuse those they deny.
  tier:     T0
  verify:   cargo nextest run -p minvmd per_mode_allow_and_deny
  <!-- S16/AC2; prose 69; state-driven; reframed, handed back as a question -->

- **NET-109** THE SYSTEM SHALL offer no HTTPS reverse proxy, no client-certificate issuance, no `min login`, and no `min ssh-forward`.
  tier:     T0
  verify:   cargo nextest run -p minimal retired_surfaces_absent
  <!-- S18/AC1; prose 70; ubiquitous -->

- **NET-110** THE SYSTEM SHALL serve SSH direct-tcpip channel requests in release builds.
  tier:     T0
  verify:   cargo nextest run -p minimald direct_tcpip_served_in_release
  <!-- S18/AC2; prose 71; ubiquitous -->

- **NET-111** THE SYSTEM SHALL document no retired command in the CLI reference.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reference_has_no_retired_commands
  <!-- S18/AC3; prose 72; ubiquitous; "just ci passes" is process -->

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
- An operator recipe for pods as box hosts: EHE's non-goal, destined for the
  Box Provider API's operator documentation.
- Choosing how a box's credentialed traffic finds the Box Egress Proxy
  (steering mode and HTTP/3 posture): the local Box Egress Proxy document; the
  fields live in the box spec's `[network]` section but the behaviour is the
  proxy's.
- Host enrolment, the node record's creation, host listing, and revocation: the
  host-enrolment work (gominimal/inbox#648). No requirement here assumes an
  enrolled host.
- Certificate-authenticated remote attach from the CLI:
  [CRA](https://github.com/gominimal/minimal/pull/1374).
- The daemon as a mesh-reachable session host, the relay tier, and the browser
  client: [MMI](https://github.com/gominimal/minimal/pull/1356) and
  [MCC](https://github.com/gominimal/minimal/pull/1355).
- Sealed secrets and the credential broker: the broker document
  (gominimal/inbox#625).
- The schema of the box spec's `[network]` fields: the box-spec document
  (gominimal/inbox#570). NET-060 binds acceptance of two fields, not the
  schema.
- Creating, listing, and choosing VMs as box providers: the Box Provider
  abstraction (gominimal/arch#45). NET-052 to NET-059 bind only the box-host
  obligations of a named VM.
- The policy feed, ingress-entry authorization, node attributes, address
  allocation, mesh bindings, and peer documents on the identity plane:
  [NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md).
- Release notes stating the install-size growth, and documentation naming the
  exact outbound destinations a box host needs: deliverables of the plan for
  the VM-stack slices.
- Retiring `<name>.local.min.internal`, the literal host address, the legacy
  flag spellings, and the deny-all opt-out after one release: ordering facts
  recorded in the plan; the requirements here bind the compatibility behaviour
  while it exists.

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
outcome; the mechanism is [design
§7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md):
a per-OS resolver hook routes the zone to an always-on loopback answerer held
by the host's service manager, published addresses come from a reserved local
range (`127.0.64.0/24`), Linux uses a systemd-resolved routing domain on a
dedicated link of routable scope, and macOS uses `/etc/resolver/min.internal`
with a `port` directive, written once by an advisory command that the session
start names. NET-018 and NET-019 take their WHERE from the same ruling: the
proxy is superseded only when host-OS resolution and published addresses are
both deployed on that host, and identity plays no part in the condition.

**A box outlives its client.** NET-015 states that a box runs from activation
until destroy whether or not a client is attached. Two alternatives were
considered: leaving box lifetime an open question and scoping port-on-listen to
a running box, or tying box lifetime to the attached client as today. The first
would have left the unattended-box story unsized; the second makes "the name
works whether or not a client is attached" narrower than the epic wrote it. The
chosen shape makes port publication unconditional and coheres with the
closed-laptop story elsewhere; the idle and stop policy that follows from it is
an open question below.

**The proxy keeps running after native resolution supersedes it.** NET-018 and
NET-019 make tooling report native DNS as the live surface while the hostname
proxy keeps serving. Stopping the listener was considered and rejected: it
breaks anything that captured a proxy URL, and two-daemon hosts would need port
discovery to handle an absent listener. The enforcement-parity rule applies to
the proxy for as long as it serves ([design
§7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).

**Names through the shipped proxy are the first slice.** Retiring the reverse
proxy first was considered because it heads the epic's order of work, but a
removal runs nothing end to end. Unhiding the flags on a stock install was the
other candidate; the naming story is what the epic's summary leads with.

**The rollout window is bound, not just the end state.** NET-076 and NET-077
bind the announcement and the opt-out flag for the deny-all default because
both are observable; recording the window only in the plan was considered and
rejected as leaving the opt-out flag unbound.

**Bounds that were chosen here.** "Local-only" for `*.min.internal` means the
zone is answered only to lookups that originate on the machine (NET-006);
answering only loopback addresses was the weaker reading considered.

**Lane stories are product behaviours.** The maintainer's lane-assertion story
became NET-107 and NET-108, whose named tests are the lane assertions; keeping
it as a test-suite obligation outside the requirements was considered and
rejected because nothing in the document would then bind that the lanes assert
it.

**Tiers.** Every frame-level admit-or-drop decision (NET-016's failure case,
NET-062, NET-064, NET-069, NET-070, NET-081's failure case, NET-084), the
rebinding intersection (NET-067), and loopback allocation (NET-010) are T2:
each is a decision separable from its I/O, and the tier constrains the daemon
to keep it a pure function so a Kani harness can exhaust it on the lane that
runs today. Proxy parity (NET-071) is T1 and adds a property-test dependency
the workspace does not have; that cost was accepted. T3 was refused for every
candidate: the effect shells are async relay tasks, sockets, and a VM boundary,
which fail the no-concurrency constraint, and the repository has no Lean
project. The escape bound (NET-085) stays a T0 system test with a root-in-VM
spoofer; its universal is the invariant below, covered by the frame core. The
feed-regression harness moved to EHE with the requirement that owns it.

**Cross-cutting decisions live in the architecture.** The two-address
node-netns split, the residency clamp, DNS-pinned FQDN rules with the rebinding
defence, and the degraded-mode profile with its host-OS resolution and
published-address rules are [design §4.1, §4.3, §5.3, §7.1, and
§7.4](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md).
This document binds the box host's observable behaviour under them and restates
none of them.

**Generality:** a second local provider or platform fits without rewording:
every requirement names the box host, the daemon, the `min` client, or the
installer, and VM-specific behaviour is scoped WHERE the host is VM-backed.
What a native co-resident host cannot offer is an enforcement point outside its
escape boundary ([design
§7.4](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md));
its egress rules hold only while the daemon does, and the attribute that makes
that gap visible to policy is EHE's.

## Security considerations

- **Invariant:** THE SYSTEM SHALL admit no connection to a box, and no
  connection from a box, that the box's declared rules do not permit.
  enforced by: the frame-level admit-or-drop decision applied at the switch,
  the relay, and every hostname-routing surface
  covered by: NET-016, NET-038, NET-062, NET-064, NET-069, NET-070, NET-074,
  NET-079
- **Invariant:** THE SYSTEM SHALL give a hostname-routing surface no reach that
  a direct connection would not have.
  enforced by: one decision function shared by the proxy and the relay
  covered by: NET-071, NET-073
- **Invariant:** THE SYSTEM SHALL bound the reach of any process inside the
  escape boundary, root included, to the union of resident boxes' declared
  egress plus the enumerated baseline set.
  enforced by: per-box source-addressed rules applied outside the VM, boxes
  without `CAP_NET_RAW`, the relay's source-address check, and guest IPv6
  disabled
  ([design §4.3 rule 0 and §8](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md))
  covered by: NET-081, NET-082, NET-083, NET-084, NET-085
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
  enforced by: the local answerer serves on-machine lookups only
  covered by: NET-006, NET-007

## Open questions

- [NEEDS CLARIFICATION (HIGH): the macOS mechanism for per-box loopback
  addresses, a root-installed boot re-apply of the reserved range installed by
  the same advisory command that writes the resolver file, is proposed in
  [design
  §7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)
  pending the loopback-alias measurement (design §12 item 13). Until it is
  deployed on a host, macOS publishes every box at `127.0.0.1`; NET-010 binds
  distinct addresses once it is, and the interim is a per-host state, not a
  platform exception.]
- [NEEDS CLARIFICATION (MEDIUM): what is the cgroup layout for the two-address
  classifier, and are host-address boxes on a co-resident Linux host in scope
  of NET-078 to NET-080? [Design
  §7.4](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)
  applies the profile's naming and addressing to that host and says nothing
  about the classifier.]
- [NEEDS CLARIFICATION (MEDIUM): with a box outliving its client (NET-015), who
  owns the idle and stop policy, and how does it compose with the closed-laptop
  story in the remote-sessions work?]
- [NEEDS CLARIFICATION (LOW): are HTTP/2 and HTTP/3 through any proxy surface
  in scope? [Design
  §5.3](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)
  governs QUIC for egress and leaves the proxy surfaces unaddressed; the local
  Box Egress Proxy document needs the answer for its steered hosts.]
