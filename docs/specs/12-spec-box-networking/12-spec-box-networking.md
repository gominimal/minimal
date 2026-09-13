---
id: NET
title: Box networking — preview by name, bounded egress, and reach across hosts
owner: norrietaylor
epic: gominimal/inbox#646
arch: https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md
updated: 2026-09-11
---

# NET — Box networking: preview by name, bounded egress, and reach across hosts

## Context

A developer on a stock install reaches a box through one surface today, the
Host-header hostname proxy, and nothing else the networking design promises
exists: no box name in a browser without proxy configuration, no egress
enforcement, hidden network-mode and ingress flags, and a VM stack that only
macOS installs receive. The architecture of record now defines what a box host
must enforce in every deployment style, and a degraded-mode profile for
un-enrolled laptops that is buildable with no identity plane. This document
covers the box host's side of that design: the `min` CLI, the session daemon,
the VM host daemon, the installer, and the release manifests. The identity
plane's side is the sibling document
[NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md).

After this ships, a developer previews a box's server at `<name>.min.internal`
in any browser, chooses a box's network posture on the command line, declares
what the box may reach and has that enforced outside the box even after an
escape into the VM, and reaches boxes on other machines over an authenticated
channel, all through one `min net` grammar. The constraint holds in both
directions: nothing reaches a box and nothing leaves it unless declared, and a
hostname-routing surface is never a policy side door.

**Success:** on a stock install, a browser opens `http://<name>.min.internal:<port>`
with no proxy configuration; an own-address box declared deny-all reaches
nothing; and a process that gains root inside the VM and spoofs another box's
address reaches nothing outside the union of resident boxes' declared egress.

**First slice:** `<name>.min.internal` and `host.min.internal` routed through
the hostname proxy that already ships, own-address sessions on the VM host
included, with every refusal logged (NET-001 to NET-004).

## Users and stories

**Roles:** developer previewing a box on my own machine, developer running a dev server in a box on my own machine, developer running two boxes that both listen on port 3000, developer previewing a box by name, developer who just started a server inside a box, developer on a host where names resolve natively and box ports are published by identity, developer relying on box hostnames, developer running a native box host and a VM box host on the same machine, developer who needs a webhook or demo URL reachable by an unauthenticated party, developer on a CloudVM or Cloudflare box host, developer activating a session, developer on a fresh macOS or Linux install, developer who just started a server inside a box I am attached to, developer on a Linux workstation, developer on an arm64 Linux machine, developer who wants strong isolation between two projects, developer with two VMs, developer running an agent in a box, developer who wants to allow `github.com` and nothing else, developer who has restricted a box's ingress, platform engineer, developer on macOS or Linux running VM-backed boxes, platform engineer running box hosts on cloud VMs, platform engineer running box hosts as pods, platform engineer writing policy, developer with a service in a remote box, developer on a laptop, developer running services across two box hosts, platform engineer standing up a box host in a private subnet, maintainer, platform engineer running box hosts for several teams

- AS A developer previewing a box on my own machine, I WANT boxes to answer at `<name>.min.internal` and the host at `host.min.internal` on an un-enrolled laptop, with the same names carrying over when the host enrols, SO THAT the names in my recipes stay valid from first install through enrolment.
- AS A developer running a dev server in a box on my own machine, I WANT `http://<name>.min.internal:<port>` to resolve in any browser without a proxy, PAC file, or `HTTP_PROXY`, SO THAT previewing my work is one URL, not a browser-profile recipe.
- AS A developer running two boxes that both listen on port 3000, I WANT each box to be published at its own `127.0.0.N` address at the box's own port, SO THAT `http://web.min.internal:3000` and `http://api.min.internal:3000` both work with no translation and no collision.
- AS A developer previewing a box by name, I WANT `<name>.min.internal` to answer the box's loopback address from `activate` until `destroy`, SO THAT the name works whether or not a client is attached right now.
- AS A developer who just started a server inside a box, I WANT its port published on the box's address the moment it listens, subject to the box's ingress rules, SO THAT I never type an `--ingress` mapping for a port I am allowed to expose.
- AS A developer on a host where names resolve natively and box ports are published by identity, I WANT the proxy to stop being the UC2a surface on that host, SO THAT there is one way to reach a box by name, not two.
- AS A developer relying on box hostnames, I WANT routing to come back by itself when the port it needs frees up, and to be told at `activate` and `ls` while it is down, SO THAT I never have to `min stop` and restart to get hostnames back.
- AS A developer running a native box host and a VM box host on the same machine, I WANT each daemon to keep a working hostname surface, SO THAT the second daemon to start does not silently lose routing.
- AS A developer who needs a webhook or demo URL reachable by an unauthenticated party, I WANT `min net expose --public <port>` to publish the port where the deployment can, and refuse clearly where it cannot, SO THAT public exposure is a deliberate act and I am never left guessing whether it happened.
- AS A developer on a CloudVM or Cloudflare box host, I WANT my authorized public port served by the deployment's gateway over the host's existing association, SO THAT the host itself opens no inbound port.
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
- AS A platform engineer running box hosts on cloud VMs, I WANT the host's fabric rule to admit only its Egress Gateway on both address families, with the gateway enforcing each box's declared egress from the signed policy feed, SO THAT my compliance story does not depend on container isolation holding.
- AS A platform engineer running box hosts as pods, I WANT a default-deny egress NetworkPolicy plus allow-to-gateway to be the entire fabric pin, SO THAT I need no FQDN-capable CNI.
- AS A platform engineer writing policy, I WANT every box host to carry `egress_pin` (pinned, pinned_site, advisory, none), asserted by the provider or admin, SO THAT boxes holding brokered secrets can be kept off hosts whose egress floor is not externally enforced.
- AS A platform engineer, I WANT to set a static egress ceiling on a host that every box's rules must fit inside, SO THAT a box that would exceed the host's bound fails at creation, not at first packet.
- AS A developer with a service in a remote box, I WANT `min net forward <box> <local>:<port>` to open a local listener that tunnels to the box over my existing SSH session, SO THAT I can hit a remote service on `localhost` with nothing else installed or configured.
- AS A developer on a laptop, I WANT `min net mesh join` to enrol me using my signed-in identity and receive peer configuration automatically, SO THAT I reach remote boxes by hostname without copying WireGuard keys around.
- AS A developer running services across two box hosts, I WANT a box on host A to reach a service in a box on host B that a named network grants it, by hostname, over an authenticated encrypted channel, SO THAT multi-host workflows do not need a VPN I set up by hand.
- AS A platform engineer standing up a box host in a private subnet, I WANT policy delivery, the relay path, and mesh to work with zero inbound reachability, SO THAT I never open an inbound port or assign a public IP to a box host.
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

- **NET-005** WHILE the host is enrolled THE SYSTEM SHALL keep every `*.min.internal` name resolvable on the machine.
  tier:     T0
  verify:   cargo nextest run -p minimald min_internal_survives_enrolment
  <!-- S1a/AC3; prose 4; state-driven -->

- **NET-006** THE SYSTEM SHALL answer `*.min.internal` names only to lookups that originate on the machine.
  tier:     T0
  verify:   cargo nextest run -p minimald min_internal_zone_not_served_off_host
  <!-- S1a/AC3; prose 4; ubiquitous; "local-only" sharpened to "not served to other hosts" -->

- **NET-007** THE SYSTEM SHALL issue no certificate and write no audit record that names a `*.min.internal` name.
  tier:     T0
  verify:   cargo nextest run -p minimald min_internal_absent_from_certs_and_audit
  <!-- S1a/AC3; prose 4; ubiquitous -->

- **NET-008** WHILE the host is enrolled THE SYSTEM SHALL list tenant-zone names before local names in `min net dns` and in box listings.
  tier:     T0
  verify:   cargo nextest run -p minimal dns_listing_prefers_tenant_zone_when_enrolled
  <!-- S1a/AC3; prose 4; state-driven -->

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

- **NET-018** WHERE native resolution and identity-published ports are both deployed on the host THE SYSTEM SHALL report native DNS as the live name surface in `min session activate` and `min ls`.
  tier:     T0
  verify:   cargo nextest run -p minimal activate_and_ls_report_native_surface
  <!-- S1b-3; prose 12; optional-feature -->

- **NET-019** WHERE native resolution and identity-published ports are both deployed on the host THE SYSTEM SHALL keep the hostname proxy serving.
  tier:     T0
  verify:   cargo nextest run -p minimald proxy_keeps_serving_after_supersession
  <!-- S1b-3; prose 12; optional-feature; interview decision -->

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

- **NET-028** IF `min net expose --public <port>` is run on a host with no gateway association and no fabric-native ingress THEN THE SYSTEM SHALL fail with "public exposure is not available on this host" and change nothing.
  tier:     T0
  verify:   cargo nextest run -p minimal expose_public_unavailable_fails_cleanly
  <!-- S3a/AC1; prose 18; unwanted -->

- **NET-029** WHERE public exposure is available THE SYSTEM SHALL create a public exposure only after an ExposeIngress authorization.
  tier:     T0
  verify:   cargo nextest run -p minimald public_exposure_requires_authorization
  <!-- S3a/AC2; prose 19; optional-feature -->

- **NET-030** WHERE public exposure is available THE SYSTEM SHALL list each live public exposure in `min session policy`.
  tier:     T0
  verify:   cargo nextest run -p minimal policy_lists_public_exposure
  <!-- S3a/AC2; prose 19; optional-feature -->

- **NET-031** WHERE public exposure is available THE SYSTEM SHALL audit each public exposure.
  tier:     T0
  verify:   cargo nextest run -p minimald public_exposure_audited
  <!-- S3a/AC2; prose 19; optional-feature -->

- **NET-032** WHEN a box or its exposure entry is removed THE SYSTEM SHALL tear its public exposure down within 5 seconds.
  tier:     T0
  verify:   cargo nextest run -p minimald exposure_torn_down_on_removal
  <!-- S3a/AC3; prose 20; event-driven; bound decided at checkpoint 2 -->

- **NET-033** WHERE the host holds a gateway association, WHEN a feed-carried ingress entry for one of its boxes arrives THE SYSTEM SHALL deliver connections on that exposure to the in-box listener per the box's ingress rules.
  tier:     T0
  verify:   cargo nextest run -p minimald feed_ingress_entry_delivered_to_listener
  <!-- S3b/AC1; prose 21; feature+event -->

- **NET-034** WHERE the provider declares fabric-native gateway ingress THE SYSTEM SHALL serve the same exposure without a gateway hop.
  tier:     T0
  verify:   cargo nextest run -p minimald fabric_native_ingress_serves_exposure
  <!-- S3b/AC2; prose 22; optional-feature -->

- **NET-035** THE SYSTEM SHALL show `--network none|host_ip|own_ip` and `--ingress` in `min session activate --help`.
  tier:     T0
  verify:   cargo nextest run -p minimal activate_help_shows_network_flags
  <!-- S4a/AC1; prose 23; ubiquitous -->

- **NET-036** THE SYSTEM SHALL document `--network` and `--ingress` in the CLI reference.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_reference_documents_network_flags
  <!-- S4a/AC1; prose 23; ubiquitous -->

- **NET-037** WHEN `--network host-net` or `--network own-ip` is given THE SYSTEM SHALL accept it as the new spelling and print a hint.
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

- **NET-042** WHERE the host is enrolled, WHEN `min net expose <port>` is run inside a box THE SYSTEM SHALL carry the request over the box's identity socket to be authorized as ExposeIngress at the feed write.
  tier:     T0
  verify:   cargo nextest run -p minimald expose_enrolled_rides_identity_sock
  <!-- S5/AC1; prose 28; feature+event -->

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

- **NET-086** WHERE the host holds a gateway association THE SYSTEM SHALL route all egress into the association.
  tier:     T0
  verify:   cargo nextest run -p minimald gateway_attached_routes_all_egress
  <!-- S10b/AC1; prose 55; optional-feature -->

- **NET-087** WHERE the host holds a gateway association THE SYSTEM SHALL preserve each own-address box's source address into the association without NAT.
  tier:     T0
  verify:   cargo nextest run -p minimald own_ip_source_preserved_into_association
  <!-- S10b/AC1; prose 55; optional-feature -->

- **NET-088** WHERE the host holds a gateway association THE SYSTEM SHALL source node-netns flows from the node-plane address and host-address cohort flows from the cohort address.
  tier:     T0
  verify:   cargo nextest run -p minimald node_netns_flows_snat_two_addresses
  <!-- S10b/AC1-2; prose 55, 56; optional-feature -->

- **NET-089** WHERE the host holds a gateway association, IF a process with root on the host spoofs another box's address THEN THE SYSTEM SHALL confine its reach, at the gateway, to the union of resident boxes' declared egress plus the baseline set.
  tier:     T0
  verify:   cargo nextest run -p minimald escape_bounded_at_gateway
  <!-- S10b/AC1; prose 55; feature+unwanted -->

- **NET-090** WHERE the host holds a gateway association THE SYSTEM SHALL take its baseline set from the deployment configuration.
  tier:     T0
  verify:   cargo nextest run -p minimald baseline_set_from_deployment_config
  <!-- S10b/AC2; prose 56; optional-feature -->

- **NET-091** WHERE the host holds a gateway association THE SYSTEM SHALL consume the signed policy feed and reject any sequence regression.
  tier:     T2
  verify:   cargo nextest run -p minimald feed_seq_regression_rejected
  property: for every incoming sequence number and every persisted high-water, a feed whose sequence is not greater than the high-water is rejected
  harness:  kani_feed_seq_regression_rejected, exhaustive to an unwind bound of 1 over two 64-bit sequence values; requires the accept/reject decision to be a pure function over the two values, separate from fetch and persistence
  <!-- S10b/AC3; prose 57; optional-feature -->

- **NET-092** WHERE the host holds a gateway association THE SYSTEM SHALL persist the feed high-water and, on start, refuse to serve until it reloads it or fetches a fresh feed.
  tier:     T0
  verify:   cargo nextest run -p minimald feed_fail_closed_on_start
  <!-- S10b/AC3; prose 57; optional-feature -->

- **NET-093** WHERE the host is enrolled, WHEN the `min` client enrols a VM-backed laptop host as its provider THE SYSTEM SHALL assert `egress_pin = pinned`.
  tier:     T0
  verify:   cargo nextest run -p minimal localvm_provider_asserts_pinned
  <!-- S11a/AC1; prose 58; feature+event -->

- **NET-094** WHERE the host is enrolled, WHEN the `min` client enrols a shared Linux host THE SYSTEM SHALL assert an `egress_pin` of `advisory` or `none`.
  tier:     T0
  verify:   cargo nextest run -p minimal shared_linux_asserts_advisory_or_none
  <!-- S11a/AC1; prose 58; feature+event -->

- **NET-095** WHERE the host is enrolled, IF creation of a box is refused for the host's pin THEN THE SYSTEM SHALL surface the audited error to the user with the pin named.
  tier:     T0
  verify:   cargo nextest run -p minimal min_surfaces_pin_refusal
  <!-- S11a/AC2; prose 59; feature+unwanted -->

- **NET-096** WHERE the host is enrolled and records a ceiling, IF a box's egress exceeds it THEN THE SYSTEM SHALL fail creation naming the offending rule.
  tier:     T0
  verify:   cargo nextest run -p minimal ceiling_violation_names_rule
  <!-- S11b/AC1; prose 60; feature+unwanted -->

- **NET-097** WHERE the host is enrolled with no public address and default-deny inbound THE SYSTEM SHALL receive its policy feed.
  tier:     T0
  verify:   cargo nextest run -p minimald outbound_only_host_receives_feed
  <!-- S15/AC1; prose 61; optional-feature -->

- **NET-098** WHERE the host is enrolled with no public address and default-deny inbound THE SYSTEM SHALL be reachable through the relay tier from a client on another network.
  tier:     T0
  verify:   cargo nextest run -p minimald outbound_only_host_reachable_via_relay
  <!-- S15/AC1; prose 61; optional-feature -->

- **NET-099** WHERE only TCP/443 egress exists THE SYSTEM SHALL run the gateway association as WireGuard over WebSocket.
  tier:     T0
  verify:   cargo nextest run -p minimald association_falls_back_to_wss
  <!-- S15/AC2; prose 62; optional-feature -->

- **NET-100** WHERE the host is enrolled THE SYSTEM SHALL accept its address blocks from the control plane and assign box addresses within them.
  tier:     T0
  verify:   cargo nextest run -p minimald enrolled_host_assigns_within_blocks
  <!-- S17/AC1; prose 64; optional-feature -->

- **NET-101** WHERE the host is enrolled THE SYSTEM SHALL report box address assignments on the heartbeat.
  tier:     T0
  verify:   cargo nextest run -p minimald assignments_reported_on_heartbeat
  <!-- S17/AC1; prose 64; optional-feature -->

- **NET-102** WHERE the host is un-enrolled THE SYSTEM SHALL self-allocate box addresses from the default plan.
  tier:     T0
  verify:   cargo nextest run -p switch unenrolled_self_allocates_default_plan
  <!-- S17/AC1; prose 64; optional-feature -->

- **NET-103** WHEN a host is renumbered THE SYSTEM SHALL keep every certificate, mesh identity, and audit correlation valid.
  tier:     T0
  verify:   cargo nextest run -p minimald renumber_preserves_identity
  <!-- S17/AC2; prose 65; event-driven -->

- **NET-104** WHEN `min net forward <box> <local>:<port>` is run THE SYSTEM SHALL open a local listener relayed over the session's SSH channel so that a request to `localhost:<local>` returns the in-box server's response.
  tier:     T0
  verify:   cargo nextest run -p minimal net_forward_relays_over_ssh_channel
  <!-- S12/AC1-2; prose 66; event-driven -->

- **NET-105** WHEN the session closes THE SYSTEM SHALL close the forward's listener.
  tier:     T0
  verify:   cargo nextest run -p minimal net_forward_closes_with_session
  <!-- S12/AC2; prose 66; event-driven -->

- **NET-106** WHERE a remote session is established THE SYSTEM SHALL serve `min net forward` against the remote host as it does a local one.
  tier:     T0
  verify:   cargo nextest run -p minimal net_forward_remote_host
  <!-- S12/AC3; prose 67; optional-feature -->

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

- **NET-112** WHERE the host is enrolled, WHEN `min net mesh join` is run THE SYSTEM SHALL enrol the laptop under its signed-in identity with no manual key exchange.
  tier:     T0
  verify:   cargo nextest run -p minimal mesh_join_uses_signed_in_identity
  <!-- S13/AC1; prose 73; feature+event -->

- **NET-113** WHERE the host is enrolled, WHEN the laptop joins a mesh THE SYSTEM SHALL receive peers, keys, endpoints, and relay assignment as signed peer documents.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_join_receives_peer_documents
  <!-- S13/AC1; prose 73; feature+event -->

- **NET-114** WHERE the laptop has joined a mesh THE SYSTEM SHALL route a request to `<name>.<node>.box.<td>:<port>` to an own-address box on a remote host.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_reaches_remote_box_by_name
  <!-- S13/AC2; prose 74; optional-feature -->

- **NET-115** WHERE the laptop has joined a mesh THE SYSTEM SHALL show peers with their last handshake in `min net status`.
  tier:     T0
  verify:   cargo nextest run -p minimal net_status_shows_peers_handshake
  <!-- S13/AC3; prose 75; optional-feature -->

- **NET-116** WHERE the laptop has joined a mesh, WHEN `min net mesh leave` is run THE SYSTEM SHALL remove the laptop from the mesh within the revocation window.
  tier:     T0
  verify:   cargo nextest run -p minimal mesh_leave_within_revocation_window
  <!-- S13/AC3; prose 75; feature+event -->

- **NET-117** WHERE the host is enrolled THE SYSTEM SHALL bring up the mesh from its peer-document mirror.
  tier:     T0
  verify:   cargo nextest run -p minimald mesh_from_peer_document_mirror
  <!-- S13/slices; prose 76; optional-feature -->

- **NET-118** WHERE the host is enrolled THE SYSTEM SHALL admit a mesh peer only against a valid, unexpired binding and re-validate it on rekey.
  tier:     T0
  verify:   cargo nextest run -p minimald peer_admitted_only_with_valid_binding
  <!-- S13/slices; prose 76; optional-feature -->

- **NET-119** WHERE the laptop has joined a mesh THE SYSTEM SHALL resolve tenant-zone box names locally.
  tier:     T0
  verify:   cargo nextest run -p minimald laptop_resolves_tenant_zone_locally
  <!-- S13/slices; prose 77; optional-feature -->

## Non-goals

- Box-to-box reach across hosts by named-network grant (the epic's remote
  box-to-box story): the grant model for it is an architecture ruling that has
  not been made; it returns as its own document once the ruling exists. The
  mesh transport it would ride is NET-112 to NET-119.
- An operator recipe for pods as box hosts (default-deny NetworkPolicy plus
  allow-to-gateway, Kata as the recommended runtime): the Box Provider API's
  operator documentation, once a provider implements the pod style.
- Choosing how a box's credentialed traffic finds the credential broker
  (steering mode and HTTP/3 posture): the credential-broker document; the
  fields live in the box's `[network]` section but the behaviour is the broker's.
- Host enrollment, the node record's creation, host listing, and revocation:
  the host-enrollment document. This document assumes an enrolled host where a
  requirement says WHERE the host is enrolled.
- Certificate-authenticated remote attach from the CLI: the remote-attach
  document. NET-106 assumes a remote session it does not establish.
- The relay tier and the browser `min` client: the remote-substrate documents.
  NET-098 assumes a relay tier it does not build.
- Sealed secrets and the credential broker: the broker document.
- The schema of the box spec's `[network]` fields: the box-spec document.
  NET-060 binds acceptance of two fields, not the schema.
- The Egress Gateway itself: its contract is the architecture of record; its
  implementation is the gateway component. This document binds the box host's
  obligations toward it (NET-086 to NET-092).
- The policy feed, ingress-entry authorization, node attributes, address
  allocation, mesh bindings, and peer documents on the identity plane: the
  sibling document
  [NPOL](https://github.com/gominimal/gatehouse/blob/main/docs/specs/02-spec-network-policy-plane/02-spec-network-policy-plane.md).
- Release notes stating the install-size growth, and documentation naming the
  exact outbound destinations a box host needs: deliverables of the plan for
  the VM-stack and outbound-only slices.
- Retiring `<name>.local.min.internal`, the literal host address, the legacy
  flag spellings, and the deny-all opt-out after one release: ordering facts
  recorded in the plan; the requirements here bind the compatibility behaviour
  while it exists.

## Design reasoning

**Two documents, not one.** The gateway-side halves of public exposure,
dynamic ingress, the pin and ceiling, address allocation, and mesh peers are
the identity plane's to implement, so they are bound in a sibling document in
that repository rather than restated here. A single document was considered
and rejected: it would bind identity-plane behaviour in a repository that does
not implement it.

**Every deployment style, scoped by WHERE.** Requirements are written against
the box host, not the laptop, and style-specific behaviour is scoped with
`WHERE the host is VM-backed`, `WHERE the host holds a gateway association`,
`WHERE the host is enrolled`, and `WHERE the provider declares fabric-native
gateway ingress`. A laptop-only document with the other styles as non-goals was
considered; it would have removed nine stories and forced a second document
when the first cloud host arrives. The laptop is the first host, not the only
one, and the architecture maps all five styles to one contract
([design §7](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).
Until the counterpart (enrollment, the association contract, a provider
capability) exists on a host, the test for a WHERE-scoped requirement is
skipped by its precondition; that ordering lives in the plan, not in the tier.

**A box outlives its client.** NET-015 states that a box runs from activation
until destroy whether or not a client is attached. Two alternatives were
considered: leaving box lifetime an open question and scoping port-on-listen to
a running box, or tying box lifetime to the attached client as today. The
first would have left the unattended-box story unsized; the second makes
"the name works whether or not a client is attached" narrower than the epic
wrote it. The chosen shape makes port publication unconditional and coheres
with the closed-laptop story elsewhere; the idle and stop policy that follows
from it is an open question below.

**The proxy keeps running after native resolution supersedes it.** NET-018 and
NET-019 make tooling report native DNS as the live surface while the hostname
proxy keeps serving. Stopping the listener was considered and rejected: it
breaks anything that captured a proxy URL, and two-daemon hosts would need
port discovery to handle an absent listener. The enforcement-parity rule
applies to the proxy for as long as it serves
([design §7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)).

**Names through the shipped proxy are the first slice.** Retiring the reverse
proxy first was considered because it heads the epic's order of work, but a
removal runs nothing end to end. Unhiding the flags on a stock install was the
other candidate; the naming story is what the epic's summary leads with.

**Mesh join is in scope; remote box-to-box is not.** The laptop mesh story
carries its own normative source for bindings and peer documents, so it is
bound here (NET-112 to NET-119) and in the sibling. The remote box-to-box story
needs a grant model that does not exist and stays a non-goal with that
destination.

**The rollout window is bound, not just the end state.** NET-076 and NET-077
bind the announcement and the opt-out flag for the deny-all default because
both are observable; recording the window only in the plan was considered and
rejected as leaving the opt-out flag unbound.

**Bounds that were chosen here.** Public exposures are torn down within
5 seconds (NET-032); no bound and a 60-second bound were the alternatives.
"Local-only" for `*.min.internal` means the zone is answered only to lookups
that originate on the machine (NET-006); answering only loopback addresses was
the weaker reading considered.

**Lane stories are product behaviours.** The maintainer's lane-assertion story
became NET-107 and NET-108, whose named tests are the lane assertions; keeping
it as a test-suite obligation outside the requirements was considered and
rejected because nothing in the document would then bind that the lanes
assert it.

**Tiers.** Every frame-level admit-or-drop decision (NET-016's failure case,
NET-062, NET-064, NET-069, NET-070, NET-081's failure case, NET-084), the
rebinding intersection (NET-067), feed regression (NET-091), and loopback
allocation (NET-010) are T2: each is a decision separable from its I/O, and the
tier constrains the daemon to keep it a pure function so a Kani harness can
exhaust it on the lane that runs today. Proxy parity (NET-071) is T1 and adds a
property-test dependency the workspace does not have; that cost was accepted.
T3 was refused for every candidate: the effect shells are async relay tasks,
sockets, and a VM boundary, which fail the no-concurrency constraint, and the
repository has no Lean project. The escape bound (NET-085, NET-089) stays a T0
system test with a root-in-VM spoofer; its universal is the invariant below,
covered by the frame core.

**Cross-cutting decisions live in the architecture.** The two-address
node-netns split, the residency clamp, DNS-pinned FQDN rules with the rebinding
defence, and the degraded-mode profile are
[design §4.1, §4.3, §5.3, and §7.1](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md);
the `ExposeIngress` action and peer documents are
[Gatehouse §6.11 and §6.9](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md).
This document binds the box host's observable behaviour under them and restates
none of them.

**Generality:** a second provider or platform fits without rewording: every
requirement names the box host, the daemon, the `min` client, or the installer,
and style-specific behaviour is scoped by WHERE. What breaks if a style has no
external enforcement point is honesty, not the document: such a host asserts
an `egress_pin` of `advisory` or `none` (NET-094) and policy can keep
secret-bearing boxes off it.

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
  without `CAP_NET_RAW`, the relay's source-address check, guest IPv6 disabled,
  and, where a gateway is attached, the gateway's residency clamp
  ([design §4.3 rule 0 and §8](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md))
  covered by: NET-081, NET-082, NET-083, NET-084, NET-085, NET-089
- **Invariant:** THE SYSTEM SHALL admit for a name only addresses that name
  resolved to, intersected with the box's denies and the infrastructure deny
  set.
  enforced by: the rebinding intersection
  covered by: NET-066, NET-067
- **Invariant:** THE SYSTEM SHALL create a public exposure only under an
  ExposeIngress authorization.
  enforced by: exposures exist only as authorized entries; the un-enrolled
  path evaluates the same request shape locally and audits it
  covered by: NET-029, NET-031, NET-042, NET-043, NET-046
- **Invariant:** THE SYSTEM SHALL keep local names out of every certificate
  and audit record and off every other host.
  enforced by: the local answerer serves on-machine lookups only
  covered by: NET-006, NET-007
- **Invariant:** THE SYSTEM SHALL accept no policy feed whose sequence number
  does not exceed the persisted high-water, and serve none before the
  high-water is reloaded or a fresh feed fetched.
  enforced by: the feed consumer's accept decision and persisted high-water
  covered by: NET-091, NET-092
- **Invariant:** THE SYSTEM SHALL admit a mesh peer only against a valid,
  unexpired binding.
  enforced by: the daemon validates bindings, and treats peer documents as
  configuration, never authorization
  covered by: NET-118

## Open questions

- [NEEDS CLARIFICATION (CRITICAL): what is the node-to-gateway association
  contract: the registration shape, the heartbeat member that carries it, and
  the feed's normative field set? NET-086 to NET-092 and NET-097 to NET-099
  bind behaviour against a contract the architecture marks as a working shape.]
- [NEEDS CLARIFICATION (HIGH): how does each host OS resolve the box zone
  natively? The Linux routing-domain answer needs a routable-scope link
  address; the macOS resolver hangs for 60 seconds when the answerer is down
  and the resolver timeout key is untested. Both rulings are open in the
  architecture; NET-009 binds the outcome, not the mechanism.]
- [NEEDS CLARIFICATION (HIGH): when does macOS take the privileged step that
  per-box loopback addresses need: once at install, at first activate, or never
  (sharing one address with port translation)? An architecture ruling has been
  requested; NET-010 binds distinct addresses on every platform.]
- [NEEDS CLARIFICATION (MEDIUM): what is the cgroup layout for the two-address
  classifier, and are host-address boxes on a shared Linux host in scope of
  NET-078 to NET-080? Both need architecture confirmation.]
- [NEEDS CLARIFICATION (MEDIUM): with a box outliving its client (NET-015),
  who owns the idle and stop policy, and how does it compose with the
  closed-laptop story in the remote-substrate work?]
- [NEEDS CLARIFICATION (MEDIUM): what is the grant model for box-to-box reach
  across hosts (provider, named network, identity)? It blocks the non-goal
  above, not any requirement here.]
- [NEEDS CLARIFICATION (LOW): are HTTP/2 and HTTP/3 through any proxy surface
  in scope? The architecture leaves them unaddressed.]
