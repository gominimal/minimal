---
id: CRA
title: Remote attach with certificates
owner: mitodrummer
epic: gominimal/inbox#513
arch: https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md
updated: 2026-09-10
---

# CRA — Remote attach with certificates

## Context

Today the CLI attaches to a session only over the daemon's local socket, and
the daemon refuses every connection that does not arrive that way. A Box Host
a provider creates, or a developer's second machine, has sessions nobody can
reach. The pieces around the gap are designed: the identity plane issues an
SSH user certificate at sign-in and renews it, and the architecture of record
says a box is reached by talking to its Box Host's daemon directly, over SSH
with those certificates ([Box Provider API §1](https://github.com/gominimal/arch/blob/main/specs/box-provider/box-provider-api.md)).
What no document states is either side of that attach: what the CLI presents
and checks, and what the daemon accepts, refuses and ends.

This spec states both, CLI first. The Box Provider abstraction hands out a
host's connection metadata and stops there; this is the attach that uses it.
The browser client is a later addition on the same foundation.

After this ships, a developer signs in once and works with sessions on any
daemon enrolled with the identity plane the way they work with local ones,
and a session outlives the laptop that started it.

**Success:** a developer on a machine with no `ssh` installed signs in once,
then lists, attaches to, renames and stops sessions on a remote Box Host and
on another of their own enrolled machines with the same commands as local
ones; a dropped connection leaves each session running detached, and a
revoked certificate loses its access within a second of the daemon learning
of it.

**First slice:** one remote Box Host, reached at the SSH endpoint its
provider publishes. The CLI attaches in process with its sign-in certificate
and checks the host's certificate; the daemon admits the certificate to its
owner's sessions only; a dropped connection re-attaches. The revocation feed
(CRA-029, CRA-030) is a configured option that follows with the identity
plane's revocation work, without changing the attach.

## Users and stories

**Roles:** developers who run long workflows in sessions and need them to
outlive their laptop, and developers who run sessions both locally and on
remote machines and want one way to work with all of them.

- AS A developer who deploys long running workflow in sessions, I WANT my sessions to stay active when my laptop is closed or asleep, SO THAT my workflow can successfully complete its objective without interruption or retries.
  <!-- Acceptance criteria, for the EARS step:
       - Processes in the session remain continuously active, and the session is in a state equivalent to detached, not exited.
  -->
- AS A developer running sessions both locally and remote, I WANT to enumerate and reconnect with remote sessions just like local sessions, SO THAT I can work with all my sessions the same way.
  <!-- Acceptance criteria, for the EARS step:
       - Remote boxes are enumerable and attachable through the same CLI surface as local ones.
  -->

The epic's other stories belong to siblings. Specifying a box's CPU and
memory is the Box Provider abstraction's, with its criteria deferred to
gominimal/inbox#570. Enumerating remote *boxes* is the Box Provider
abstraction's inventory; enumerating and attaching to their *sessions* is
this spec's. Monitoring a session from a browser is the browser client's,
built on this one. Copying files out of a box has no spec; see Open
questions. The epic's residue items, R9 and R12, are routed by the Box
Provider abstraction and add nothing here.

## Requirements

"Non-local" means any connection other than the daemon's local socket or
vsock. Certificate shapes, principals and lifetimes are the identity plane's
([Gatehouse §5.3, §5.7](https://github.com/gominimal/arch/blob/main/specs/authn-authz/gatehouse-spec.md));
the requirements cite them rather than restate them.

### The CLI's credential

- **CRA-001** THE SYSTEM SHALL authenticate a non-local attach with the SSH
  user certificate the identity plane issued at sign-in and the key it
  certifies, and with no other credential (sign-in is GHS-006; the
  certificate is Gatehouse §6.6).
  tier:     T0
  verify:   cargo nextest run -p minimal-client remote_attach_offers_only_the_signin_certificate

- **CRA-002** WHILE the CLI holds a refresh token THE SYSTEM SHALL renew the
  SSH user certificate before it expires, with no browser step and no open
  attach required (Gatehouse §5.7).
  tier:     T0
  verify:   cargo nextest run -p minimal-client certificate_renews_before_expiry_without_attach

- **CRA-003** THE SYSTEM SHALL keep the CLI's signing key in the operating
  system's credential store, held for this device only, and use it for no
  process other than the CLI.
  tier:     T0
  verify:   cargo nextest run -p minimal-client cli_key_lives_in_the_os_store_for_this_device

- **CRA-031** THE SYSTEM SHALL place neither the CLI's signing key nor its
  refresh token in any session, local or remote, whether as a file, an
  environment variable or a forwarded agent.
  tier:     T0
  verify:   cargo nextest run -p minimal cli_credentials_reach_no_session

### Checking the daemon is genuine

- **CRA-004** IF a non-local daemon's host certificate does not verify under
  the issuer's Host CA for the name the CLI dialed THEN THE SYSTEM SHALL
  abort the attach before authenticating, report the failure, and offer no
  way to accept the key instead (Gatehouse §6.2).
  tier:     T0
  verify:   cargo nextest run -p minimal-client unverified_host_aborts_before_auth_with_no_override

- **CRA-005** THE SYSTEM SHALL take Host CA anchors only from the issuer
  named in the credential the CLI holds (Gatehouse §8.2).
  tier:     T0
  verify:   cargo nextest run -p minimal-client host_ca_anchors_come_only_from_the_credential_issuer

- **CRA-006** IF the CLI holds no Host CA anchors THEN THE SYSTEM SHALL
  attempt no non-local attach.
  tier:     T0
  verify:   cargo nextest run -p minimal-client no_anchors_means_no_remote_attach

- **CRA-007** IF a daemon presents a host certificate the identity plane's
  certificate vectors mark invalid THEN THE SYSTEM SHALL refuse it with the
  vector's named reason.
  tier:     T0
  verify:   cargo nextest run -p minimal-client host_certificate_vectors_refused_with_named_reason

- **CRA-008** WHERE the connection is the daemon's local socket or vsock THE
  SYSTEM SHALL connect the CLI and the daemon with no certificate on either
  side.
  tier:     T0
  verify:   cargo nextest run -p minimald local_socket_and_vsock_need_no_certificate

### Same commands, local or remote

- **CRA-009** THE SYSTEM SHALL accept `min session attach`, `ls`, `rename`
  and `stop` for a session on a remote daemon with the same arguments and
  output as for a local one.
  tier:     T0
  verify:   cargo nextest run -p minimal remote_session_commands_match_local_grammar

- **CRA-010** THE SYSTEM SHALL attach to a remote session in process, with
  raw-mode terminal, resize and signal handling, on a machine with no `ssh`
  executable.
  tier:     T0
  verify:   cargo nextest run -p minimal remote_attach_runs_without_an_ssh_executable

- **CRA-011** WHEN the CLI connects to a daemon THE SYSTEM SHALL agree a
  protocol version before any session operation.
  tier:     T0
  verify:   cargo nextest run -p minimal-client protocol_version_agreed_before_session_ops

- **CRA-012** IF the daemon's protocol version is outside the range the CLI
  supports THEN THE SYSTEM SHALL refuse the connection, naming both versions
  and the remedy (the architecture's version skew paragraph).
  tier:     T0
  verify:   cargo nextest run -p minimal-client out_of_window_daemon_refused_with_both_versions

- **CRA-013** THE SYSTEM SHALL report for every session in `min session ls`
  whether it is attached, detached or exited, and when it was last active.
  tier:     T0
  verify:   cargo nextest run -p minimal ls_reports_attachment_state_and_last_activity

### Staying attached

- **CRA-014** WHEN a client attaches to a running session THE SYSTEM SHALL
  write, before any new output, a repaint of the current screen, the
  cursor's position and visibility, and the terminal modes the session has
  turned on.
  tier:     T0
  verify:   cargo nextest run -p minimald attach_repaints_screen_cursor_and_modes_first

- **CRA-015** WHEN a second client attaches to an attached session THE
  SYSTEM SHALL move the session to the new client and end the first client's
  attach with a superseded notice.
  tier:     T0
  verify:   cargo nextest run -p minimald second_attach_supersedes_the_first

- **CRA-016** WHEN the connection under an attached client ends without a
  detach THE SYSTEM SHALL keep the session's processes running and report it
  detached, never exited, within 5 s.
  tier:     T0
  verify:   cargo nextest run -p minimald dropped_client_leaves_session_detached_not_exited

- **CRA-017** WHEN a remote attach ends because the connection was lost or
  the certificate expired THE SYSTEM SHALL attach again, after 1 s and
  doubling the wait to at most 30 s, until it succeeds or the developer
  detaches.
  tier:     T0
  verify:   cargo nextest run -p minimal-client lost_attach_retries_1s_doubling_to_30s

### Who the daemon admits

- **CRA-018** WHERE the daemon is enrolled with an identity plane THE SYSTEM
  SHALL accept certificate-authenticated non-local connections with no
  further setting, on a developer's own machine as on a provider's host
  (Gatehouse §6.2).
  tier:     T0
  verify:   cargo nextest run -p minimald enrolled_daemon_accepts_remote_certificates_by_default

- **CRA-019** IF the daemon is not enrolled with an identity plane THEN THE
  SYSTEM SHALL accept no non-local connection and serve its local socket
  and vsock exactly as today.
  tier:     T0
  verify:   cargo nextest run -p minimald unenrolled_daemon_accepts_no_remote_connection

- **CRA-020** IF a non-local connection offers authentication other than a
  certificate THEN THE SYSTEM SHALL refuse it, naming public-key
  authentication as the method to use.
  tier:     T0
  verify:   cargo nextest run -p minimald non_certificate_auth_refused_naming_publickey

- **CRA-021** THE SYSTEM SHALL decide a user certificate from the
  certificate, the username, the clock, the trusted User CA keys and the
  revoked serials alone, accepting it only when it is a user certificate
  signed by a trusted User CA, within its validity allowing 60 s of clock
  skew, carrying the username as a principal, and not revoked.
  tier:     T0
  verify:   cargo nextest run -p minimald user_certificate_decided_from_five_inputs

- **CRA-022** IF a connection presents a user certificate the identity
  plane's certificate vectors mark invalid THEN THE SYSTEM SHALL refuse it
  with the vector's named reason.
  tier:     T0
  verify:   cargo nextest run -p minimald user_certificate_vectors_refused_with_named_reason

- **CRA-023** THE SYSTEM SHALL let a certificate-authenticated connection
  list, attach to, rename or stop only the sessions its subject owns: the
  subject whose connection created the session, or, for a session created
  over the local socket or vsock, the node's enrolling owner.
  tier:     T0
  verify:   cargo nextest run -p minimald certificate_connection_reaches_only_owned_sessions

- **CRA-024** THE SYSTEM SHALL present on every non-local connection a host
  certificate whose principals cover the node's canonical name and its
  per-node wildcard, and no tunnel address (Gatehouse §5.3).
  tier:     T0
  verify:   cargo nextest run -p minimald host_certificate_covers_canonical_and_wildcard_only

- **CRA-025** IF authentication fails on a non-local connection THEN THE
  SYSTEM SHALL answer the first refusal within 100 ms, delay each later
  refusal on that connection by at least 1 s, and close the connection after
  the third.
  tier:     T0
  verify:   cargo nextest run -p minimald failed_auth_throttled_then_closed_after_third

CRA-026 and CRA-027, the identity plane's per-connection check, were retired
on 2026-09-11 and are not reused; see Non-goals.

### Expiry and revocation

- **CRA-028** WHEN a certificate-authenticated connection reaches its
  certificate's expiry THE SYSTEM SHALL close it within 1 s, leave every
  session it was attached to running and detached, and end each attached
  channel with an expired notice.
  tier:     T0
  verify:   cargo nextest run -p minimald expiry_closes_connection_sessions_stay_detached

- **CRA-029** WHERE a revocation-list source is configured THE SYSTEM SHALL
  fetch it at least every 60 s and apply only a list signed by the issuer,
  for the daemon's own trust domain, newer than the last one it applied
  (`gatehouse-krl+jws`, Gatehouse §8.2).
  tier:     T0
  verify:   cargo nextest run -p minimald krl_applies_only_signed_newer_same_domain

- **CRA-030** WHEN an applied revocation list revokes a live connection's
  certificate THE SYSTEM SHALL close that connection within 1 s, ending each
  attached channel with a revoked notice.
  tier:     T0
  verify:   cargo nextest run -p minimald revoked_connection_closed_within_1s

## Non-goals

- Enumerating remote boxes, the providers that host them, host lifecycle and
  the connection metadata a host is reached by: the Box Provider abstraction
  and its endpoints spec (gominimal/arch#45, BPA and BPE). BPA-023 limits a
  provider to handing out that metadata; this spec starts where it stops.
- The identity plane checking each connection against current policy
  (`SshConnect`), and per-action decisions for stopping and renaming
  (`StopBox`, `RenameBox`): the policy follow-on of gominimal/inbox#648 (its
  S5), which arrives with its own epic and spec rather than partially. When
  it lands, an identity plane that cannot be reached refuses the attach, as
  decided on 2026-09-10.
- A CLI key held in hardware: the follow-on S6 of gominimal/inbox#648. The
  identity plane certifies P-256 user keys, the ones hardware keystores hold,
  only under its FIPS profile (Gatehouse §5.3, N7).
- The path to a remote daemon, whether a published endpoint, the mesh or a
  relay and Egress Gateway: the networking work, designed in
  [deployment-and-egress-gateway.md](https://github.com/gominimal/arch/blob/main/specs/networking/deployment-and-egress-gateway.md)
  and to be specified in its own spec. The daemon's mesh-ingress half is
  drafted in [MMI](../14-spec-minimald-mesh-ingress/14-spec-minimald-mesh-ingress.md)
  until then.
- Issuing, renewing and revoking certificates on the identity plane's side,
  and the CLI's sign-in ceremony: the identity plane's spec (gominimal/gatehouse#1,
  GHI) and [GHS](../12-spec-github-sessions/12-spec-github-sessions.md).
- Attaching from a browser: the browser client
  ([MCC](../13-spec-min-client-core/13-spec-min-client-core.md) and
  gominimal/webapp#763), on hold until this spec lands, and built on it.
- Two developers in one session: ruled out on 2026-08-20, so the daemon
  admits a session's owner only (CRA-023).
- Copying files out of a box, the epic's sync-out story: no spec. See Open
  questions.
- What the CLI does at sign-out: see Open questions.
- Specifying a box's resources: the Box Provider abstraction and
  gominimal/inbox#570.
- Pushing a running local session to a remote host: parked by the epic under
  its Negotiable heading.

## Design reasoning

**Why a spec of its own, CLI first.** The certificate path is what every
remote attach needs, the CLI's included, and the browser client is an
addition on top of it rather than the reason for it. So the attach is
specified here, for the CLI, and the browser specs wait for it.

**One spec for both halves.** The CLI's half and the daemon's half are two
ends of one protocol, and they sit in the same place. The identity plane's
per-connection check and revocation feed are consumed as the identity plane
defines them, so a second, identity-plane-side sibling was considered and not
taken.

**Any enrolled daemon, a developer's own machine included.** The narrower
readings were considered: only hosts a provider created, with a laptop
staying on its local socket, or only Minimal-hosted boxes for now. The widest
was chosen. Enrolling is the opt-in, so an enrolled daemon accepts remote
certificates with no further setting (CRA-018), and a daemon that is not
enrolled accepts no remote connection at all (CRA-019). Asking for a second
setting after enrolment, so that enrolling never opens a listener by itself,
was offered and declined; so was letting hand-configured trust anchors stand
in for enrolment, which would have made a second way in. How a remote client
reaches a laptop is the networking work's.

**No `ssh` required.** The first version could have kept the system `ssh`
client, which already speaks user and host certificates, and deferred an
in-process client to the browser build. The in-process client was chosen now
(CRA-010), because it is the foundation the browser build reuses and it
removes a dependency developers otherwise need.

**Reconnect until back or detached.** A dropped attach retries on its own
(CRA-017), which suits long agent runs. Exiting on every drop, and retrying
for a bounded window before exiting, were the alternatives.

**Key custody this cycle, hardware later.** The CLI's key signs both SSH
authentication and the proofs that make its refresh token usable, so the key,
not the token, is what must not travel: neither reaches a session (CRA-031),
which closes the paths a dotfile loadout or a forwarded agent would otherwise
open (Gatehouse T20). A signer that never releases the key, hardware-backed
where the machine has it, was the preferred form, because the browser client
meets the same contract with a non-extractable WebCrypto key. It waits for
the identity plane to certify P-256 user keys outside its FIPS profile, which
moved to a follow-on on 2026-09-11, so this cycle keeps the key in the
operating system's credential store for this device (CRA-003). Naming only
where the key is stored was the other form considered. The refresh token is
bound to the key (Gatehouse T1), so no requirement fixes where the token
itself is stored.

**Everything at T0.** Three groups were offered above T0: the certificate
vectors (CRA-007, CRA-022) walked over the whole manifest, the user
certificate rule (CRA-021) as a property test or a Kani harness, and owner-only
admission (CRA-023) enumerated or proved, since its domain is small. Each was
declined in favour of named tests. T3 was ruled out because signature checking
runs through cryptography outside the safe Rust subset Aeneas takes, and the
CLI and daemon repository has no Lean project.

**Generality:** any daemon enrolled with the identity plane is attached the
same way, whether a provider created its host or it runs on a developer's own
machine; what differs is only the connection metadata a provider hands out
and the path the networking layer supplies. A second SSH client, such as the
browser build, fits by meeting CRA-001, CRA-002, CRA-004 to CRA-008, CRA-011,
CRA-012 and CRA-031 unchanged, with key custody of its own in place of
CRA-003.

## Security considerations

- **Invariant:** THE SYSTEM SHALL attach to no non-local daemon whose host
  certificate does not verify under the issuer's Host CA for the name the
  CLI dialed.
  enforced by: the CLI's host check, with anchors from the credential's
  issuer only and no trust on first use (Gatehouse §6.2; T7)
  covered by: CRA-004, CRA-005, CRA-006, CRA-007

- **Invariant:** THE SYSTEM SHALL open no session channel on a non-local
  connection that did not authenticate with a valid user certificate.
  enforced by: the daemon's certificate-only authentication and its user
  certificate decision (T2)
  covered by: CRA-019, CRA-020, CRA-021, CRA-022

- **Invariant:** THE SYSTEM SHALL expose no session to a subject that does
  not own it.
  enforced by: the daemon's owner check on every list, attach, rename and
  stop
  covered by: CRA-023

- **Invariant:** THE SYSTEM SHALL let no process in a session sign with, or
  read, the CLI's signing key or its refresh token.
  enforced by: the operating system's credential store on the developer's
  machine, and no file, environment variable or forwarded agent carrying
  either into a session (Gatehouse T2, T20)
  covered by: CRA-003, CRA-031

- **Invariant:** THE SYSTEM SHALL end an expired or revoked certificate's
  access within 1 s of the daemon learning of it, leaving the sessions it
  reached running.
  enforced by: the daemon's expiry timer and revocation list (T2, T5, T14)
  covered by: CRA-028, CRA-029, CRA-030

## Open questions

- [NEEDS CLARIFICATION (HIGH): where does `min session ls` learn which remote
  daemons to ask: the providers' inventories, the identity plane's node
  listing, or both?] Survives because the two sources cover different
  daemons: provider-created hosts appear in their provider's inventory and,
  today, not in the identity plane's listing (gominimal/arch#47), while a
  developer's own enrolled machine appears only in the latter. The identity
  plane's listing covering both is gominimal/inbox#648's S3a; once it lands,
  one source may do.

- [NEEDS CLARIFICATION (HIGH): copying files or directories out of a box, the
  epic's sync-out story, has no spec in any repository.] Survives because it
  was kept out of this spec's scope and no other spec has taken it; the Box
  Provider abstraction records the same gap.

- [NEEDS CLARIFICATION (MEDIUM): how a remote daemon is reached beyond the
  SSH endpoint its provider publishes, a developer's own machine included.]
  Survives because the transport belongs to the networking spec, which does
  not exist yet; the first slice uses the published endpoint the Box
  Provider API names.

- [NEEDS CLARIFICATION (MEDIUM): what does the CLI do at sign-out?] Survives
  because it was kept out of this spec and neither the GitHub-sessions spec
  nor the identity plane's spec states it.

- [NEEDS CLARIFICATION (MEDIUM): how wide is the range of daemon protocol
  versions the CLI accepts?] Survives because the architecture records it as
  an open gap, and CRA-012 needs a range to refuse against.
