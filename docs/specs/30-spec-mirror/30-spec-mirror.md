---
id: MIR
title: Mirror — one copy per laptop of the package cache and the package repositories, which every client and every VM on the laptop reads, so boxes come up offline
owner: msample
epic: gominimal/inbox#TBD
arch: none
arch_sha: "none"
updated: 2026-10-21
---

# MIR — Mirror — one copy per laptop of the package cache and the package repositories, which every client and every VM on the laptop reads, so boxes come up offline

## Context

Before its shell paints, a box needs the package repository at the project's pinned commit and every repository the project's upstream chain and sideloads name. It also needs the cache index for the pinned commit and the artifact of every package it lists. All of that comes from the Internet or from an organization's network, and nothing on the laptop holds it for long. The host CLI and each daemon keep separate caches. Each VM keeps its daemon's cache on its own data volume, so a laptop with several VMs downloads each artifact once per VM, and a new VM starts with that volume empty. With no connection, `min init` in a fresh repository fails, and so does `min session activate`. Off the corporate VPN, a project that builds on an organization's private repositories and cache fails the same way. That holds for packages this laptop downloaded yesterday as much as for new ones. Demos on conference networks hit this first, and the local-first ordering that [NET](../18-spec-box-networking/18-spec-box-networking.md) and [BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md) record puts the laptop first.

After this work merges, one mirror per user on the laptop keeps a copy of what that user's clients fetch. The clients are the host CLI, `mip`, a native session daemon and the daemon in every VM. The mirror also keeps what the user's projects and loadouts need, across every hop of each project's upstream chain and its sideloads, and any packages the user asks it to keep. It stores everything under the origin the client asked for. A client keeps choosing its cache as it does today, and the mirror needs no map of which cache serves which repository. Online, or on the VPN, nothing changes for the user. Offline, or off the VPN, a new project and a new box come up from the copy, once the laptop was online with its mirror running. The mirror reads private repositories and private cache buckets with the user's own credentials, so a VM's daemon, which holds none, reads them too. Only the user's own processes and the daemons in the user's VMs reach the mirror, and no box does. The mirror keeps the signatures the publisher emits beside what they sign, so a client that checks them later can do so offline. The publisher's catalogue of one commit's artifacts is its closure, and a project pins to a commit whose closure the publisher sealed.

**Success:** `min mirror prepare` reports ready. Then the laptop's network interface goes down. `min init` in an empty git repository and `min session activate` reach a shell with the project's packages and the user's loadout packages. A second VM, and a new VM instance with an empty data volume, do the same, and the mirror's store holds one copy of each artifact. `min mirror status` says what the mirror holds, what it protects, which origins it last reached and whether the laptop is ready for offline.

**First slice:** the mirror daemon serves cache objects for any cache origin a client names, and copies of package repositories, on a Unix socket on the laptop. `min` starts it on demand. Every VM host daemon connects its guest's door to that socket, and the guest daemon reads its cache and its repositories through the door. `min mirror status` prints the daemon, origin, disk and repository lines. The mirror holds what clients fetched through it, within the default budget: MIR-001 to MIR-005, MIR-007 to MIR-013, MIR-014 without its credential exception, MIR-020 without its registration step, MIR-021 to MIR-026, MIR-040, MIR-044, MIR-062 to MIR-064, MIR-070, MIR-073 and MIR-080 to MIR-083. Private sources, project registration and the chain walk, the planner, `min mirror prepare`, the age rule, sealed pins and the trusted root follow.

## Users and stories

**Roles:** developers on a laptop who are sometimes offline, off their organization's VPN, or about to be, and who watch their disk. A reviewer of what a box and a VM can reach.

- AS A developer who is offline, I WANT `min init` and `min session activate` to work in a new repository from what this laptop holds, SO THAT I can start a project with no connection.
- AS A developer who is online, I WANT every fetch to pass through the mirror with no configuration, SO THAT what I used today is here tomorrow.
- AS A developer whose projects build on my organization's private repositories and cache, I WANT what I fetched on the VPN kept, SO THAT I can work off the VPN.
- AS A developer, I WANT every repository my projects' upstream chains and sideloads name kept, with no list to maintain, SO THAT a project with several hops comes up offline.
- AS A developer with several VMs, I WANT one copy of each artifact on the laptop, SO THAT a second VM, or a re-created one, costs no download.
- AS A developer about to go offline, I WANT one command that fills the mirror and names what is still missing, SO THAT I board the plane knowing.
- AS A developer, I WANT to name packages the mirror always keeps, SO THAT a demo of a stack I never used works offline.
- AS A developer, I WANT a disk budget and a warning when it is too small for what I asked to keep, SO THAT the mirror neither fills my disk nor drops my packages without a word.
- AS A developer, I WANT the signatures published for what I hold kept beside it, SO THAT verification works offline once the client performs it.
- AS A developer, I WANT my project pinned to a commit the build pipeline sealed, SO THAT I never build from source what the cache was meant to supply.
- AS A reviewer, I WANT no box to reach the mirror, and the mirror to use my credentials only for repositories and buckets I named from the laptop, SO THAT the mirror widens no box's reach and a VM cannot steer my credentials.

## Requirements

### O1 One daemon per laptop, keyed by origin, reached locally

One mirror runs per user on the laptop. It answers HTTP on a Unix socket in its state directory, the host socket. It answers the same requests on a vsock door in each VM, which that VM's host daemon connects to the host socket (MIR-023). The host CLI, `mip` and a native session daemon read the mirror through the host socket. The guest daemon reads it through its door. Every VM therefore shares one store.

A cache origin is the base URL a client reads a cache from, `https://<host>[:<port>]/[<segment>/...]`, written without its scheme and its trailing slash. `<host>` is a DNS name of lowercase letters, digits, `-` and `.`, and `<port>` is a decimal number from 1 to 65535. Each `<segment>` follows the segment rule below and is not `-`. The location `gs://<bucket>` is the origin `storage.googleapis.com/<bucket>`. Under the mount `/-/c/<origin>/-/`, the mirror serves the upstream cache's own keys. It fetches a key it does not hold from `https://<origin>/<key>`.

| Request path | Meaning | Lifetime |
|---|---|---|
| `/-/c/<origin>/-/index.shisha` | the origin's root index | mutable |
| `/-/c/<origin>/-/<slug>/<commit>.closure.shisha` | the sealed per-commit closure index | immutable |
| `/-/c/<origin>/-/<slug>/<commit>.shisha` | the per-commit snapshot index | immutable |
| `/-/c/<origin>/-/<slug>/<commit>.closure.shisha.sigstore.json`, `/-/c/<origin>/-/<slug>/<commit>.map.json` | companions of a closure | immutable |
| `/-/c/<origin>/-/<sha256>.zst` | one artifact, named by the sha256 of its bytes | immutable |
| `/-/git/<slug>/-/bundle` | a git bundle of every branch and tag of the repository copy (O2) | refreshed |
| `/-/sigstore/trusted_root.json` | the Sigstore public-good trusted root | refreshed |

`<slug>` is a repository URL with scheme, credentials, query, trailing slash and `.git` stripped, the form the index keys already use: a host, then one path segment or more. Each segment is one or more of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `.`, `_` and `-`, and no segment is `.` or `..`. `<commit>` is 40 hex digits and `<sha256>` is 64. The rows under `/-/c/` are cache objects. The literal segment `-` ends an origin and ends a slug, so a path parses one way only.

- **MIR-001** WHEN a request names a cache object the mirror holds THE SYSTEM SHALL answer with the bytes the mirror last stored for that key, which are bytes the origin served for it, unchanged.
  tier:     T1
  verify:   cargo nextest run -p minmirrord served_object_bytes_equal_origin
  property: the mirror answers a cache object key with its last stored body for that key. The origin that key names served that body.
  <!-- the mirror is a copy, never an interpreter: every integrity check the client does today (sha256 on artifacts) keeps its meaning, and a verifier added later reads the publisher's bytes. A repository bundle is git's own format, which git checks on receipt (MIR-013) -->

- **MIR-002** WHEN a request names an immutable cache object the mirror does not hold THE SYSTEM SHALL fetch it from the origin the path names, store it, and stream it to the client within the same request.
  tier:     T0
  verify:   cargo nextest run -p minmirrord immutable_miss_fetches_stores_and_streams
  <!-- pull-through: observed demand is the first source of what the mirror holds; a client never waits for a second request. The origin is whatever the client resolved, so a project on an organization's cache fills from that cache and the mirror holds no map of which cache serves which repository -->
  - THE SYSTEM SHALL treat a redirect from the origin as a status other than 200 or 404, following none.
    tier:   T0
    verify: cargo nextest run -p minmirrord origin_redirect_is_not_followed
    <!-- the mirror connects to the origin the path names and nowhere a redirect points -->
  - WHEN several clients request one object the mirror does not hold THE SYSTEM SHALL fetch it from the origin once.
    tier:   T0
    verify: cargo nextest run -p minmirrord concurrent_misses_fetch_once
    <!-- several VMs booting at once ask for the same artifacts -->
  - WHEN a HEAD request names an immutable cache object the mirror does not hold THE SYSTEM SHALL fetch and store it as for a GET and answer with the headers alone.
    tier:   T0
    verify: cargo nextest run -p minmirrord head_request_pulls_through
  - IF the origin answers 404 THEN THE SYSTEM SHALL answer 404 and record the absence with its time.
    tier:   T0
    verify: cargo nextest run -p minmirrord origin_absence_is_recorded
  - WHILE the mirror can reach the origin THE SYSTEM SHALL ask it again for a key whose absence record is older than 60 seconds, and answer 404 from the record otherwise.
    tier:   T0
    verify: cargo nextest run -p minmirrord absence_record_reasked_after_sixty_seconds
    <!-- a walk over many commits (MIR-050) asks the origin once per object, and a closure published later is found within a minute -->
  - WHEN the origin answers 200 for a key with an absence record THE SYSTEM SHALL drop the record.
    tier:   T0
    verify: cargo nextest run -p minmirrord absence_record_dropped_on_hit
  - IF the mirror cannot reach the origin and holds an absence record for the key THEN THE SYSTEM SHALL answer 404 from the record, however old it is.
    tier:   T0
    verify: cargo nextest run -p minmirrord remembered_absence_served_when_offline
    <!-- the sealed-pin walk (MIR-050) runs offline only because the sync recorded, while online, which closures do not exist (MIR-032); a 502 would end the walk -->
  - THE SYSTEM SHALL keep at most 100 000 absence records that requests caused, dropping the oldest first. A record a sync wrote (MIR-032) leaves when a later sync no longer visits its key.
    tier:   T0
    verify: cargo nextest run -p minmirrord absence_records_are_bounded
    <!-- a client can name any number of absent keys and the records it causes are bounded; a sync visits at most 64 keys per registered upstream link, so the records it writes are bounded by the registry -->
  - IF the mirror cannot reach the origin, or the origin answers a status other than 200 or 404, THEN THE SYSTEM SHALL answer 502 with the one-line body `the mirror could not reach https://<origin>/: <cause>` and store nothing.
    tier:   T0
    verify: cargo nextest run -p minmirrord origin_failure_is_502_and_stores_nothing
    <!-- the cache reader retries an artifact's error status with its backoff and then fails; an index fetch fails on the first error status; MIR-063 turns either failure into a message that names the mirror. A 404 on the root index the client reads as an empty index, and an artifact 404 is retried then fatal, so an outage must never become a 404 -->

- **MIR-003** WHEN the mirror fetches an artifact `<sha256>.zst` from an origin THE SYSTEM SHALL store it only when the sha256 of the received bytes equals its name.
  tier:     T0
  verify:   cargo nextest run -p minmirrord artifact_hash_mismatch_is_not_stored
  <!-- the mirror never serves a mismatched artifact from disk. An artifact is fetched by name alone: a gate that required a held index to name the sha256 first was dropped, see Design reasoning -->
  - IF the hash does not match THEN THE SYSTEM SHALL end the client's response before completion.
    tier:   T0
    verify: cargo nextest run -p minmirrord artifact_hash_mismatch_truncates_response
    <!-- the client hashes too and retries a truncated body -->

- **MIR-004** WHILE the held copy of an origin's `index.shisha` is younger than 5 minutes THE SYSTEM SHALL answer a request for it from that copy and contact no origin.
  tier:     T0
  verify:   cargo nextest run -p minmirrord root_index_fresh_copy_answers_without_origin
  <!-- 5 minutes is the client's own trust window for its local copy of the root index; one window, two layers -->
  - WHEN a client requests an origin's `index.shisha` and the held copy is older than 5 minutes or absent THE SYSTEM SHALL revalidate it with the origin by a conditional request, store the result, and answer with it. The mirror answers an origin's 404 as 404, which the client reads as an empty index.
    tier:   T0
    verify: cargo nextest run -p minmirrord root_index_revalidates_after_five_minutes
  - IF the mirror cannot reach the origin and holds a copy THEN THE SYSTEM SHALL answer with the held copy and an `Age` header carrying its age in seconds.
    tier:   T0
    verify: cargo nextest run -p minmirrord root_index_served_stale_with_age_when_offline
  - IF the mirror cannot reach the origin and does not hold a copy THEN THE SYSTEM SHALL answer 502 as MIR-002 does.
    tier:   T0
    verify: cargo nextest run -p minmirrord root_index_miss_offline_is_502

- **MIR-005** WHEN the mirror fetches a closure THE SYSTEM SHALL also fetch and store each companion the table above lists for it, from the same origin.
  tier:     T0
  verify:   cargo nextest run -p minmirrord companions_fetched_with_closure
  <!-- the closure's sigstore bundle signs the closure bytes (a hashedrekord bundle over its sha256); the commit map is what the publisher emits beside it; the client verifies neither yet, and keeping them now is what lets a verifier work offline later. The companion table is one place: a new published companion, such as a per-artifact attestation, is one row -->
  - IF the origin does not publish a companion THEN THE SYSTEM SHALL treat it as absent and not as an error.
    tier:   T0
    verify: cargo nextest run -p minmirrord missing_companion_is_not_an_error

- **MIR-006** WHEN a sync runs (MIR-032) and the mirror can reach the Sigstore trusted-root host THE SYSTEM SHALL refresh its copy of the Sigstore public-good trusted root and serve it at `/-/sigstore/trusted_root.json`.
  tier:     T0
  verify:   cargo nextest run -p minmirrord trusted_root_refreshed_on_sync_and_served
  <!-- a sigstore bundle verifies against the trusted root (Fulcio and Rekor keys); offline verification needs a copy of it -->

- **MIR-007** THE SYSTEM SHALL answer 404 to any request whose path matches no row of the table above, or that carries a query string, without contacting any origin.
  tier:     T1
  verify:   cargo nextest run -p minmirrord paths_outside_the_grammar_are_404_without_origin
  property: for every byte string used as a request path, the mirror opens an outbound connection only if the path parses as a row of the grammar, and then only to the host that row names.

- **MIR-008** THE SYSTEM SHALL answer requests only on the host socket and on the VM doors (MIR-023), and SHALL open no TCP or UDP listener.
  tier:     T0
  verify:   cargo nextest run -p minmirrord serves_only_on_host_socket
  <!-- with no listener on an address, nothing on the network and no other account on the laptop can reach the mirror or squat its port, so the client leg needs no TLS; the mirror's own connections to origins still use TLS against the system authorities -->
  - THE SYSTEM SHALL create the host socket with mode 0600 in a directory with mode 0700.
    tier:   T0
    verify: cargo nextest run -p minmirrord host_socket_is_private

- **MIR-009** THE SYSTEM SHALL bound each connection attempt to an origin, or to a repository's host, to 3 seconds.
  tier:     T0
  verify:   cargo nextest run -p minmirrord origin_connect_is_bounded
  <!-- off the VPN, an organization's hosts stop resolving or stop answering; a client waits for one bounded failure, not for the operating system's connect timeout -->
  - WHEN a connection to a host fails THE SYSTEM SHALL treat that host as unreachable for the next 30 seconds and try it no sooner. It answers from held copies where MIR-004 and MIR-012 allow, and as MIR-002 states for an unreachable origin otherwise.
    tier:   T0
    verify: cargo nextest run -p minmirrord unreachable_host_is_not_retried_for_thirty_seconds
    <!-- a box start asks for many objects; off the VPN it pays one bounded failure per host, not one per object -->

### O2 Package repositories

A repository copy is a mirror clone of an `https` repository without user information and without a port, kept under `<store>/git/<slug>`. The mirror makes a copy when a client first asks for one. It keeps the copy fresh while a registered project's chain names the repository (MIR-030). A host client asks for a copy over the host socket, and the answer names the copy's path in the store, which the client's git reads as a local repository. The guest daemon reads the copy as one bundle file through its door, because git cannot read a repository through a Unix socket or a vsock door.

- **MIR-010** WHEN a client asks for a repository the mirror holds a copy of THE SYSTEM SHALL serve the copy, to a host client as its path in the store and to the guest daemon as the bundle under `/-/git/<slug>/-/bundle`, so that git fetches every branch head and tag the origin had at the last refresh.
  tier:     T0
  verify:   cargo nextest run -p minmirrord copy_served_to_host_and_guest
  <!-- git hashes every object it receives, from a local repository and from a bundle, and the checkout is by commit hash, so the copy cannot substitute content -->
  - WHEN a client asks for a repository the mirror holds no copy of THE SYSTEM SHALL clone it before answering.
    tier:   T0
    verify: cargo nextest run -p minmirrord repo_without_copy_clones_on_demand
    <!-- pull-through for repositories: the first client to ask waits for the clone, as it waited for its own clone from the origin before. Every hop and sideload a client fetches is copied this way, before any registration -->
  - IF the mirror cannot clone the repository THEN THE SYSTEM SHALL answer that it holds no copy, with the one-line body `the mirror could not copy <repository URL>: <cause>`, and record the cause for `min mirror status`.
    tier:   T0
    verify: cargo nextest run -p minmirrord failed_clone_answers_no_copy_and_records_cause
    <!-- the client then fetches from the origin itself (MIR-013), with whatever credentials it has; a private repository that a door named before any registration lands here (MIR-027) -->
  - THE SYSTEM SHALL always register the repository that `min init` writes as a new project's upstream.
    tier:   T0
    verify: cargo nextest run -p minmirrord default_upstream_is_always_registered

- **MIR-011** WHEN the mirror refreshes a repository copy THE SYSTEM SHALL fetch every branch and tag and remove the refs the origin removed, so a client that fetched before sees the new heads.
  tier:     T0
  verify:   cargo nextest run -p minmirrord refresh_updates_heads_and_prunes
  - WHEN a refresh changes the copy's refs THE SYSTEM SHALL write a new bundle of every branch and tag, and replace the served bundle by one atomic rename.
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_rewrites_bundle_atomically
    <!-- the bundle is written once per change of refs, not once per request, so serving it runs no git process -->
  - WHEN the served bundle is replaced THE SYSTEM SHALL let a response that began before the replacement finish with the bundle it began with.
    tier:   T0
    verify: cargo nextest run -p minmirrord bundle_replacement_does_not_cut_a_response
  - WHEN a host client fetches from a copy while a refresh of that copy runs THE SYSTEM SHALL let the client's fetch complete.
    tier:   T0
    verify: cargo nextest run -p minmirrord host_fetch_survives_concurrent_refresh
  - WHEN a refresh or a clone starts THE SYSTEM SHALL finish it, even when the request that triggered it stopped waiting (MIR-012), so no half-written copy is left behind.
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_runs_to_completion
  - THE SYSTEM SHALL run at most one clone or refresh of one repository copy at a time, with a request that needs a copy another operation is creating waiting for that operation and never for a sync.
    tier:   T0
    verify: cargo nextest run -p minmirrord one_writer_per_copy_and_waiters_skip_the_sync

- **MIR-012** WHEN a request for a repository arrives and the copy's last refresh is older than 5 minutes, or a refresh request arrives over the host socket, THE SYSTEM SHALL refresh the copy first, bounded to 10 seconds, and then answer.
  tier:     T0
  verify:   cargo nextest run -p minmirrord refresh_request_refreshes_within_bound
  <!-- `min init` and `min update` ask for the newest head over the host socket before they resolve it; online they get it, offline they get the newest head the mirror saw, which is the newest commit whose supply can be here -->
  - IF the refresh fails THEN THE SYSTEM SHALL answer with the held copy.
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_failure_answers_with_held_copy
  - IF the refresh exceeds the bound THEN THE SYSTEM SHALL answer with the held copy while the refresh completes (MIR-011).
    tier:   T0
    verify: cargo nextest run -p minmirrord slow_refresh_answers_with_held_copy
  - IF the repository has no copy THEN THE SYSTEM SHALL clone it first (MIR-010).
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_of_uncloned_repo_clones_first

- **MIR-013** WHILE a client reads a mirror (MIR-020, MIR-024) THE SYSTEM SHALL fetch every repository whose URL has the scheme `https`, no user information and no port from the mirror's copy of it (MIR-010), and keep the original URL as git's remote.
  tier:     T1
  verify:   cargo nextest run -p checkouts mirror_rewrite_fetches_from_copy
  property: for every repository URL with an `https` scheme, no user information and no port, git's fetch source is the copy the mirror named for that URL's slug, as a store path on the host or a bundle in the guest, and git's remote is the original URL.
  - IF the mirror answers that it holds no copy THEN THE SYSTEM SHALL fetch the repository from its original URL, as today.
    tier:   T0
    verify: cargo nextest run -p checkouts no_copy_fetches_from_origin
  - THE SYSTEM SHALL keep the original URL as the repository's identity in the checkout registry and in every cache key.
    tier:   T0
    verify: cargo nextest run -p checkouts rewrite_keeps_original_url_as_identity
    <!-- cache keys embed the slug of the original URL (`<host>/<owner>/<repo>/<commit>.closure.shisha`), so the identity must not move with the fetch -->
  - IF the scheme of the URL is not `https`, or the URL includes user information or a port, THEN THE SYSTEM SHALL fetch it without the mirror and never register it.
    tier:   T0
    verify: cargo nextest run -p checkouts non_https_credentialed_and_ported_urls_bypass_the_mirror
    <!-- a credential in the URL would travel in a request and be stored with the copy; a port is a character the slug grammar does not admit; an ssh URL carries the user's ssh identity, which the mirror does not hold -->

- **MIR-014** THE SYSTEM SHALL run the mirror's own git commands with the user and system git configuration ignored and prompts disabled. The one exception is the credential helpers MIR-027 admits.
  tier:     T0
  verify:   cargo nextest run -p minmirrord mirror_git_ignores_user_configuration

### O3 Reaching the mirror

A door is a vsock port the VM host daemon maps to a Unix socket on the host. The guest already uses doors to report boxes and to forward telemetry. Every box runs under a socket seal that refuses the vsock family, so a door is the guest daemon's alone. The client configuration file is `<config>/minimal/config.toml`, the file `min dirs` prints, and `<config path>` in every message below is that path. Its `[mirror]` table holds:

| Key | Meaning | Default |
|---|---|---|
| `enabled` | run the mirror on this laptop and read it | `true` |
| `max_disk` | the store's budget (MIR-040) | `20 GiB` |
| `keep_unused_for` | the age rule (MIR-041) | `30d` |
| `always` | packages the mirror always keeps (MIR-031) | none |
| `git_credentials` | let the mirror's git use the user's credential helpers for registered repositories (MIR-027) | `true` |
| `gcloud_buckets` | `gs://` buckets the mirror reads with the user's Google credentials (MIR-028) | none |

- **MIR-020** WHEN `min` runs a command that reads a project and the client configuration enables the mirror THE SYSTEM SHALL start the mirror daemon if it is not running and wait until it answers, bounded to 10 seconds.
  tier:     T0
  verify:   cargo nextest run -p minimal project_command_starts_mirror
  <!-- the shape the CLI already has for the VM host daemon: read the lifecycle, start detached if stopped, wait for the socket -->
  - WHEN the daemon answers THE SYSTEM SHALL register the project (MIR-030), then resolve every repository fetch and every cache fetch of the command through the mirror (MIR-013, MIR-021).
    tier:   T0
    verify: cargo nextest run -p minimal project_command_registers_and_routes_through_mirror
  - IF the mirror daemon does not answer within the bound THEN THE SYSTEM SHALL fail the command with exit 1 and print three lines: `the mirror did not start: <cause>.`, `Run min mirror status to see its state.` and `Set [mirror] enabled = false in <config path> to fetch without it.` The cause is the first line the daemon wrote to its standard error before it exited, as `min` reports the VM host daemon's start failure today. Any further lines print after the three.
    tier:   T0
    verify: cargo nextest run -p minimal mirror_start_failure_fails_command_naming_both_remedies
    <!-- a silent fallback to the origins would hide a local fault behind a working day online and surface it offline; one line per fact, one action per line -->
  - THE SYSTEM SHALL NOT start the mirror daemon for `min mirror status` or `min mirror stop`.
    tier:   T0
    verify: cargo nextest run -p minimal status_and_stop_never_start_the_daemon
  - WHEN `mip` runs a command that reads a project THE SYSTEM SHALL route its fetches through the mirror when its daemon is running, and otherwise fetch as today and start nothing.
    tier:   T0
    verify: cargo nextest run -p mip mip_uses_running_mirror_and_starts_none
    <!-- `mip` runs on build servers and CI runners, where a detached daemon with a disk budget is unwanted; on a laptop `min` keeps the mirror up and `mip` benefits -->

- **MIR-021** THE SYSTEM SHALL read the environment variable `MINIMAL_MIRROR_SOCKET`, the path of the host socket, in `min`, in `mip` and in a native session daemon.
  tier:     T0
  verify:   cargo nextest run -p mctx mirror_socket_variable_selects_the_mirror
  - WHEN `min` or `mip` resolves the host socket THE SYSTEM SHALL read it from the running mirror's lifecycle file and pass it, as the variable, to every process it starts except the mirror daemon. A process that finds the variable set uses it.
    tier:   T0
    verify: cargo nextest run -p minimal mirror_socket_derived_and_passed_on
  - WHEN a process that reads a mirror resolves the cache read location THE SYSTEM SHALL resolve it as today, `MINIMAL_REMOTE_CACHE_URL` first, then an explicitly configured location, then the default. It SHALL then read that location through the mirror at its origin's mount when the location is an `https` base in the origin grammar or a `gs://` bucket.
    tier:   T0
    verify: cargo nextest run -p mctx cache_location_is_read_through_its_origin_mount
    <!-- the mirror does not choose the cache; the client does, as today, so a project on an organization's cache keeps reading that cache, through the mirror. The writer's bucket is untouched, so an upload still goes to the configured bucket -->
  - WHERE the location is outside the origin grammar THE SYSTEM SHALL read it without the mirror, as today.
    tier:   T0
    verify: cargo nextest run -p mctx location_outside_grammar_bypasses_mirror
    <!-- an `http` base, a base with a query or user information, or a path segment the grammar refuses -->
  - THE SYSTEM SHALL start the mirror daemon with `MINIMAL_MIRROR_SOCKET` and `MINIMAL_REMOTE_CACHE_URL` unset, and the daemon SHALL fetch from origins alone.
    tier:   T0
    verify: cargo nextest run -p minmirrord daemon_starts_without_client_variables
    <!-- the daemon's own graph evaluation reads caches and repositories too; with the variables unset it never fetches from itself -->
  - WHERE `mip --no-fetch` is present THE SYSTEM SHALL NOT fetch an artifact, from the mirror or from an origin, as today. `mip --offline` keeps its meaning for sources and checkouts.
    tier:   T0
    verify: cargo nextest run -p mctx no_fetch_skips_the_mirror_too

- **MIR-022** WHERE the client configuration file sets `[mirror] enabled = false` THE SYSTEM SHALL fetch as it does today: `min` and `mip` read no mirror, whatever `MINIMAL_MIRROR_SOCKET` says, no mirror daemon starts, and no door opens.
  tier:     T0
  verify:   cargo nextest run -p minimal mirror_disabled_leaves_fetch_paths_unchanged
  - THE SYSTEM SHALL read the `[mirror]` table from the client configuration file in `mip` and in the VM host daemon as well as in `min`.
    tier:   T0
    verify: cargo nextest run -p minvmd vm_host_daemon_reads_mirror_table_from_client_config
    <!-- today `mip` reads no user configuration file and the VM host daemon reads only its own provider file, so both gain a reader of this one table -->

- **MIR-023** WHERE the VM host daemon boots a guest and the client configuration enables the mirror THE SYSTEM SHALL start the mirror daemon if it is not running, connect each connection the guest opens on vsock door 7354 to the host socket, and put the token `MINIMALD_MIRROR_DOOR=7354` on the guest's command line.
  tier:     T0
  verify:   cargo nextest run -p minvmd vm_boot_opens_mirror_door_and_passes_token
  <!-- the door is the same mechanism the READY marker, the box report door and the telemetry door use; the token is printable ASCII with no space and carries no secret -->
  - WHILE several VMs run THE SYSTEM SHALL connect every VM's door to the one mirror daemon.
    tier:   T0
    verify: cargo nextest run -p minvmd every_vm_door_reaches_the_one_mirror
    <!-- one VM host daemon runs per VM, and each opens the same door number for its own guest -->
  - IF the host socket does not answer a door connection THEN THE SYSTEM SHALL start the mirror daemon and connect within MIR-020's bound, and close the guest's connection when that fails.
    tier:   T0
    verify: cargo nextest run -p minvmd door_restarts_a_stopped_mirror
  - THE SYSTEM SHALL place the door token on the command line before the telemetry tokens, never dropping it, with the telemetry tokens judged against the budget that remains.
    tier:   T0
    verify: cargo nextest run -p minvmd door_token_survives_a_full_command_line
    <!-- the telemetry tokens are dropped as a group when the line's budget overflows; the door token must not be in that group, or a long telemetry filter would silently take the mirror away from the guest -->

- **MIR-024** WHEN the guest daemon starts with `MINIMALD_MIRROR_DOOR` on its command line THE SYSTEM SHALL read its cache objects and its repository copies through that door (MIR-013, MIR-021).
  tier:     T0
  verify:   cargo nextest run -p minimald guest_reads_cache_and_repos_through_door
  - WHEN the token is absent THE SYSTEM SHALL fetch from the origins directly, as it does today.
    tier:   T0
    verify: cargo nextest run -p minimald no_door_token_fetches_origins

- **MIR-025** WHILE the guest daemon reads a mirror THE SYSTEM SHALL send its cache traffic through the door alone, and fetch a repository from its origin only where the mirror answered that it holds no copy (MIR-010).
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_supply_traffic_goes_through_the_door
  <!-- runs on the VM lane -->

- **MIR-026** THE SYSTEM SHALL let no process in a box connect to the mirror, on the laptop or in a guest.
  tier:     T0
  verify:   ./scripts/session-e2e.sh box_cannot_reach_mirror
  <!-- every box's socket seal refuses the vsock family. Boxes on the host network plan share the guest daemon's network namespace, so the guest daemon reaches the door through no TCP listener of its own. The host socket sits in a directory no box mounts -->

### O4 Private sources

A client reads every cache anonymously today, and a VM's daemon holds no git credential. The mirror runs as the user, so it can read what the user's own tools can read. It uses that reach only for sources the user named from the laptop.

- **MIR-027** WHERE `[mirror] git_credentials` is true and a project registration over the host socket named the repository (MIR-030) THE SYSTEM SHALL let the mirror's git use the credential helpers the user's own git configuration, system file included, names for that repository's URL, with prompts disabled.
  tier:     T0
  verify:   cargo nextest run -p minmirrord registered_repo_uses_user_credential_helpers
  <!-- a host `min init` already reaches these repositories with the same helpers; a VM's daemon holds none, so a private upstream or sideload reaches the VM only through the copy. On macOS the keychain helper is set in the system file, which the mirror's git otherwise ignores (MIR-014) -->
  - THE SYSTEM SHALL NOT give a credential helper to a git command for a repository that no registration named.
    tier:   T0
    verify: cargo nextest run -p minmirrord unregistered_repo_is_cloned_anonymously
    <!-- a repository a door named first is cloned anonymously, so a guest cannot steer the user's credentials to a host of its choosing; the next sync after the project's registration copies it with the helpers -->

- **MIR-028** WHERE `[mirror] gcloud_buckets` lists a bucket THE SYSTEM SHALL send each request to `https://storage.googleapis.com/<bucket>/` with an access token from the user's Google Application Default Credentials, and SHALL send no credential to any other origin.
  tier:     T0
  verify:   cargo nextest run -p minmirrord listed_bucket_reads_with_application_default_credentials
  <!-- the mirror is the first reader of a private bucket; it reads with the user's credentials so the VM's daemon need hold none -->
  - IF the mirror finds no Application Default Credentials, or cannot obtain a token from them, THEN THE SYSTEM SHALL answer 502 with the one-line body `the mirror has no Google credentials for gs://<bucket>: <cause>`, and the client SHALL print `Run gcloud auth application-default login.` as the line after it.
    tier:   T0
    verify: cargo nextest run -p mctx missing_google_credentials_names_the_login_command

### O5 The protected set and the sync

- **MIR-030** WHEN `min` or `mip` registers a project (MIR-020) THE SYSTEM SHALL record over the host socket the project's root, the cache origin the registering client reads (MIR-021) and the time, read its `minimal.toml`, register the repositories its links name, and answer at once.
  tier:     T0
  verify:   cargo nextest run -p minmirrord registration_records_root_origin_and_links
  <!-- the origin is recorded because the client, not the mirror, chooses the cache; the sync fetches a project's protected artifacts from the origin its client reads -->
  - WHEN the project has no `minimal.toml` THE SYSTEM SHALL register the root alone.
    tier:   T0
    verify: cargo nextest run -p minmirrord registration_without_mfile_records_root
    <!-- `min init` registers before the file exists and reads the default upstream, which is always registered (MIR-010) -->
  - THE SYSTEM SHALL NOT make a registration wait for a running sync.
    tier:   T0
    verify: cargo nextest run -p minmirrord registration_does_not_wait_for_sync
  - WHEN a sync runs THE SYSTEM SHALL load each registered project's upstream chain, as the box's graph loads it, and register the repository of every git link it visits: each layer's upstream and each layer's sideloads.
    tier:   T0
    verify: cargo nextest run -p minmirrord sync_registers_every_hop_and_sideload
    <!-- a project's own `minimal.toml` names only its direct links; the layers above it name the rest. A `dir` link is on the laptop already -->
  - WHEN a sync runs THE SYSTEM SHALL read each registered project's `minimal.toml` again at that time, so it follows a moved pin and a new link without a new registration.
    tier:   T0
    verify: cargo nextest run -p minmirrord sync_reads_current_pin_and_links
  - WHEN a registered project's `minimal.toml` was unreadable at every sync for 30 days, or no command ran in the project for 90 days, THE SYSTEM SHALL drop the project from the registry and list it in the next `min mirror status` under `dropped:`.
    tier:   T0
    verify: cargo nextest run -p minmirrord stale_project_dropped_and_listed_once
  - WHEN `min mirror forget <path>` is run THE SYSTEM SHALL drop the project now and print two lines: `forgot <path>.` and `Its artifacts are no longer protected.`
    tier:   T0
    verify: cargo nextest run -p minimal forget_drops_project_and_prints_outcome

- **MIR-031** WHEN a sync runs THE SYSTEM SHALL compute the protected set as the union of the artifact sets the table below lists, together with the index objects, companions and repository copies those resolutions read, all for the target this machine's boxes run, which is Linux on the machine's architecture. An artifact set is the artifact the index names for each package in the transitive closure of the listed packages, resolved against the graph at the listed commit, at the listed origin.
  tier:     T1
  verify:   cargo nextest run -p minmirrord protected_set_covers_projects_and_new_projects
  property: for every row of the table and every package in the transitive closure of that row's packages at its commit, the protected set holds the artifact the index at that row's origin names for that package at that commit.
  <!-- the daemon composes a loadout's packages into the box and resolves them against the project's graph at the project's pin, so a loadout's artifacts differ per project and are protected per project. The mirror resolves with the graph loader and the cache reader the clients use, which build on macOS; the build context does not, because it carries the sandbox. A package the index does not name has no artifact to protect and is reported (MIR-034) -->

  | Row | Packages | Commit | Origin |
  |---|---|---|---|
  | each registered project | the packages of every box entry in its `minimal.toml`, which today are the `[session]` table and the `[tasks.*]` entries and under BOX also the `[sessions.*]` and `[boxes.*]` entries, the packages of the stack it names and the `build_packages` and `runtime_packages` its `[stack]` table adds, the packages of every loadout in the user's loadouts directory, and the `[mirror] always` packages | the project's pinned upstream, with its pinned sideloads | the origin its registration recorded |
  | new projects | the packages of every loadout in the user's loadouts directory and the `[mirror] always` packages | the newest sealed commit of the default upstream's `main` (MIR-050) | the origin the most recent registration recorded |

- **MIR-032** WHEN the daemon starts, WHEN 60 minutes passed since the last sync, WHEN a project's first registration arrives and WHEN `min mirror prepare` is run THE SYSTEM SHALL run a sync.
  tier:     T0
  verify:   cargo nextest run -p minmirrord sync_triggers
  - WHEN a sync runs THE SYSTEM SHALL refresh every registered repository and clone any without a copy (MIR-011), then walk the tracked branch of each registered project's upstream link through its first-parent ancestors until it finds a sealed closure at the project's origin or reaches 64 commits, fetching the closures that exist and recording the absences (MIR-002), then fetch the index objects and companions of every pinned commit, then fetch every protected artifact not held, within the disk budget (MIR-042).
    tier:   T0
    verify: cargo nextest run -p minmirrord sync_order
    <!-- the walk is what lets MIR-050 run offline. The tracked branch is the link's `branch`, or the origin's default head when it names none; a sideload is pinned to its head (MIR-050) and is not walked -->
  - THE SYSTEM SHALL run one sync at a time and queue a sync request that arrives during one.
    tier:   T0
    verify: cargo nextest run -p minmirrord sync_serialization
    <!-- one actor, as the daemon's own cache maintenance is: two syncs over one store would race -->

- **MIR-033** THE SYSTEM SHALL record the time of the last request for every object it holds.
  tier:     T0
  verify:   cargo nextest run -p minmirrord every_served_object_records_last_request
  <!-- observed demand is the usage history; nothing else records it; one record per held object, so the records are bounded by the store -->
  - THE SYSTEM SHALL keep every object it served or fetched until eviction removes it (MIR-040, MIR-041).
    tier:   T0
    verify: cargo nextest run -p minmirrord objects_stay_until_evicted

- **MIR-034** WHEN `min mirror prepare` is run THE SYSTEM SHALL run a sync now, wait for it, and print one line per row of the MIR-031 table, each with the row's name, the pin, `sealed` or `unsealed` (MIR-051), the held and total artifact counts and the bytes missing.
  tier:     T0
  verify:   cargo nextest run -p minimal prepare_reports_coverage
  <!-- the surface that stays; the activate path prints nothing new (MIR-062) -->
  - WHEN the mirror holds every protected artifact THE SYSTEM SHALL print `ready for offline` and exit 0.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_ready_exit_zero
  - WHEN a protected artifact is missing THE SYSTEM SHALL print one line per reason, one of `origin unreachable`, `not in any index` or `disk budget exceeded`, with the count and size it covers, then `not ready for offline: <n> artifacts missing (<size>).`, and exit 1.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_not_ready_exit_one
  - WHEN the reason `origin unreachable` appears THE SYSTEM SHALL print after it one line per unreachable origin, `<origin URL> did not answer: <cause>.`
    tier:   T0
    verify: cargo nextest run -p minimal prepare_names_unreachable_origins
    <!-- off the VPN, the user learns which of their caches they need the VPN for before they leave it -->
  - WHEN the reason `not in any index` appears THE SYSTEM SHALL print after it `A package in no index builds from source, which fails offline.`
    tier:   T0
    verify: cargo nextest run -p minimal prepare_explains_not_in_any_index
  - WHEN a loadout package is missing from a pin THE SYSTEM SHALL report it once per loadout, not once per project.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_reports_loadout_gaps_once
  - WHERE the `--all` flag is present THE SYSTEM SHALL also fetch every artifact named by the sealed closure of each pinned commit and of the default upstream's newest sealed `main` commit, within the budget.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_all_fetches_whole_closures
  - WHERE the `--json` flag is present THE SYSTEM SHALL print the report as one JSON document under the schema `min/v1/mirror-prepare` with the same exit codes.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_json_schema_and_exit_codes
  - IF the client configuration disables the mirror THEN THE SYSTEM SHALL print three lines, `the mirror is turned off by [mirror] enabled = false in <config path>.`, `Set [mirror] enabled = true in <config path>.` and `Run min mirror prepare again.`, and exit 2.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_refused_when_disabled

### O6 Disk

- **MIR-040** WHILE an eligible object remains THE SYSTEM SHALL keep the store's total size at or under `[mirror] max_disk`, default `20 GiB`, by evicting eligible objects in order of oldest last request first. An eligible object is an unprotected artifact, or an unprotected copy of a repository no registration names, with no request in flight and a last request more than an hour old.
  tier:     T1
  verify:   cargo nextest run -p minmirrord eviction_is_lru_over_eligible_objects
  property: for every store state and every eviction run, each removed object was eligible. No removed object had a request more recent than any retained eligible object. Afterwards the total is at or under the budget, or no eligible object remains.
  - THE SYSTEM SHALL NOT evict a protected object, an object requested within the last hour, an object with a request in flight, an index object or companion, or the copy of a registered repository.
    tier:   T0
    verify: cargo nextest run -p minmirrord eviction_spares_protected_recent_indexes_and_copies
    <!-- a client keeps its copy of a per-commit index for ever and never asks again, so an index must outlive the budget; the indexes of registered projects are protected (MIR-031) and the rest leave by age (MIR-041) -->
  - IF the store exceeds the budget and no eligible object remains THEN THE SYSTEM SHALL report `the store exceeds the budget: <used> of <max_disk>.` in `min mirror status` and in its log.
    tier:   T0
    verify: cargo nextest run -p minmirrord over_budget_with_nothing_eligible_is_reported
    <!-- a burst of distinct real artifacts within one hour, a large registered repository, or the protected set alone can pass the ceiling -->
  - WHILE the store exceeds the budget THE SYSTEM SHALL still fetch an object a client requests.
    tier:   T0
    verify: cargo nextest run -p minmirrord over_budget_keeps_fetching
    <!-- every client is the user's own; a refused fetch online would send it to build from source -->

- **MIR-041** THE SYSTEM SHALL evict an unprotected object whose last request is older than `[mirror] keep_unused_for`, default `30d`, whether or not the store reaches the budget.
  tier:     T0
  verify:   cargo nextest run -p minmirrord unused_objects_evicted_after_keep_unused_for
  <!-- the duration grammar is the one `mip cache clean --older-than` takes: a whole number of days, hours or minutes -->

- **MIR-042** IF the protected set alone exceeds the budget THEN THE SYSTEM SHALL fetch protected artifacts only up to the budget and keep what it holds.
  tier:     T0
  verify:   cargo nextest run -p minmirrord protected_set_over_budget_stops_at_budget
  <!-- the budget is a ceiling the user set and the protected set is a promise the user made; when they conflict the mirror keeps the ceiling, keeps what it has, and says which promise it cannot keep -->
  - WHILE filling under that condition THE SYSTEM SHALL take the rows of the MIR-031 table in order of most recent command first, with the `new projects` row last.
    tier:   T0
    verify: cargo nextest run -p minmirrord over_budget_fill_order
  - WHILE that condition holds THE SYSTEM SHALL report it in `min mirror status`, in `min mirror prepare` and in its log as three lines: `the protected set needs <size>.`, `The disk budget [mirror] max_disk is <max_disk>.` and `Raise it in <config path>, or run min mirror forget <path> to drop a project.`
    tier:   T0
    verify: cargo nextest run -p minmirrord protected_set_over_budget_warns

- **MIR-043** WHEN `min mirror clean` is run THE SYSTEM SHALL run eviction now and print two lines: `freed <size>.` and `<used> of <budget> in use.`
  tier:     T0
  verify:   cargo nextest run -p minimal clean_evicts_now_and_prints_sizes

- **MIR-044** THE SYSTEM SHALL keep the store, with the mirror's own layer cache for graph evaluation, under the user's cache directory, and the registry, lifecycle file, log and host socket under the user's state directory, each directory with mode 0700 and at paths that do not change between runs.
  tier:     T0
  verify:   cargo nextest run -p minmirrord store_and_state_paths_and_modes
  - WHEN `min dirs` is run THE SYSTEM SHALL print both paths.
    tier:   T0
    verify: cargo nextest run -p minimal dirs_prints_mirror_store_and_state

### O7 Pins follow sealed closures

- **MIR-050** WHEN `min init`, `min update`, `mip init`, `mip update` or `mip run` with an inline upstream resolves the upstream's branch head to a pin THE SYSTEM SHALL ask the mirror to refresh the repository (MIR-012) and then pin the newest commit, among the head and its first-parent ancestors up to 64 commits back, for which the cache the client reads publishes a sealed closure.
  tier:     T0
  verify:   cargo nextest run -p op pin_follows_newest_sealed_closure
  <!-- the closure is the publisher's sealed catalogue for one commit; the snapshot is an uncurated copy of the root at publish time and the root is mutable (the 2026-08-17 dangling-index incident the index-source comments in mfile record). A project pinned to a commit with no closure reads the uncurated chain and may build from source what the cache was meant to supply. Each existence probe is one request to the mirror, answered from its absence records offline (MIR-002, MIR-032); the probes may run concurrently. The reference pages that describe the re-pin, the `min update` section of the CLI reference and the `locked_commit` paragraph of the `minimal.toml` reference, change with this requirement -->
  - WHEN the pin is behind the head THE SYSTEM SHALL print two lines: `pinned <commit>.` and `<branch> is <n> commits ahead of it with no published closure yet.`
    tier:   T0
    verify: cargo nextest run -p op pin_behind_head_says_how_far
  - IF no commit within that range has a sealed closure THEN THE SYSTEM SHALL pin the head and print two lines: `<repo>: no commit within 64 of <branch> has a published closure.` and `Pinned <commit>. Its packages may build from source.`
    tier:   T0
    verify: cargo nextest run -p op unsealed_range_pins_head_and_says_so
  - IF a probe fails with a status other than 200 or 404 THEN THE SYSTEM SHALL fail the command as MIR-063 states, and pin nothing.
    tier:   T0
    verify: cargo nextest run -p op probe_failure_fails_the_command
  - WHEN the same commands resolve a sideload's branch head THE SYSTEM SHALL pin the head, as today.
    tier:   T0
    verify: cargo nextest run -p op sideload_pin_is_the_head
    <!-- a sideload repository outside the build infrastructure publishes no closure; its specs resolve locally as they always have -->
  - THE SYSTEM SHALL apply the rule whatever the project's `[cache] index_source` setting is.
    tier:   T0
    verify: cargo nextest run -p op sealed_pin_ignores_index_source_setting
    <!-- `root` and `pinned` never read the closure, but a sealed pin costs them nothing and keeps one rule -->

- **MIR-051** WHEN `min mirror status` or `min mirror prepare` lists a row THE SYSTEM SHALL mark its pin `sealed` when the mirror holds, or the row's origin publishes, the pin's closure object, and `unsealed` otherwise.
  tier:     T0
  verify:   cargo nextest run -p minmirrord status_marks_pin_sealed_or_unsealed

### O8 Observability

- **MIR-060** WHEN `min mirror status` is run THE SYSTEM SHALL print the lines the table below lists, in that order, and exit 0 when the daemon is running and 1 otherwise.
  tier:     T0
  verify:   cargo nextest run -p minimal status_report_fields_and_exit_code
  <!-- the one surface that stays and that every warning in this document points at; the first slice prints the `mirror:`, `origins:`, `disk:` and `repositories:` lines -->
  - WHERE the `--json` flag is present THE SYSTEM SHALL print the same facts as one JSON document under the schema `min/v1/mirror-status`.
    tier:   T0
    verify: cargo nextest run -p minimal status_json_schema

  | Line | Content |
  |---|---|
  | `mirror:` | the daemon's state, and when running its process id and the path of the host socket |
  | `origins:` | one line per cache origin the mirror contacted, with the last successful contact and, when later, the last failure with its cause |
  | `last sync:` | when the last sync ran and whether it completed |
  | `disk:` | bytes in use, bytes protected, and the budget, then the MIR-040 and MIR-042 lines when they apply |
  | `projects:` | the lines MIR-034 prints for the rows of the MIR-031 table |
  | `repositories:` | one line per repository copy with its heads and last refresh, and the last failure with its cause when later; or the cause the mirror holds no copy (MIR-010) |
  | `dropped:` | projects dropped since the last status (MIR-030), when any |
  | last lines | the ready line MIR-034 prints, followed when not ready by `Run min mirror prepare to fetch them.` |

  ```text
  mirror: running (pid 41234) at ~/.local/state/minimal/mirror/mirror.sock
  origins:
    https://cache.minimal.dev/                     reachable, last contact 3 min ago
    https://cache.acme.internal/                   last contact 2 h ago, unreachable 3 min ago: connection timed out
  last sync: 3 min ago, complete
  disk: 8.2 GiB in use, 6.9 GiB protected, 20 GiB budget
  projects:
    ~/src/railway-demo   pkgs@bd62e6e2 sealed     142/142 artifacts
    ~/src/acme-api       pkgs@5c1e0a77 sealed      96/98 artifacts, 21 MiB missing
    new projects         pkgs@bd62e6e2 sealed      49/49 artifacts
  repositories:
    github.com/gominimal/pkgs          main bd62e6e2   refreshed 3 min ago
    git.acme.internal/platform/pkgs    main 5c1e0a77   refreshed 2 h ago, last refresh failed: could not resolve host
  not ready for offline: 2 artifacts missing (21 MiB).
  Run min mirror prepare to fetch them.
  ```

- **MIR-061** THE SYSTEM SHALL write the daemon's log as JSON records in the state directory, in the format the other daemons write.
  tier:     T0
  verify:   cargo nextest run -p minmirrord log_is_json_records_in_state_dir
  - WHEN `min bug` is run THE SYSTEM SHALL include the log's tail, the status document and the daemon's process marker in the diagnostic bundle.
    tier:   T0
    verify: cargo nextest run -p minimal bug_bundle_includes_mirror_log_and_status

- **MIR-062** WHILE a box starts healthily THE SYSTEM SHALL NOT print a line on behalf of the mirror before the box shell, on `min session activate` and on `min session attach`.
  tier:     T0
  verify:   ./scripts/session-e2e.sh mirror_adds_no_line_before_shell
  <!-- the healthy-start rule: the mirror has nothing to tell the user on a start that reaches the shell; a fetch failure through it is an error that ends the command and stays on screen (MIR-063) -->

- **MIR-063** IF a fetch through the mirror fails because the mirror does not answer THEN THE SYSTEM SHALL fail that fetch with two lines, `the mirror did not answer: <cause>.` and `Run min mirror status to see its state.`, on the surface where the daemon or the CLI reports a failed fetch today.
  tier:     T0
  verify:   cargo nextest run -p mctx mirror_unanswered_names_status_command
  - IF the mirror answers 502 THEN THE SYSTEM SHALL fail that fetch with the 502 body (MIR-002, MIR-028) as its first line and `Run min mirror status to see its state.` as its second, except where MIR-028 names the line that follows.
    tier:   T0
    verify: cargo nextest run -p mctx mirror_502_body_reaches_the_user
    <!-- today the reader renders an error status as its variant name; through the mirror the body says what the user needs, that an origin is out of reach -->
  - WHERE the fetch runs in the guest daemon THE SYSTEM SHALL print the same lines on the same surface.
    tier:   T0
    verify: cargo nextest run -p minimald guest_fetch_failure_names_status_command
  - WHERE the command is `mip` THE SYSTEM SHALL print, in place of the second line after an unanswered fetch, `Set [mirror] enabled = false in <config path> to fetch without it.`, and after a 502 the body alone.
    tier:   T0
    verify: cargo nextest run -p mip fetch_failure_message_without_min
    <!-- `mip` can run where `min` is not installed, and an instruction names a command the user can run; the 502 body states the situation on its own -->

- **MIR-064** WHEN the cache reader receives an answer with an `Age` header THE SYSTEM SHALL record the age in its log.
  tier:     T0
  verify:   cargo nextest run -p rcache stale_answer_age_is_logged
  <!-- the header the mirror sets on a stale root index (MIR-004) has a reader, so a stale offline answer is traceable -->

### O9 Lifecycle

- **MIR-070** THE SYSTEM SHALL run one mirror daemon per user on the laptop, as `minmirrord run [--detach]`, and stop it with `minmirrord stop` and `min mirror stop`.
  tier:     T0
  verify:   cargo nextest run -p minmirrord run_detach_and_stop_round_trip
  <!-- the VM host daemon's shape: a lifecycle file, an alive lock, a detached re-exec -->
  - IF the process a running state names no longer exists THEN THE SYSTEM SHALL report the mirror as stopped and start it on the next demand (MIR-020, MIR-023).
    tier:   T0
    verify: cargo nextest run -p minmirrord dead_process_reads_as_stopped
  - IF `git` is not on the daemon's `PATH` THEN THE SYSTEM SHALL refuse to start, exit 1, and write two lines to its standard error: `git is not installed.` and `The mirror needs it to copy package repositories.` When `min` started the daemon, those lines are the `<cause>` of MIR-020's first line.
    tier:   T0
    verify: cargo nextest run -p minmirrord missing_git_refuses_start
    <!-- `min init` on the host already requires git for the same reason -->
  - WHEN several starters race to start the mirror THE SYSTEM SHALL leave one daemon running and let every starter proceed against it within MIR-020's bound.
    tier:   T0
    verify: cargo nextest run -p minmirrord racing_starters_share_one_daemon
    <!-- `min` and the host daemon of every booting VM start the mirror on demand; the alive lock decides the winner and the losers wait for its socket -->

- **MIR-071** THE SYSTEM SHALL keep the mirror daemon's life independent of every VM host daemon and session daemon. `min stop` leaves it running, a VM restart or a new VM instance reuses it, and only `min mirror stop`, `minmirrord stop` or the installer stops it.
  tier:     T0
  verify:   ./scripts/session-e2e.sh mirror_survives_vm_restart

- **MIR-072** WHEN the installer replaces the binaries THE SYSTEM SHALL run `min mirror stop` first, silently and without failing the install when nothing runs or the installed `min` lacks the verb, record the mirror binary in the install record, and let the next `min` command start the new daemon.
  tier:     T0
  verify:   scripts/install_test.sh mirror_stopped_before_binary_swap
  <!-- swapping a binary under a running daemon wedges it, the rule the installer already applies to the other daemons through `min stop`, which leaves the mirror running (MIR-071) -->

- **MIR-073** IF the daemon stops while writing an object THEN THE SYSTEM SHALL never answer that key with a partial body, before or after a restart. An object whose last request time was lost with the restart counts as requested at the restart.
  tier:     T0
  verify:   cargo nextest run -p minmirrord interrupted_write_leaves_no_partial_object
  <!-- a crash never leaves a partial object visible to a client, so MIR-001 holds across restarts -->

### O10 Security

- **MIR-080** THE SYSTEM SHALL accept registration, refresh, `prepare`, `forget`, `clean` and `stop` only on the host socket, and never through a door.
  tier:     T0
  verify:   cargo nextest run -p minmirrord control_verbs_refused_through_a_door
  <!-- a guest reads; only the laptop decides what is registered, protected and credentialed (MIR-027) -->

- **MIR-081** THE SYSTEM SHALL open an outbound connection only for a key in the grammar, to the origin the path names, or for a repository copy, to that repository's host. The one exception is the Sigstore trusted-root host, for `/-/sigstore/trusted_root.json` alone.
  tier:     T1
  verify:   cargo nextest run -p minmirrord outbound_hosts_follow_the_grammar
  property: for every request sequence from clients, every connection the mirror opens goes to the host a parsed request path or a repository copy names. The trusted root is the only fetch that goes elsewhere.
  <!-- the guest reaches every such host itself through the VM's network today, so the mirror widens no reach; what it adds is the user's credentials, which MIR-082 bounds -->

- **MIR-082** THE SYSTEM SHALL attach a credential only to a git command for a repository a registration named (MIR-027) or to a request to a bucket `[mirror] gcloud_buckets` lists (MIR-028).
  tier:     T1
  verify:   cargo nextest run -p minmirrord credentials_follow_registrations_only
  property: for every sequence of registrations over the host socket and requests through doors, every outbound operation that carries a credential targets a repository some registration named or a bucket the configuration lists.

- **MIR-083** THE SYSTEM SHALL NOT write a credential to the store, the log, the status output or a response, and SHALL send each credential only to the host it is for.
  tier:     T0
  verify:   cargo nextest run -p minmirrord credentials_never_stored_logged_or_served
  <!-- the mirror stores what a credential fetched, never the credential; the helpers and the token source stay the user's own -->

## Non-goals

- A shared mirror on an office network, and tiers of mirrors where a laptop's mirror fills from an office mirror. Serving other machines needs TLS and a caller's identity, which belong with the identity plane ([BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md) names Gatehouse). The paths this document defines are keyed by origin, so a shared mirror can serve the same paths later, and a laptop's mirror can name it as a tier without a change to clients. One of the issues the first Open question names.
- Declaring, per link of an upstream chain, which cache that link publishes to. A client reads one cache per process today, chosen by `MINIMAL_REMOTE_CACHE_URL` or the default, and a chain that mixes caches does not resolve today either. The mirror follows whatever the client chose (MIR-021).
- Repositories named by an ssh or scp-style URL, or by a URL with user information or a port. The client fetches them as today (MIR-013). An ssh identity is the user's agent's to present, and the mirror does not hold it.
- Private caches other than Google Cloud Storage buckets through Application Default Credentials (MIR-028), and credentials through the Box Egress Proxy's sign-in and secret store. The proxy is the only reader of its GitHub token, which GitHub rotates on every renewal, so the mirror would reach it through the proxy, not beside it. One of the issues the first Open question names.
- Caching a box's own package-manager traffic, such as npm, PyPI or crates.io inside a box. That is box egress, which [BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md) and [NET](../18-spec-box-networking/18-spec-box-networking.md) govern, and no box reaches the mirror (MIR-026).
- One extracted cache shared by every VM. The mirror holds compressed artifacts and repository copies once per laptop. Each daemon still extracts into its own cache, on its VM's data volume, which `mip cache clean` and the session daemon's maintenance actor reclaim as today. A client's checkout also keeps its own bare clone of each repository, as it does today, outside the mirror's budget.
- Checking the sigstore bundles and the trusted root in the client. That is a separate spec, one of the issues the first Open question names. This document keeps their bytes (MIR-005, MIR-006) so that check works offline.
- Source tarballs by hash under `/-/src/`. That is the second slice, one of the issues the first Open question names. A package the index does not name builds from source, and `min mirror prepare` names it (MIR-034). Most sideloads publish no closure, so a sideload's packages build from source, and its repository copy (MIR-030) is necessary but not enough offline until that slice lands.
- Starting the mirror at login through a macOS launch agent or a systemd user unit. The CLI and the VM host daemon start it on demand (MIR-020, MIR-023). A login unit is one of the issues the first Open question names.

## Non-functional requirements

- **MIR-N01** WHILE streaming an object it is fetching from an origin THE SYSTEM SHALL relay each received chunk to the client before the origin's response completes.
  tier:   T0
  verify: cargo nextest run -p minmirrord streamed_fetch_is_not_buffered

- **MIR-N02** WHILE answering a held artifact to the guest through its door THE SYSTEM SHALL start the response within 100 ms at the 95th percentile on an idle host.
  tier:   T0
  verify: just bench-mirror guest_time_to_first_byte
  <!-- a new recipe over a new `scripts/bench-mirror.sh`; the existing boot benchmark takes no case argument, so this one is its own script -->

- **MIR-N03** THE SYSTEM SHALL run at most 8 origin fetches at a time.
  tier:   T0
  verify: cargo nextest run -p minmirrord origin_fetches_are_bounded
  <!-- the number the build orchestrator fetches with today; several VMs booting at once cannot turn the mirror into a flood against an origin -->

- **MIR-N04** WHILE the layer cache already holds every registered pin's evaluation THE SYSTEM SHALL compute a sync's protected set for 10 registered projects within 5 seconds on an idle host.
  tier:   T0
  verify: just bench-mirror protected_set_ten_projects
  <!-- the layer cache makes a re-evaluation at a known pin cheap; this bounds what the loadout superset costs -->

## Design reasoning

**One laptop, not a network.** The mirror serves the clients on one laptop: the host CLI, `mip`, a native session daemon and the daemon in every VM. An earlier draft served every client over HTTPS, so a shared mirror on an office network and a Box Host on another machine could read it too. That reach costs a certificate authority, certificate renewal, a trust setting per client, and a choice of which mirror to read that depends on whether the laptop is on the VPN. Projects that build on private repositories and caches also need a map of which cache serves which link of a chain, kept at the publisher, the organization and the user. The laptop alone needs none of that. It still gets the success criterion, one copy for every VM, and private sources, so it ships first, and the shared mirror follows as its own spec (Non-goals).

**Keyed by origin, so the mirror needs no map.** The cache reader already reads plain keys under one base URL. The mirror serves those keys under a mount named after that base (MIR-002, MIR-021). The client keeps choosing its cache as it does today, and the mirror fetches from whatever origin the path names. A project on an organization's cache fills from that cache while the laptop is on the VPN, and reads the copy once it is off. No setting says which cache a repository uses. A shared mirror added later serves the same paths, so a laptop's mirror can name it as a tier without a change to clients. The same holds for repositories, which the mirror keys by slug. A store with an API of its own fails this test. Every client then needs a second code path, and the publisher's signatures no longer cover what the client reads.

**A Unix socket and a door, no TLS.** With no listener on an address, nothing on the network and no other account on the laptop can reach the mirror, and no process can squat its port first (MIR-008). The host socket sits at mode 0600 in a 0700 directory. The guest reaches the mirror through a vsock door, the mechanism its other host channels already use. Every box runs under a socket seal that refuses the vsock family, so the door is the guest daemon's alone (MIR-026). The guest daemon opens no TCP listener to relay it: boxes on the host network plan share the guest daemon's network namespace and would reach one. The earlier draft that served HTTPS on loopback rejected this transport only because a Box Host on another machine cannot use it, which this document does not serve.

**Git reads a local copy on the host and a bundle in the guest.** Git cannot read a repository through a Unix socket or a vsock door. A host client asks the mirror for a current copy over the host socket and fetches from it as a local repository (MIR-010, MIR-013). The guest daemon reads one bundle file through its door and fetches from that. The mirror writes the bundle once per change of refs (MIR-011), so serving it runs no git process. Git hashes every object it receives from either source, and the checkout is by commit hash, so the copy cannot swap in other content. The earlier draft served git's dumb HTTP protocol, which needed an ordered rewrite of the pack list and refs, a repack of loose objects and a delay before old packs could go. A bundle needs none of that. The cost is that a guest with an older clone fetches the whole bundle again. That cost falls once per VM per change of refs, and an Open question asks for incremental bundles. Git records the original URL as the remote, and the cache keys embed its slug, so the copy touches the fetch only (MIR-013). Rewriting the URL in `minimal.toml` fails because it changes the cache keys and ties the project file to one machine.

**The mirror runs as the user.** A client reads every cache anonymously today, and the daemon in a VM holds no git credential, so a private upstream or sideload cannot reach a VM at all. The mirror runs as the user and can use the user's own git credential helpers and Google credentials (MIR-027, MIR-028). It uses them only for what the user named from the laptop: repositories a project registration's chain names, and buckets the configuration lists (MIR-082). A repository a guest names first is cloned anonymously, so a guest cannot steer the user's credentials to a host of its choosing. The Box Egress Proxy is the long-term home for credentials, but it holds its GitHub token alone, because GitHub rotates the refresh token on every renewal. Its certificate authority is name-constrained away from Minimal's own hosts and is trusted only inside boxes, never by the daemons the mirror serves. So the mirror stands beside the proxy and reuses no part of it now. A later spec can route the mirror's private fetches through the proxy (Non-goals).

**Every hop, with no list.** A box's graph loads the project's upstream, that layer's upstream, and so on up the chain, with each layer's sideloads. Pull-through copies every repository a client fetches (MIR-010), so every hop is in the mirror after one online activation. The sync loads the same chain for each registered project and registers every repository it visits (MIR-030), which keeps those copies fresh, gives them the user's credentials and protects them from eviction. A project's own `minimal.toml` names only its direct links, so registering those alone, as an earlier draft did, left the rest of the chain to fail offline.

**One daemon, many VMs.** One VM host daemon runs per VM. Each would otherwise keep its guest's cache on that VM's own data volume, so N VMs meant N downloads. One mirror daemon per user is the single writer to one store, and every VM host daemon connects its guest's door to it (MIR-023). A store that the CLI and every VM host daemon wrote directly would need cross-process locks to fetch a miss once and to keep eviction off a read in progress. Folding the mirror into the VM host daemon fails because a VM re-creation is the event the mirror must survive (MIR-071). The session daemon owns one extracted cache, and the CLI is not a service. The crate takes the binary's name, `minmirrord`, as the other daemons' crates do, so no stale binary under a second name can linger in a build directory. `mip` uses a running mirror and starts none (MIR-020), because it also runs on build servers and CI runners, where a detached daemon with a disk budget has no place.

**The daemon resolves packages itself, per project.** Keeping the protected set warm without a user command is the point of the mirror. So the daemon resolves packages to artifacts itself (MIR-031, MIR-032). It uses the graph loader and the cache reader the clients use, which build on macOS, and not the build context, which carries the sandbox and does not. The daemon composes a loadout's packages into a box and resolves them against the project's graph at the project's pin. One loadout yields different artifacts in different projects, and the mirror protects them per project. Every loadout on disk counts, not only the default ones, because the user can apply any of them at the next activation, and the extra cost is a few more roots in a graph the layer cache already holds (MIR-N04). A separate row at the newest sealed commit of the default upstream covers the project `min init` is about to create. Resolving in the CLI and handing the daemon a list fails because the set is then fresh only when the user runs the command. Asking the running session daemon fails because it can be down, and because it couples two lifecycles. The daemon reads none of the client variables (MIR-021), so it never fetches from itself.

**Observed demand is the baseline, the lists are the promise.** Everything fetched through the mirror stays until eviction (MIR-033). That is the usage history. Registered projects, loadouts and the always list are what the user said they need (MIR-031). The mirror protects exactly those and evicts only among the rest (MIR-040). The budget is a ceiling. The mirror never exceeds it silently, and it reports a protected set larger than the ceiling instead of trimming it (MIR-042). Evicting protected objects to fit fails because an offline user then finds a promise broken with no warning. A sync runs on a project's first registration and not on every command (MIR-030, MIR-032), because every `min` command in a project registers it. Indexes and companions never leave by budget (MIR-040). A client keeps its own copy of a per-commit index for ever and asks only for the artifacts it names.

**The mirror fetches artifacts by name, with no catalogue gate.** The mirror fetches any artifact whose name parses, from the origin the path names, and keeps it only when the bytes hash to the name (MIR-002, MIR-003). An earlier draft fetched an artifact only when a held index named it. That gate breaks the first run. A client whose local index copy predates the mirror asks for an artifact the mirror has no index for. It gets 404 and builds from source. The grammar bounds what the mirror requests (MIR-007, MIR-081), and a bound on absence records bounds what a client can make the mirror remember (MIR-002).

**Pins follow sealed closures, offline too.** The closure is the publisher's sealed catalogue for one commit. A head with no closure reads from the snapshot and the root. The index-source comments call those not curated and mutable. A project pinned there can build from source what the cache was meant to supply, and offline that build fails. So `min init` and `min update` pin the newest commit within 64 first-parent commits of the head that has a closure (MIR-050). This changes what `min update` means, from the head to the newest sealed commit. The reference pages that describe the re-pin change with it. The walk runs offline because the sync already walked the same commits online and recorded which closures do not exist (MIR-002, MIR-032). The sync walks only each upstream link's tracked branch, so the records it writes stay bounded by the registry. Those records never expire on their own, and the mirror asks the origin again only while it can reach it. A 502 is not a 404, so an absence the mirror never recorded ends the command rather than mis-pinning (MIR-050). Holding back the refs the mirror copies fails twice over. The mirror then alters what it copies (MIR-001), and the rule applies only through a mirror. This document takes a closure to mean that the pipeline built every artifact of the commit. Open questions asks the publisher to make sure of that.

**Off the VPN in one wait.** An organization's hosts stop resolving or stop answering when the laptop leaves the VPN. A box start asks for many objects, and each would wait for the operating system's connect timeout. The mirror bounds each connection attempt and remembers a failed host for 30 seconds (MIR-009). A start then pays one bounded failure per host and reads the rest from the copy.

**Companions now, verification later.** The publisher puts the closure's sigstore bundle and the commit map beside it, and each costs one request. The trusted root is one small file. Keeping them (MIR-005, MIR-006) lets a client-side verifier, once merged, run on a laptop that is offline. The companion table is the one place that takes a new published artifact, such as a per-artifact attestation.

**What a client can make the mirror do.** Only the user's own processes and the guest daemons reach the mirror (MIR-008, MIR-026). Through a door, a guest can make the mirror fetch an object in the grammar from the origin its path names (MIR-007, MIR-081), and copy a repository anonymously (MIR-082). It reaches every such host itself through the VM's network today, so the mirror widens no reach. A guest cannot register a project, change what is protected, or make the mirror present a credential (MIR-080, MIR-082).

**Messages.** Every message this document adds states one fact per line or names one command per line. The start failure names `min mirror status` and the opt-out setting on separate lines (MIR-020). A fetch the mirror does not answer, and a 502 it relays, name `min mirror status` (MIR-063). A missing Google credential names the login command (MIR-028). `prepare` names each unreachable origin, so the user knows which caches need the VPN (MIR-034). The budget shortfall names the setting and `min mirror forget` (MIR-042). The pin lines name the pinned commit and how far the head is ahead, or what can follow (MIR-050). None prints before the box shell (MIR-062). The tests named on each requirement pin the text.

**Tiers.** The decisions that are pure functions over in-memory inputs are T1. On the serving side those are the comparison of served bytes with origin bytes (MIR-001) and the path grammar (MIR-007). On the fetching side they are the repository rewrite (MIR-013), the outbound host bound (MIR-081) and the credential bound (MIR-082). On the keeping side they are the protected set (MIR-031) and eviction (MIR-040). Stating each as a property constrains it to a pure function separate from I/O. Eviction decides from a store snapshot, and a recording origin checks the host and credential bounds. Everything else is an effect with no decision of its own and stays T0. No requirement is T2, because the decisions range over unbounded strings and sets, not a small state machine. This document refuses T3: there is no Lean project.

**Generality:** a second deployment fits where it stays on the laptop. A native session daemon on a Linux laptop reads the host socket as the CLI does (MIR-021). A second VM, or a hundred, opens the same door (MIR-023). A second cache, public or private, needs no setting, because the origin is in the path (MIR-002), and a private bucket needs one line (MIR-028). What does not fit yet: a reader on another machine, which needs TLS and an identity (Non-goals). A repository host that speaks only ssh, or on a port, stays outside the copy (MIR-013).

## Security considerations

- **Invariant:** THE SYSTEM SHALL serve for any cache object key only bytes the origin that key names served for it.
  enforced by: a store written by rename from a temporary file that passed its hash check and never rewritten (MIR-073), and the artifact hash check on ingest (MIR-003)
  covered by: MIR-001, MIR-003, MIR-073
- **Invariant:** THE SYSTEM SHALL let only the user's own processes and the daemons in the user's VMs reach the mirror, and no process in a box.
  enforced by: no listener on an address, a host socket at mode 0600 in a 0700 directory (MIR-008), doors the VM host daemon connects, and the socket seal that refuses the vsock family in every box (MIR-026)
  covered by: MIR-008, MIR-023, MIR-026
- **Invariant:** THE SYSTEM SHALL serve every repository object with bytes whose hash equals the id the origin names.
  enforced by: git's own hashing of every object on receipt, from a local repository and from a bundle, and the checkout by commit hash
  covered by: MIR-010, MIR-013
- **Invariant:** THE SYSTEM SHALL request nothing outside its grammar, and connect to no host but the one a parsed path or a repository copy names. The trusted-root host is the one exception.
  enforced by: the mirror decides the grammar before any connection and follows no redirect (MIR-007, MIR-002)
  covered by: MIR-002, MIR-007, MIR-081
- **Invariant:** THE SYSTEM SHALL let no guest change what the mirror registers, protects or credentials.
  enforced by: the control verbs are on the host socket only (MIR-080). A repository a door names first is copied anonymously (MIR-027). MIR-002 caps the absence records a request can cause
  covered by: MIR-002, MIR-027, MIR-080, MIR-082
- **Invariant:** THE SYSTEM SHALL present a user's credential only for a repository a registration from the laptop named or a bucket the user's configuration lists, and only to that source's host.
  enforced by: the credential helpers are passed only to git commands for registered repositories (MIR-027), and the Google token only to requests for listed buckets (MIR-028). No credential is written to the store, the log or a response (MIR-083)
  covered by: MIR-027, MIR-028, MIR-082, MIR-083

## Open questions

- [NEEDS CLARIFICATION (HIGH): the spec number and the epic. `30` is the next free number in this tree. The epic issue does not exist yet, and the header holds a placeholder. Non-goals names the follow-up issues to file with it: the shared mirror and tiers, credentials through the Box Egress Proxy, the client-side verifier, source tarballs, and a login unit.]
- [NEEDS CLARIFICATION (HIGH): the node-plane baseline. NET's built-in baseline names the switch's host alias as the `cache` endpoint for the guest daemon's own traffic, and its enforcement waits on a cache answering there. Through the door, the guest's cache traffic leaves the network path entirely, and only a repository the mirror cannot copy reaches its origin over the network (MIR-025). NET's owner decides whether the `cache` entry goes, and whether a direct repository fetch stays admitted once the baseline is enforced.]
- [NEEDS CLARIFICATION (MEDIUM): MIR-050 changes `min update` from the head to the newest sealed commit. The publisher needs to make sure that a closure object means the pipeline built every artifact of that commit. The 64-commit range needs a check against how often `pkgs` publishes.]
- [NEEDS CLARIFICATION (MEDIUM): incremental bundles. A guest with an older clone fetches the whole bundle again after each change of refs (MIR-011). The mirror can keep a bundle per pair of consecutive refreshes, or accept a `have` commit, once the size of the default upstream's bundle is measured.]
- [NEEDS CLARIFICATION (MEDIUM): the bucket path. MIR-028 reads a `gs://` bucket as `https://storage.googleapis.com/<bucket>/<key>`. Whoever builds it confirms that this path serves the cache's keys, slashes included, for a public bucket read anonymously and for a private one read with a token.]
- [NEEDS CLARIFICATION (MEDIUM): the default budget. 20 GiB is a guess for a laptop.]
- [NEEDS CLARIFICATION (LOW): the trusted root. MIR-006 fetches the public-good trusted root as one file from the Sigstore TUF repository. A TUF client that follows the repository's own update chain is the stricter alternative, and the verifier spec can ask for it.]
- [NEEDS CLARIFICATION (LOW): a login unit. On-demand start serves each command that reads a project, but a sync runs only while the daemon is up. A laptop with no `min` command since boot syncs nothing. A user-level launch agent on macOS or a user unit on Linux can start it at login.]
- [NEEDS CLARIFICATION (LOW): companions. The publish pipeline emits SBOM and provenance outside this repository, and the tree shows a bundle for the closure only. A developer script fetches the commit map today from a second cache host, not the configured base. Once the publisher names the keys on the configured base, they become rows in the companion table (MIR-005). That includes any bundle for the snapshot and per-artifact attestations.]
- [NEEDS CLARIFICATION (LOW): a first copy for the guest. A fresh VM reads the default upstream's bundle through its door, and MIR-N02 bounds artifacts only. The benchmark recipe can time the bundle too once its size is known.]
