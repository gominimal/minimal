---
id: MIR
title: Mirror — a copy of the package cache and the package repositories that every daemon reads over HTTPS, so boxes come up offline
owner: msample
epic: gominimal/inbox#TBD
arch: none
arch_sha: "none"
updated: 2026-10-21
---

# MIR — Mirror — a copy of the package cache and the package repositories that every daemon reads over HTTPS, so boxes come up offline

## Context

Before its shell paints, a box needs the package repository at the project's pinned commit and the cache index for that commit. It also needs the artifact of every package it lists. All of that comes from the Internet, and nothing on the laptop holds it for long. The host CLI and each daemon keep separate caches. In a VM the daemon's cache sits on the VM's data volume, and a new VM starts with that volume empty. With no connection, `min init` in a fresh repository fails, and so does `min session activate`. That holds for packages this laptop downloaded yesterday as much as for new ones. Demos on conference networks hit this first, and the local-first ordering that [NET](../18-spec-box-networking/18-spec-box-networking.md) and [BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md) record puts the laptop first.

After this work merges, a mirror keeps a copy of what the daemons fetch. It also keeps what the user's projects and loadouts need, and any packages the user asks it to keep. Every daemon reads the mirror over HTTPS at a name its certificate covers, and checks that certificate against the authority its host configured. A client reads a laptop's own mirror and a shared one on an office network the same way. Online, nothing changes for the user. Offline, a new project and a new box come up from the copy, once the laptop was online with its own mirror running. A machine that only reads a shared mirror has no copy of its own, and a laptop in an office keeps its own mirror and points it at the shared one. The mirror keeps the signatures the publisher emits beside what they sign, so a client that checks them later can do so offline. The publisher's catalogue of one commit's artifacts is its closure, and a project pins to a commit whose closure the publisher sealed.

**Success:** `min mirror prepare` reports ready. Then the laptop's network interface goes down. `min init` in an empty git repository and `min session activate` reach a shell with the project's packages and the user's loadout packages. A new VM instance with an empty data volume does the same. `min mirror status` says what the mirror holds, what it protects and whether the host is ready for offline.

**First slice:** the mirror daemon serves cache objects and the default package repository over HTTPS on the laptop's loopback with a certificate authority it generated, `min` starts it on demand and checks that authority, the VM host daemon hands the guest the mirror's address and authority, and `min mirror status` prints the daemon, upstream, disk and repository lines. The mirror holds what clients fetched through it, within the default budget: MIR-001 to MIR-005, MIR-007, MIR-008 and MIR-009 without their operator-certificate and `system` sub-bullets, MIR-010 for the default upstream only, MIR-011 to MIR-014, MIR-020 without its registration and shared-mirror steps, MIR-021 to MIR-025, MIR-040, MIR-044, MIR-062 to MIR-064, MIR-070, MIR-073 and MIR-080 to MIR-084. Project registration, the planner, `min mirror prepare`, the age rule, sealed pins, the trusted root and a shared mirror's settings follow.

## Users and stories

**Roles:** developers on a laptop who are sometimes offline or about to be, and who watch their disk. A team that shares an office network. A reviewer of what a daemon trusts.

- AS A developer who is offline, I WANT `min init` and `min session activate` to work in a new repository from what this laptop holds, SO THAT I can start a project with no connection.
- AS A developer who is online, I WANT every fetch to pass through the mirror with no configuration, SO THAT what I used today is here tomorrow.
- AS A developer about to go offline, I WANT one command that fills the mirror and names what is still missing, SO THAT I board the plane knowing.
- AS A developer, I WANT to name packages the mirror always keeps, SO THAT a demo of a stack I never used works offline.
- AS A developer, I WANT a disk budget and a warning when it is too small for what I asked to keep, SO THAT the mirror neither fills my disk nor drops my packages without a word.
- AS A developer whose VM was re-created, I WANT its empty volume filled from the mirror, SO THAT a reset costs seconds and no download.
- AS A developer, I WANT the signatures published for what I hold kept beside it, SO THAT verification works offline once the client performs it.
- AS A developer, I WANT my project pinned to a commit the build pipeline sealed, SO THAT I never build from source what the cache was meant to supply.
- AS A team, I WANT one mirror on the office network that every laptop and every Box Host reads, SO THAT each artifact leaves the building once.
- AS A reviewer, I WANT every daemon to check the mirror's certificate against an authority I configured, SO THAT nothing on the network or on the machine can serve my boxes a crafted index.

## Requirements

### O1 One daemon, the upstream's layout, one transport

The mirror answers HTTPS on one TCP address, `127.0.0.1:7657` unless the `[mirror] listen` setting says otherwise, with a certificate for every name clients use (MIR-008). A Unix socket, the control socket, takes the `min mirror` verbs (MIR-081). Every client reads the mirror the same way. The host CLI and the native daemon read it at the loopback address. The in-VM daemon reads it at `host.min.internal`, the name the switch answers with the host alias that reaches the laptop's loopback. A daemon on another machine reads it at the name a shared mirror's operator chose. Each checks the certificate against the authority its host configured (MIR-009). The HTTPS keys are the upstream cache's keys, so one base URL points a client at the mirror. Everything that is not an upstream key sits under the reserved prefix `/-/`.

| Request path | Meaning | Lifetime |
|---|---|---|
| `/index.shisha` | the root index | mutable |
| `/<host>/<path>/<commit>.closure.shisha` | the sealed per-commit closure index | immutable |
| `/<host>/<path>/<commit>.shisha` | the per-commit snapshot index | immutable |
| `/<host>/<path>/<commit>.closure.shisha.sigstore.json`, `/<host>/<path>/<commit>.map.json` | companions of a closure | immutable |
| `/<sha256>.zst` | one artifact, named by the sha256 of its bytes | immutable |
| `/-/git/<host>/<path>[.git]/<file>` | a file of a package repository copy, `<file>` from the table under MIR-010 | refreshed |
| `/-/sigstore/trusted_root.json` | the Sigstore public-good trusted root | refreshed |

`<host>/<path>` is the slug the index keys already use: the repository URL with scheme, credentials, query, trailing slash and `.git` stripped, so `<path>` has one segment or more. Each segment is one or more of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `.`, `_` and `-`, and no segment is `.` or `..`. `<commit>` is 40 hex digits and `<sha256>` is 64. The first five rows are cache objects. The mirror ignores a query string under `/-/git/` and refuses one elsewhere.

- **MIR-001** WHEN a request names a cache object the mirror holds THE SYSTEM SHALL answer with the bytes the mirror last stored for that key, which are bytes the upstream served for it, unchanged.
  tier:     T1
  verify:   cargo nextest run -p minmirrord served_object_bytes_equal_upstream
  property: the mirror answers a cache object key with its last stored body for that key. The upstream served that body.
  <!-- the mirror is a copy, never an interpreter: every integrity check the client does today (sha256 on artifacts) keeps its meaning, and a verifier added later reads the publisher's bytes. The repository rows are git's own objects, which git hashes on receipt (MIR-010) -->

- **MIR-002** WHEN a request names an immutable cache object the mirror does not hold THE SYSTEM SHALL fetch it from the `[mirror] upstream` base, store it, and stream it to the client within the same request.
  tier:     T0
  verify:   cargo nextest run -p minmirrord immutable_miss_fetches_stores_and_streams
  <!-- pull-through: observed demand is the first source of what the mirror holds; a client never waits for a second request -->
  - THE SYSTEM SHALL treat a redirect from the upstream as a status other than 200 or 404, following none.
    tier:   T0
    verify: cargo nextest run -p minmirrord upstream_redirect_is_not_followed
    <!-- stricter than the client's own HTTP library, on purpose: the mirror connects to the one configured base and nowhere a redirect points -->
  - WHEN several clients request one object the mirror does not hold THE SYSTEM SHALL fetch it from the upstream once.
    tier:   T0
    verify: cargo nextest run -p minmirrord concurrent_misses_fetch_once
  - WHEN a HEAD request names an immutable cache object the mirror does not hold THE SYSTEM SHALL fetch and store it as for a GET and answer with the headers alone.
    tier:   T0
    verify: cargo nextest run -p minmirrord head_request_pulls_through
    <!-- a client warms a mirror without taking the body (MIR-034) -->
  - IF the upstream answers 404 THEN THE SYSTEM SHALL answer 404 and record the absence with its time.
    tier:   T0
    verify: cargo nextest run -p minmirrord upstream_absence_is_recorded
  - WHILE the mirror can reach the upstream THE SYSTEM SHALL ask the upstream again for a key whose absence record is older than 60 seconds, and answer 404 from the record otherwise.
    tier:   T0
    verify: cargo nextest run -p minmirrord absence_record_reasked_after_sixty_seconds
    <!-- a walk over many commits (MIR-050) asks the upstream once per object, and a closure published later is found within a minute -->
  - WHEN the upstream answers 200 for a key with an absence record THE SYSTEM SHALL drop the record.
    tier:   T0
    verify: cargo nextest run -p minmirrord absence_record_dropped_on_hit
  - IF the mirror cannot reach the upstream and holds an absence record for the key THEN THE SYSTEM SHALL answer 404 from the record, however old it is.
    tier:   T0
    verify: cargo nextest run -p minmirrord remembered_absence_served_when_offline
    <!-- the sealed-pin walk (MIR-050) runs offline only because the sync recorded, while online, which closures do not exist (MIR-032); a 502 would end the walk -->
  - THE SYSTEM SHALL keep at most 100 000 absence records, dropping the oldest first, except records a sync wrote (MIR-032), which leave when a later sync no longer visits their key.
    tier:   T0
    verify: cargo nextest run -p minmirrord absence_records_are_bounded
    <!-- a client can name any number of absent keys; the records it causes are bounded, and the ones the offline walk needs are not among those dropped -->
  - IF the mirror cannot reach the upstream, or the upstream answers a status other than 200 or 404, THEN THE SYSTEM SHALL answer 502 with the one-line body `the mirror could not reach <upstream>: <cause>` and store nothing.
    tier:   T0
    verify: cargo nextest run -p minmirrord upstream_failure_is_502_and_stores_nothing
    <!-- the cache reader retries an artifact's error status with its backoff and then fails; an index fetch fails on the first error status; MIR-063 turns either failure into a message that names the mirror. A 404 on the root index the client reads as an empty index, and an artifact 404 is retried then fatal, so an outage must never become a 404 -->

- **MIR-003** WHEN the mirror fetches an artifact `<sha256>.zst` from the upstream THE SYSTEM SHALL store it only when the sha256 of the received bytes equals its name.
  tier:     T0
  verify:   cargo nextest run -p minmirrord artifact_hash_mismatch_is_not_stored
  <!-- the mirror never serves a mismatched artifact from disk. An artifact is fetched by name alone, from the one configured base (MIR-002, MIR-007): a gate that required a held index to name the sha256 first was dropped, see Design reasoning -->
  - IF the hash does not match THEN THE SYSTEM SHALL end the client's response before completion.
    tier:   T0
    verify: cargo nextest run -p minmirrord artifact_hash_mismatch_truncates_response
    <!-- the client hashes too and retries a truncated body -->

- **MIR-004** WHILE the held copy of `/index.shisha` is younger than 5 minutes THE SYSTEM SHALL answer a request for it from that copy and contact no upstream.
  tier:     T0
  verify:   cargo nextest run -p minmirrord root_index_fresh_copy_answers_without_upstream
  <!-- 5 minutes is the client's own trust window for its local copy of the root index; one window, two layers -->
  - WHEN a client requests `/index.shisha` and the held copy is older than 5 minutes or absent THE SYSTEM SHALL revalidate it with the upstream by a conditional request, store the result, and answer with it. The mirror answers an upstream 404 as 404, which the client reads as an empty index.
    tier:   T0
    verify: cargo nextest run -p minmirrord root_index_revalidates_after_five_minutes
  - IF the mirror cannot reach the upstream and holds a copy THEN THE SYSTEM SHALL answer with the held copy and an `Age` header carrying its age in seconds.
    tier:   T0
    verify: cargo nextest run -p minmirrord root_index_served_stale_with_age_when_offline
  - IF the mirror cannot reach the upstream and does not hold a copy THEN THE SYSTEM SHALL answer 502 as MIR-002 does.
    tier:   T0
    verify: cargo nextest run -p minmirrord root_index_miss_offline_is_502

- **MIR-005** WHEN the mirror fetches a closure THE SYSTEM SHALL also fetch and store each companion the table above lists for it, from the same upstream base.
  tier:     T0
  verify:   cargo nextest run -p minmirrord companions_fetched_with_closure
  <!-- the closure's sigstore bundle signs the closure bytes (a hashedrekord bundle over its sha256); the commit map is what the publisher emits beside it; the client verifies neither yet, and keeping them now is what lets a verifier work offline later. The companion table is one place: a new published companion, such as a per-artifact attestation, is one row -->
  - IF the upstream does not publish a companion THEN THE SYSTEM SHALL treat it as absent and not as an error.
    tier:   T0
    verify: cargo nextest run -p minmirrord missing_companion_is_not_an_error

- **MIR-006** WHEN a sync runs (MIR-032) and the mirror can reach the upstream THE SYSTEM SHALL refresh its copy of the Sigstore public-good trusted root and serve it at `/-/sigstore/trusted_root.json`.
  tier:     T0
  verify:   cargo nextest run -p minmirrord trusted_root_refreshed_on_sync_and_served
  <!-- a sigstore bundle verifies against the trusted root (Fulcio and Rekor keys); offline verification needs a copy of it, and this is the only object the mirror fetches from a host other than the cache and the registered repositories -->

- **MIR-007** THE SYSTEM SHALL answer 404 to any request whose path matches no row of the table above, without contacting any upstream.
  tier:     T1
  verify:   cargo nextest run -p minmirrord paths_outside_the_grammar_are_404_without_upstream
  property: for every byte string used as a request path, the mirror opens an upstream connection only if the path parses as a row of the grammar.

- **MIR-008** THE SYSTEM SHALL serve HTTPS only, with TLS 1.2 or later and no plain HTTP on any address, with a certificate whose names include every entry of `[mirror] names`, default `127.0.0.1`, `localhost` and `host.min.internal`.
  tier:     T0
  verify:   cargo nextest run -p minmirrord serves_tls_only_for_configured_names
  <!-- the certificate is how a client tells the mirror from anything else that answers on the same address; a plain listener would be first-binder-wins on a shared machine. TLS 1.2 stays admitted because the host's git on macOS links a TLS library that may not negotiate 1.3 -->
  - WHERE `[mirror] cert` and `[mirror] key` name a certificate and its key THE SYSTEM SHALL serve that certificate.
    tier:   T0
    verify: cargo nextest run -p minmirrord serves_operator_certificate
    <!-- a shared mirror's operator brings a certificate from the organization's authority or a public one -->
  - WHERE `[mirror] cert` and `[mirror] key` are unset THE SYSTEM SHALL generate, at first start, a certificate authority valid for 10 years and a leaf certificate for the configured names valid for 90 days, keep both private keys at mode 0600 under the state directory, and write the authority's certificate at a fixed path in the state directory that `min mirror status` prints.
    tier:   T0
    verify: cargo nextest run -p minmirrord generates_authority_and_leaf_on_first_start
    <!-- the certificate shape the Box Egress Proxy's interception authority already has; a laptop's clients accept this one authority and nothing else for the mirror (MIR-009) -->
  - WHEN the generated leaf has less than 30 days left THE SYSTEM SHALL issue a new one from the same authority, so a client that checks against the authority never sees an expired certificate.
    tier:   T0
    verify: cargo nextest run -p minmirrord leaf_renewed_before_expiry

- **MIR-009** WHEN a client opens a connection to the mirror THE SYSTEM SHALL verify the certificate chain against the configured authority, and the certificate's names against the host in the mirror URL. The configured authority is the local mirror's own, or the one the file `[mirror] ca` names.
  tier:     T1
  verify:   cargo nextest run -p rcache mirror_certificate_verified_against_configured_authority_only
  property: given a mirror URL and a configured authority, for every certificate chain a server presents the client proceeds if and only if the chain ends at that authority and the leaf names the host in the URL.
  <!-- a client pinned to one authority accepts no certificate a public authority issued for a name it does not own, and no self-signed squatter -->
  - THE SYSTEM SHALL NOT accept a chain that ends at any other authority.
    tier:   T0
    verify: cargo nextest run -p rcache no_fallback_to_other_authorities
  - WHERE `[mirror] ca` is `system` THE SYSTEM SHALL verify against the host's system authorities instead.
    tier:   T0
    verify: cargo nextest run -p rcache system_authorities_when_configured
    <!-- a shared mirror behind a public certificate -->
  - IF verification fails THEN THE SYSTEM SHALL fail the fetch with two lines, `the mirror at <url> presented a certificate this host does not trust: <cause>.` and `Run min mirror status to see which authority this host trusts.`, on the surface where the daemon or the CLI reports a failed fetch today.
    tier:   T0
    verify: cargo nextest run -p mctx untrusted_mirror_certificate_names_authority_and_status
  - WHEN git fetches through the mirror THE SYSTEM SHALL give git the mirror's authority alone and let git follow no redirect.
    tier:   T0
    verify: cargo nextest run -p checkouts git_pinned_to_mirror_authority_follows_no_redirect
    <!-- git chooses its authority once, for the URL it starts with, and keeps it across a redirect; a redirect to the upstream would then fail its handshake, so the client reads the mirror's answer itself before it runs git (MIR-013) -->
  - WHERE the command is `mip` THE SYSTEM SHALL print, in place of the second line, `The authority is the file MINIMAL_MIRROR_CA names.`
    tier:   T0
    verify: cargo nextest run -p mip untrusted_certificate_message_without_min
    <!-- `mip` runs on hosts without `min`, and an instruction names a command the user can run -->

### O2 Package repositories

A registered repository is one of two things. It is the default upstream repository, the one `min init` writes to a new project. Or it is an `https` repository URL without user information and without a port that a registered project's `minimal.toml` names as its upstream or as a sideload. The mirror reads those links at the project's registration and at each sync (MIR-030). The mirror keeps a copy of each under `<store>/git/<host>/<path>`, with `<path>.git` as a second name for the same copy.

| `<file>` under a repository copy | Served |
|---|---|
| `HEAD`, `info/refs`, `objects/info/packs` | yes |
| `objects/<2 hex>/<38 hex>` | yes |
| `objects/pack/pack-<40 or 64 hex>.pack`, the same with `.idx` | yes |
| anything else, `config`, `hooks`, `objects/info/alternates` and `objects/info/http-alternates` included | no, 404 |

- **MIR-010** THE SYSTEM SHALL serve, under `/-/git/<host>/<path>`, the files the table above admits from the copy of each registered repository, as `text/plain` or `application/octet-stream`, so that `git` clones and fetches the copy over HTTPS and finds every branch head and tag the upstream had at the last refresh.
  tier:     T0
  verify:   cargo nextest run -p minmirrord registered_repo_clones_over_https
  <!-- git's dumb HTTP protocol reads static files, so no git process runs on the mirror; every client uses the git command line, which speaks it natively when the first answer is not the smart protocol's advertisement; git recomputes every object's hash on receipt and the checkout is by commit hash, so the copy cannot substitute content -->
  - WHEN a request names a repository that is not registered THE SYSTEM SHALL answer 302 to the same path and query under `https://<host>/`, without contacting any upstream.
    tier:   T0
    verify: cargo nextest run -p minmirrord unregistered_repo_redirects_to_upstream
    <!-- the client reads the redirect and fetches the upstream itself with the system authorities (MIR-013); offline that fetch fails as a direct fetch does today -->
  - WHEN a request names a registered repository that the mirror does not hold a copy of yet THE SYSTEM SHALL clone it before answering.
    tier:   T0
    verify: cargo nextest run -p minmirrord registered_repo_without_copy_clones_on_demand
    <!-- pull-through for repositories: the first client to ask waits for the clone, as it waited for its own clone from the upstream before -->
  - THE SYSTEM SHALL always register the default upstream repository.
    tier:   T0
    verify: cargo nextest run -p minmirrord default_upstream_is_always_registered

- **MIR-011** WHEN the mirror refreshes a repository THE SYSTEM SHALL fetch every branch and tag and remove the refs the upstream removed, so a client that fetched before sees the new heads.
  tier:     T0
  verify:   cargo nextest run -p minmirrord refresh_updates_heads_and_prunes
  - WHEN a refresh completes THE SYSTEM SHALL hold every object of the copy in a pack file, with no loose object left.
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_leaves_no_loose_objects
    <!-- git's default keeps a small fetch as loose objects, which a dumb-protocol client fetches one request each; the copy packs them so a refill is a few requests -->
  - WHEN a refresh publishes its result THE SYSTEM SHALL write the pack list before the refs, each by one atomic replacement.
    tier:   T0
    verify: cargo nextest run -p minmirrord pack_list_written_before_refs
    <!-- a dumb-protocol client reads the refs, then the pack list, then the packs; new refs beside an old pack list would name objects the list does not reach. Git's own server-info helper writes them in the other order, so the mirror writes both files itself -->
  - WHEN the mirror compacts a repository copy THE SYSTEM SHALL keep every file the copy served before the compaction readable for one hour after it, so a client that began a fetch before it completes that fetch.
    tier:   T0
    verify: cargo nextest run -p minmirrord compaction_keeps_old_files_an_hour
  - WHEN a refresh or a clone starts THE SYSTEM SHALL finish it, even when the request that triggered it stopped waiting (MIR-012), so no half-written copy is left behind.
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_runs_to_completion
  - THE SYSTEM SHALL run at most one clone or refresh of one repository copy at a time, with a request that needs a copy another operation is creating waiting for that operation and never for a sync.
    tier:   T0
    verify: cargo nextest run -p minmirrord one_writer_per_copy_and_waiters_skip_the_sync
    <!-- an on-demand clone (MIR-010) and the sync (MIR-032) can want the same copy; one writer per copy, and a waiter never queues behind a sync that is fetching artifacts -->

- **MIR-012** WHEN a request for `/-/git/<repo>/info/refs` arrives and the last refresh is older than 5 minutes, or a refresh request arrives over the control socket, THE SYSTEM SHALL refresh the repository first, bounded to 10 seconds, and then answer.
  tier:     T0
  verify:   cargo nextest run -p minmirrord refresh_request_refreshes_within_bound
  <!-- `min init` and `min update` ask for the newest head over the control socket before they resolve it; online they get it, offline they get the newest head the mirror saw, which is the newest commit whose supply can be here; a daemon elsewhere asks through the refs request -->
  - IF the refresh fails THEN THE SYSTEM SHALL answer with the held refs.
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_failure_answers_with_held_refs
  - IF the refresh exceeds the bound THEN THE SYSTEM SHALL answer with the held refs while the refresh completes (MIR-011).
    tier:   T0
    verify: cargo nextest run -p minmirrord slow_refresh_answers_with_held_refs
  - IF the repository has no copy THEN THE SYSTEM SHALL clone it first (MIR-010).
    tier:   T0
    verify: cargo nextest run -p minmirrord refresh_of_uncloned_repo_clones_first

- **MIR-013** WHERE `MINIMAL_MIRROR_URL` names a mirror (MIR-021) THE SYSTEM SHALL send every repository fetch whose URL has the scheme `https`, no user information and no port to `<mirror>/-/git/<host><path>`, by a setting passed to each git command and written into no file, when the mirror answers 200 to the client's own request for that repository's `info/refs`.
  tier:     T1
  verify:   cargo nextest run -p checkouts mirror_rewrite_redirects_fetch
  property: for every repository URL with an `https` scheme, no user information and no port, and every mirror base that answers 200 for its refs, git receives the base, `/-/git/`, then the host and path of the original URL.
  <!-- Git 2.55: `-c url.<base>.insteadOf=https://` clones and fetches from a static HTTP server and records the original URL as the remote; the client asks for the refs first over its own pinned connection (MIR-009), because git cannot change authority across a redirect -->
  - WHEN the mirror answers the client's refs request with 302 THE SYSTEM SHALL fetch the repository from its original URL, with no rewrite and the system authorities.
    tier:   T0
    verify: cargo nextest run -p checkouts unregistered_repo_fetched_from_upstream_after_302
    <!-- the mirror's redirect (MIR-010) is read by the client, never by git -->
  - THE SYSTEM SHALL keep the original URL as the repository's identity in the checkout registry and in every cache key.
    tier:   T0
    verify: cargo nextest run -p checkouts rewrite_keeps_original_url_as_identity
    <!-- cache keys embed the slug of the original URL (`<host>/<owner>/<repo>/<commit>.closure.shisha`), so the identity must not move with the fetch -->
  - IF the scheme of the URL is not `https`, or the URL includes user information or a port, THEN THE SYSTEM SHALL fetch it without a rewrite and never register it.
    tier:   T0
    verify: cargo nextest run -p checkouts non_https_credentialed_and_ported_urls_are_not_rewritten
    <!-- the rewrite is a textual prefix replacement; a credential in the URL would travel in a request path and the copy would be served to every reader; a port is a character the slug grammar does not admit; an `http` repository has no scheme to redirect to under `/-/git/` -->

- **MIR-014** THE SYSTEM SHALL run the mirror's own git commands with the user and system git configuration ignored, the credential helper disabled and prompts disabled. A repository that only the user's own git settings can reach stays out of the mirror.
  tier:     T0
  verify:   cargo nextest run -p minmirrord mirror_git_ignores_user_configuration

### O3 Reaching the mirror

The switch is the user-space network the VM host daemon runs for boxes, as [NET](../18-spec-box-networking/18-spec-box-networking.md) describes. It answers `host.min.internal` with the host alias, an address it translates to the laptop's loopback, and NET-130's node-plane baseline names that alias as the `cache` endpoint the in-VM daemon's own traffic reaches. A door is a vsock port the VM host daemon maps to a Unix socket on the host. The guest already uses doors to report boxes and to forward telemetry. The client configuration file is `<config>/minimal/config.toml`, the file `min dirs` prints, and `<config path>` in every message below is that path. Its `[mirror]` table holds:

| Key | Meaning | Default |
|---|---|---|
| `enabled` | run a mirror on this machine and read it | `true` |
| `url` | a shared mirror to read instead of running one here, for a machine without a copy of its own | unset |
| `ca` | the file holding the authority that signs the shared mirror's certificate, or `system` | the local mirror's own authority |
| `upstream` | the cache the local mirror copies, the public cache or another mirror | `https://cache.minimal.dev/` |
| `upstream_ca` | the authority for `upstream` when it is another mirror, or `system` | `system` |
| `listen` | the address the local mirror serves on | `127.0.0.1:7657` |
| `names` | the names the generated certificate covers | `127.0.0.1`, `localhost`, `host.min.internal` |
| `cert`, `key` | an operator's certificate and key, instead of generated ones | unset |
| `max_disk` | the store's budget (MIR-040) | `20 GiB` |
| `keep_unused_for` | the age rule (MIR-041) | `30d` |
| `always` | packages the mirror always keeps (MIR-031) | none |

- **MIR-020** WHEN `min` runs a command that reads a project, the client configuration enables the mirror and `url` is unset THE SYSTEM SHALL start the mirror daemon if it is not running and wait until it answers, bounded to 10 seconds.
  tier:     T0
  verify:   cargo nextest run -p minimal project_command_starts_mirror
  <!-- the shape the CLI already has for the VM host daemon: read the lifecycle, start detached if stopped, wait for the socket -->
  - WHEN the daemon answers THE SYSTEM SHALL register the project (MIR-030), then resolve every repository fetch of the command through the mirror, and every cache fetch too unless the environment sets `MINIMAL_REMOTE_CACHE_URL` (MIR-021).
    tier:   T0
    verify: cargo nextest run -p minimal project_command_registers_and_routes_through_mirror
  - WHERE `url` names a shared mirror THE SYSTEM SHALL resolve the same fetches through that mirror with the authority `ca` names, with no daemon started and nothing registered.
    tier:   T0
    verify: cargo nextest run -p minimal shared_mirror_url_routes_without_a_local_daemon
  - IF the mirror daemon does not answer within the bound THEN THE SYSTEM SHALL fail the command with exit 1 and print three lines: `the mirror did not start: <cause>.`, `Run min mirror status to see its state.` and `Set [mirror] enabled = false in <config path> to fetch without it.` The cause is the first line the daemon wrote to its standard error before it exited, as `min` reports the VM host daemon's start failure today. Any further lines print after the three.
    tier:   T0
    verify: cargo nextest run -p minimal mirror_start_failure_fails_command_naming_both_remedies
    <!-- a silent fallback to the upstream would hide a local fault behind a working day online and surface it offline; one line per fact, one action per line -->
  - THE SYSTEM SHALL NOT start the mirror daemon for `min mirror status` or `min mirror stop`.
    tier:   T0
    verify: cargo nextest run -p minimal status_and_stop_never_start_the_daemon
  - WHEN `mip` runs a command that reads a project THE SYSTEM SHALL route its fetches through the shared mirror `url` names, or through the local mirror when its daemon is running, and otherwise fetch as today and start nothing.
    tier:   T0
    verify: cargo nextest run -p mip mip_uses_configured_or_running_mirror_and_starts_none
    <!-- `mip` runs on build servers and CI runners, where a detached daemon with a disk budget is unwanted; on a laptop `min` keeps the mirror up and `mip` benefits -->

- **MIR-021** THE SYSTEM SHALL read two environment variables in `min`, in `mip`, in the native daemon and in the in-VM daemon. `MINIMAL_MIRROR_URL` is the mirror's HTTPS base, `https://127.0.0.1:7657/` for a local mirror read from the host, `https://host.min.internal:7657/` for one read from the guest, or a shared mirror's URL, and becomes the cache read URL and, with `/-/git/` appended, the repository base (MIR-013). `MINIMAL_MIRROR_CA` is the path of the authority's certificate, or `system`, and becomes the authority MIR-009 verifies against.
  tier:     T0
  verify:   cargo nextest run -p mctx mirror_variables_derive_cache_git_and_authority
  - WHEN `min` or `mip` resolves the two values THE SYSTEM SHALL derive them from the client configuration for a shared mirror and from the mirror's lifecycle file for a local one, and pass them, as the two variables, to every process it starts except the mirror daemon, where a process that finds them set uses them.
    tier:   T0
    verify: cargo nextest run -p minimal mirror_variables_derived_and_passed_on
  - WHEN a process resolves the cache read URL THE SYSTEM SHALL let `MINIMAL_REMOTE_CACHE_URL` win when set, then an explicitly configured location, then `MINIMAL_MIRROR_URL`, then the default.
    tier:   T0
    verify: cargo nextest run -p mctx mirror_url_replaces_the_default_location_only
    <!-- the mirror stands in for the default location, the public cache its `upstream` copies; a reader that pinned another location, by variable or by configuration, keeps it, and the writer's bucket is untouched, so an upload still goes to the configured bucket -->
  - WHERE the configured cache location is a `gs://` bucket THE SYSTEM SHALL fetch artifacts from that bucket and not through the mirror.
    tier:   T0
    verify: cargo nextest run -p mctx gcs_location_is_not_mirrored
  - THE SYSTEM SHALL start the mirror daemon with `MINIMAL_MIRROR_URL`, `MINIMAL_MIRROR_CA` and `MINIMAL_REMOTE_CACHE_URL` unset, and the daemon SHALL fetch from `[mirror] upstream` alone.
    tier:   T0
    verify: cargo nextest run -p minmirrord daemon_starts_without_client_variables
    <!-- the daemon's own graph evaluation runs through the same build context the clients use, which reads the cache variable; with the variables unset it never fetches from itself -->
  - WHERE `[mirror] upstream` names another mirror THE SYSTEM SHALL fetch cache objects and repository copies from it, checking its certificate against `upstream_ca` as MIR-009 does.
    tier:   T0
    verify: cargo nextest run -p minmirrord chained_mirror_fetches_from_upstream_mirror
    <!-- a laptop in an office keeps its own copy and fills it from the office mirror, which fills from the Internet -->
  - WHERE `mip --no-fetch` is present THE SYSTEM SHALL NOT fetch an artifact, from the mirror or from the upstream, as today. `mip --offline` keeps its meaning for sources and checkouts.
    tier:   T0
    verify: cargo nextest run -p mctx no_fetch_skips_the_mirror_too

- **MIR-022** WHERE the client configuration file sets `[mirror] enabled = false` THE SYSTEM SHALL fetch from the upstream as it does today, which means a stopped mirror daemon, unset variables and a closed door.
  tier:     T0
  verify:   cargo nextest run -p minimal mirror_disabled_leaves_fetch_paths_unchanged
  - THE SYSTEM SHALL read the `[mirror]` table from the client configuration file in `mip` and in the VM host daemon as well as in `min`.
    tier:   T0
    verify: cargo nextest run -p minvmd vm_host_daemon_reads_mirror_table_from_client_config
    <!-- today `mip` reads no user configuration file and the VM host daemon reads only its own provider file, so both gain a reader of this one table -->

- **MIR-023** WHERE the VM host daemon boots a guest and the client configuration enables the mirror THE SYSTEM SHALL start the local mirror daemon if `url` is unset and it is not running, serve on the vsock door 7354 the mirror URL as the guest reaches it and the authority's certificate or the word `system`, and put the token `MINIMALD_MIRROR_DOOR=7354` on the guest's command line.
  tier:     T0
  verify:   cargo nextest run -p minvmd vm_boot_serves_mirror_settings_on_door_and_passes_token
  <!-- the URL the guest reaches is `https://host.min.internal:7657/` for a local mirror and the shared URL otherwise; the door is the same call the READY marker, the box report door and the telemetry door use, and it carries the certificate, which does not fit the command line; the token is printable ASCII with no space and carries no secret -->
  - THE SYSTEM SHALL place the door token on the command line before the telemetry tokens, never dropping it, with the telemetry tokens judged against the budget that remains.
    tier:   T0
    verify: cargo nextest run -p minvmd door_token_survives_a_full_command_line
    <!-- the telemetry tokens are dropped as a group when the line's budget overflows; the door token must not be in that group, or a long telemetry filter would silently take the mirror away from the guest -->

- **MIR-024** WHEN the in-VM daemon starts with `MINIMALD_MIRROR_DOOR` on its command line THE SYSTEM SHALL read the mirror URL and the authority from that door before it reports ready, keep the authority's certificate under its state directory, and resolve its own cache and repository fetches through that URL with that authority (MIR-009), over the switch.
  tier:     T0
  verify:   cargo nextest run -p minimald guest_reads_mirror_settings_from_door_and_uses_them
  <!-- the same two settings the host's processes carry as variables (MIR-021), delivered over the one channel that exists before the guest has a network -->
  - WHEN the token is absent THE SYSTEM SHALL fetch from the upstream directly, as it does today.
    tier:   T0
    verify: cargo nextest run -p minimald no_door_token_fetches_upstream

- **MIR-025** WHILE the in-VM daemon holds a mirror URL THE SYSTEM SHALL send its own cache and repository traffic to the host of that URL only, and to an upstream host only where the mirror answered a redirect (MIR-010).
  tier:     T0
  verify:   cargo nextest run -p minvmd guest_supply_traffic_goes_to_mirror_host
  <!-- runs on the VM lane; for a local mirror the host is the switch's host alias, the `cache` endpoint NET-130's baseline already names. In force, that baseline admits the alias alone: it closes the redirect path for the guest and reaches a shared mirror only once the `cache` category names that mirror's host, which is NET's to configure -->

### O4 The protected set and the sync

- **MIR-030** WHEN `min` or `mip` registers a project (MIR-020) THE SYSTEM SHALL record the project's root and the time over the control socket, read its `minimal.toml`, register the repositories its links name (O2), and answer at once.
  tier:     T0
  verify:   cargo nextest run -p minmirrord registration_records_root_and_links
  <!-- a copy of a newly registered repository appears on its first request (MIR-010) or at the next sync, whichever comes first -->
  - WHEN the project has no `minimal.toml` THE SYSTEM SHALL register the root alone.
    tier:   T0
    verify: cargo nextest run -p minmirrord registration_without_mfile_records_root
    <!-- `min init` registers before the file exists and reads the default upstream, which is always registered (MIR-010) -->
  - THE SYSTEM SHALL NOT make a registration wait for a running sync.
    tier:   T0
    verify: cargo nextest run -p minmirrord registration_does_not_wait_for_sync
  - WHEN a sync runs THE SYSTEM SHALL read each registered project's `minimal.toml` again at that time, so it follows a moved pin and a new link without a new registration.
    tier:   T0
    verify: cargo nextest run -p minmirrord sync_reads_current_pin_and_links
  - WHEN a registered project's `minimal.toml` was unreadable at every sync for 30 days, or no command ran in the project for 90 days, THE SYSTEM SHALL drop the project from the registry and list it in the next `min mirror status` under `dropped:`.
    tier:   T0
    verify: cargo nextest run -p minmirrord stale_project_dropped_and_listed_once
  - WHEN `min mirror forget <path>` is run THE SYSTEM SHALL drop the project now and print two lines: `forgot <path>.` and `Its artifacts are no longer protected.`
    tier:   T0
    verify: cargo nextest run -p minimal forget_drops_project_and_prints_outcome

- **MIR-031** WHEN a sync runs THE SYSTEM SHALL compute the protected set as the union of the artifact sets the table below lists, together with the index objects, companions and repository copies those resolutions read, all for the target this machine's boxes run, which is Linux on the machine's architecture. An artifact set is the artifact the index names for each package in the transitive closure of the listed packages, resolved against the graph at the listed commit.
  tier:     T1
  verify:   cargo nextest run -p minmirrord protected_set_covers_projects_and_new_projects
  property: for every row of the table and every package in the transitive closure of that row's packages at its commit, the protected set holds the artifact the index names for that package at that commit.
  <!-- the daemon composes a loadout's packages into the box and resolves them against the project's graph at the project's pin, so a loadout's artifacts differ per project and are protected per project; the resolution is the graph code `mip` and the daemons share through the build context, not the session daemon itself; a package the index does not name has no artifact to protect and is reported (MIR-034) -->

  | Row | Packages | Commit |
  |---|---|---|
  | each registered project | the packages of every box entry in its `minimal.toml`, which today are the `[session]` table and the `[tasks.*]` entries and under BOX also the `[sessions.*]` and `[boxes.*]` entries, the packages of the stack it names and the `build_packages` and `runtime_packages` its `[stack]` table adds, the packages of every loadout in the user's loadouts directory, and the `[mirror] always` packages | the project's pinned upstream, with its pinned sideloads |
  | new projects | the packages of every loadout in the user's loadouts directory and the `[mirror] always` packages | the newest sealed commit of the default upstream's `main` (MIR-050) |

- **MIR-032** WHEN the daemon starts, WHEN 60 minutes passed since the last sync, WHEN a project's first registration arrives and WHEN `min mirror prepare` is run THE SYSTEM SHALL run a sync.
  tier:     T0
  verify:   cargo nextest run -p minmirrord sync_triggers
  - WHEN a sync runs THE SYSTEM SHALL refresh every registered repository and clone any without a copy (MIR-011), then walk each branch head of each registered repository through its first-parent ancestors until it finds a sealed closure or reaches 64 commits, fetching the closures that exist and recording the absences (MIR-002), then fetch the index objects and companions of every pinned commit, then fetch every protected artifact not held, within the disk budget (MIR-042).
    tier:   T0
    verify: cargo nextest run -p minmirrord sync_order
    <!-- the walk is what lets MIR-050 run offline -->
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

- **MIR-034** WHEN `min mirror prepare` is run against the local mirror THE SYSTEM SHALL run a sync now, wait for it, and print one line per row of the MIR-031 table, each with the row's name, the pin, `sealed` or `unsealed` (MIR-051), the held and total artifact counts and the bytes missing.
  tier:     T0
  verify:   cargo nextest run -p minimal prepare_reports_coverage
  <!-- the surface that stays; the activate path prints nothing new (MIR-062) -->
  - WHEN the mirror holds every protected artifact THE SYSTEM SHALL print `ready for offline` and exit 0.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_ready_exit_zero
  - WHEN a protected artifact is missing THE SYSTEM SHALL print one line per reason, one of `upstream unreachable`, `not in any index` or `disk budget exceeded`, with the count and size it covers, then `not ready for offline: <n> artifacts missing (<size>).`, and exit 1.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_not_ready_exit_one
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
  - WHERE `[mirror] url` names a shared mirror THE SYSTEM SHALL compute the protected set on this machine, ask that mirror for every missing artifact and index object by a HEAD request (MIR-002), print the same rows, and end with `the shared mirror at <url> holds every artifact this machine needs.` and exit 0, or `the shared mirror at <url> is missing <n> artifacts (<size>).` and exit 1.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_against_shared_mirror_warms_by_head
    <!-- a shared mirror has no registration from other machines (MIR-081); a client can still make it hold what the client needs, and the operator's budget and always list decide how long it stays; this machine holds no copy, so it prints no ready line -->
  - IF the client configuration disables the mirror THEN THE SYSTEM SHALL print three lines, `the mirror is turned off by [mirror] enabled = false in <config path>.`, `Set [mirror] enabled = true in <config path>.` and `Run min mirror prepare again.`, and exit 2.
    tier:   T0
    verify: cargo nextest run -p minimal prepare_refused_when_disabled

### O5 Disk

- **MIR-040** WHILE an eligible object remains THE SYSTEM SHALL keep the store's total size at or under `[mirror] max_disk`, default `20 GiB`, by evicting eligible objects in order of oldest last request first. An eligible object is an unprotected artifact with no request in flight and a last request more than an hour old.
  tier:     T1
  verify:   cargo nextest run -p minmirrord eviction_is_lru_over_eligible_objects
  property: for every store state and every eviction run, each removed object was eligible. No removed object had a request more recent than any retained eligible object. Afterwards the total is at or under the budget, or no eligible object remains.
  - THE SYSTEM SHALL NOT evict a protected object, an object requested within the last hour, an object with a request in flight, an index object or companion, or the repository copy of a registered repository.
    tier:   T0
    verify: cargo nextest run -p minmirrord eviction_spares_protected_recent_indexes_and_copies
    <!-- a client keeps its copy of a per-commit index for ever and never asks again, so an index must outlive the budget; the indexes of registered projects are protected (MIR-031) and the rest leave by age (MIR-041) -->
  - IF the store exceeds the budget and no eligible object remains THEN THE SYSTEM SHALL report `the store exceeds the budget: <used> of <max_disk>.` in `min mirror status` and in its log.
    tier:   T0
    verify: cargo nextest run -p minmirrord over_budget_with_nothing_eligible_is_reported
    <!-- a burst of distinct real artifacts within one hour, a large registered repository, or the protected set alone can pass the ceiling -->
  - WHILE the store exceeds the budget and `listen` is a loopback address THE SYSTEM SHALL still fetch an object a client requests.
    tier:   T0
    verify: cargo nextest run -p minmirrord over_budget_loopback_keeps_fetching
    <!-- the only client is the user's own; a refused fetch online would send it to build from source -->
  - WHILE the store exceeds the budget and `listen` is not a loopback address THE SYSTEM SHALL answer 507 for an object it does not hold.
    tier:   T0
    verify: cargo nextest run -p minmirrord over_budget_on_network_refuses_misses
    <!-- a client on the network must not be able to grow the store past the operator's ceiling -->

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

- **MIR-044** THE SYSTEM SHALL keep the store, with the mirror's own layer cache for graph evaluation, under the user's cache directory, and the registry, lifecycle file, log, keys and control socket under the user's state directory, each directory with mode 0700 and at paths that do not change between runs.
  tier:     T0
  verify:   cargo nextest run -p minmirrord store_and_state_paths_and_modes
  - WHEN `min dirs` is run THE SYSTEM SHALL print both paths.
    tier:   T0
    verify: cargo nextest run -p minimal dirs_prints_mirror_store_and_state

### O6 Pins follow sealed closures

- **MIR-050** WHEN `min init`, `min update`, `mip init`, `mip update` or `mip run` with an inline upstream resolves the upstream's branch head to a pin THE SYSTEM SHALL ask the mirror to refresh the repository (MIR-012) and then pin the newest commit, among the head and its first-parent ancestors up to 64 commits back, for which the cache publishes a sealed closure.
  tier:     T0
  verify:   cargo nextest run -p op pin_follows_newest_sealed_closure
  <!-- the closure is the publisher's sealed catalogue for one commit; the snapshot is an uncurated copy of the root at publish time and the root is mutable (the 2026-08-17 dangling-index incident the index-source comments in mfile record). A project pinned to a commit with no closure reads the uncurated chain and may build from source what the cache was meant to supply. Each existence probe is one request to the mirror, answered from its absence records offline (MIR-002, MIR-032); the probes may run concurrently. Against a shared mirror the refresh request is the refs request (MIR-012). The reference pages that describe the re-pin, the `min update` section of the CLI reference and the `locked_commit` paragraph of the `minimal.toml` reference, change with this requirement -->
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

- **MIR-051** WHEN `min mirror status` or `min mirror prepare` lists a row THE SYSTEM SHALL mark its pin `sealed` when the mirror holds, or the upstream publishes, the pin's closure object, and `unsealed` otherwise.
  tier:     T0
  verify:   cargo nextest run -p minmirrord status_marks_pin_sealed_or_unsealed

### O7 Observability

- **MIR-060** WHEN `min mirror status` is run THE SYSTEM SHALL print the lines the table below lists, in that order, and exit 0 when the daemon is running and 1 otherwise.
  tier:     T0
  verify:   cargo nextest run -p minimal status_report_fields_and_exit_code
  <!-- the one surface that stays and that every warning in this document points at; the first slice prints the `mirror:`, `certificate:`, `upstream:`, `disk:` and `repositories:` lines -->
  - WHERE the `--json` flag is present THE SYSTEM SHALL print the same facts as one JSON document under the schema `min/v1/mirror-status`.
    tier:   T0
    verify: cargo nextest run -p minimal status_json_schema
  - WHERE `[mirror] url` names a shared mirror THE SYSTEM SHALL print `mirror: shared at <url>`, the `certificate:` line for the authority `ca` names, and whether the last request to it succeeded, and exit 0 when it did and 1 otherwise.
    tier:   T0
    verify: cargo nextest run -p minimal status_for_shared_mirror

  | Line | Content |
  |---|---|
  | `mirror:` | the daemon's state, and when running its process id and URL |
  | `certificate:` | the path of the authority's certificate this host checks the mirror against, and for a generated leaf its expiry |
  | `upstream:` | the last successful contact and, when later, the last failure with its cause |
  | `last sync:` | when the last sync ran and whether it completed |
  | `disk:` | bytes in use, bytes protected, and the budget, then the MIR-040 and MIR-042 lines when they apply |
  | `projects:` | the lines MIR-034 prints for the rows of the MIR-031 table |
  | `repositories:` | one line per repository copy with its heads and last refresh |
  | `dropped:` | projects dropped since the last status (MIR-030), when any |
  | last lines | the ready line MIR-034 prints, followed when not ready by `Run min mirror prepare to fetch them.` |

  ```text
  mirror: running (pid 41234) at https://127.0.0.1:7657/
  certificate: ~/.local/state/minimal/mirror/ca.pem, leaf valid 61 more days
  upstream: reachable, last contact 3 min ago
  last sync: 3 min ago, complete
  disk: 8.2 GiB in use, 6.9 GiB protected, 20 GiB budget
  projects:
    ~/src/railway-demo   pkgs@bd62e6e2 sealed     142/142 artifacts
    ~/src/blog           pkgs@840fd07d sealed      96/98 artifacts, 21 MiB missing
    new projects         pkgs@bd62e6e2 sealed      49/49 artifacts
  repositories:
    github.com/gominimal/pkgs   main bd62e6e2   refreshed 3 min ago
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

- **MIR-063** IF a fetch through the mirror fails because the mirror does not answer THEN THE SYSTEM SHALL fail that fetch with two lines, `the mirror at <url> did not answer: <cause>.` and `Run min mirror status to see its state.`, on the surface where the daemon or the CLI reports a failed fetch today.
  tier:     T0
  verify:   cargo nextest run -p mctx mirror_unanswered_names_mirror_and_status_command
  - IF the mirror answers 502 THEN THE SYSTEM SHALL fail that fetch with the 502 body (MIR-002) as its first line and `Run min mirror status to see its state.` as its second.
    tier:   T0
    verify: cargo nextest run -p mctx mirror_502_body_reaches_the_user
    <!-- today the reader renders an error status as its variant name; through the mirror the body says what the user needs, that the upstream is out of reach -->
  - WHERE the fetch runs in the in-VM daemon THE SYSTEM SHALL print the same lines on the same surface.
    tier:   T0
    verify: cargo nextest run -p minimald guest_fetch_failure_names_mirror_and_status_command
  - WHERE the command is `mip` THE SYSTEM SHALL print, in place of the second line, `The mirror is the one MINIMAL_MIRROR_URL or [mirror] url in <config path> names.`
    tier:   T0
    verify: cargo nextest run -p mip fetch_failure_message_without_min
    <!-- `mip` runs on hosts without `min`, and an instruction names a command the user can run -->

- **MIR-064** WHEN the cache reader receives an answer with an `Age` header THE SYSTEM SHALL record the age in its log.
  tier:     T0
  verify:   cargo nextest run -p rcache stale_answer_age_is_logged
  <!-- the header the mirror sets on a stale root index (MIR-004) has a reader, so a stale offline answer is traceable -->

### O8 Lifecycle

- **MIR-070** THE SYSTEM SHALL run the mirror as `minmirrord run [--detach]` and stop it with `minmirrord stop` and `min mirror stop`.
  tier:     T0
  verify:   cargo nextest run -p minmirrord run_detach_and_stop_round_trip
  <!-- the VM host daemon's shape: a lifecycle file, an alive lock, a detached re-exec -->
  - IF the process a running state names no longer exists THEN THE SYSTEM SHALL report the mirror as stopped and start it on the next demand (MIR-020).
    tier:   T0
    verify: cargo nextest run -p minmirrord dead_process_reads_as_stopped
  - IF `git` is not on the daemon's `PATH` THEN THE SYSTEM SHALL refuse to start, exit 1, and write two lines to its standard error: `git is not installed.` and `The mirror needs it to copy package repositories.` When `min` started the daemon, those lines are the `<cause>` of MIR-020's first line.
    tier:   T0
    verify: cargo nextest run -p minmirrord missing_git_refuses_start
    <!-- `min init` on the host already requires git for the same reason -->
  - IF `[mirror] cert` or `[mirror] key` names a file that does not exist or does not parse THEN THE SYSTEM SHALL refuse to start, exit 1, and write one line per failing file to its standard error: `[mirror] cert in <config path> names <path>, which could not be read: <cause>.`, with `key` in place of `cert` for the key.
    tier:   T0
    verify: cargo nextest run -p minmirrord bad_operator_certificate_refuses_start

  - WHEN two starters race to start the mirror THE SYSTEM SHALL leave one daemon running and let both starters proceed against it within MIR-020's bound.
    tier:   T0
    verify: cargo nextest run -p minmirrord racing_starters_share_one_daemon
    <!-- `min` and each VM host daemon start the mirror on demand; the alive lock decides the winner and the loser waits for its socket -->

- **MIR-071** THE SYSTEM SHALL keep the mirror daemon's life independent of the VM host daemon and the session daemon. `min stop` leaves it running, a VM restart or a new VM instance reuses it, and only `min mirror stop`, `minmirrord stop` or the installer stops it.
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

### O9 Security

- **MIR-080** THE SYSTEM SHALL listen for HTTPS only on the address `[mirror] listen` names, default `127.0.0.1:7657`, and for control only on a Unix socket created with mode 0600 in a directory with mode 0700.
  tier:     T0
  verify:   cargo nextest run -p minmirrord listens_on_configured_address_and_private_control_socket
  <!-- the default keeps the mirror on the laptop's loopback, which the switch's host alias reaches for the guest; an operator widens the address for a shared mirror; whoever answers on either, a client accepts only the configured authority (MIR-009) -->

- **MIR-081** THE SYSTEM SHALL accept registration, refresh, `prepare`, `forget`, `clean` and `stop` only over the control socket, and never over HTTPS.
  tier:     T0
  verify:   cargo nextest run -p minmirrord control_verbs_refused_over_https
  <!-- a client on the network, the guest included, must not be able to register a repository or change what is protected; a refresh of an already registered repository is the one upstream contact a request can cause, and it reaches only that repository's host -->

- **MIR-082** THE SYSTEM SHALL open an upstream connection only for a key in the grammar, and only to the configured cache base or to the host of a registered repository. The one exception is the Sigstore trusted-root host, for `/-/sigstore/trusted_root.json` alone.
  tier:     T1
  verify:   cargo nextest run -p minmirrord upstream_hosts_bounded_by_registrations
  property: for every request sequence from clients, every connection the mirror opens goes to the cache base's host or to a registered repository's host. The trusted root is the only fetch that goes elsewhere.

- **MIR-083** THE SYSTEM SHALL NOT hold a credential or send an authentication header to any upstream.
  tier:     T0
  verify:   cargo nextest run -p minmirrord no_credentials_sent_upstream
  <!-- MIR-013 keeps credentialed URLs out of the registry and MIR-014 keeps the user's credential helpers out of the mirror's git -->

- **MIR-084** THE SYSTEM SHALL keep the generated authority's and leaf's private keys readable by the user alone, never served, logged or printed.
  tier:     T0
  verify:   cargo nextest run -p minmirrord private_keys_never_leave_the_state_dir

## Non-goals

- Private repositories and authenticated upstream hosts. The client fetches a credentialed URL as today, and the mirror never registers it (MIR-013). Credentialed fetches belong with the Box Egress Proxy's modules ([BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md)).
- Checking the sigstore bundles and the trusted root in the client. That is a separate spec, one of the issues the first Open question names. This document keeps their bytes (MIR-005, MIR-006) so that check works offline.
- Source tarballs by hash under `/-/src/`. That is the second slice, one of the issues the first Open question names. A package the index does not name builds from source, and `min mirror prepare` names it (MIR-034).
- A shared mirror's control plane for other machines: registration, protection and `forget` from a client that is not on the mirror's machine. Those need an identity for the caller and belong with the identity plane ([BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md) names Gatehouse). A client of a shared mirror reads it and warms it by request (MIR-034).
- How a Box Host on another machine receives the mirror URL and the authority. The daemon reads the two settings from its environment (MIR-021). The identity plane's enrollment delivers them, one of the issues the first Open question names.
- Proxying a box's own egress. That is [BEP](../24-spec-box-egress-proxy/24-spec-box-egress-proxy.md) and [NET](../18-spec-box-networking/18-spec-box-networking.md). The mirror serves the daemons' supply, not a box's traffic.
- The daemons' own extracted caches. They stay with `mip cache clean` and the session daemon's maintenance actor, which reclaim them today. The mirror holds compressed artifacts, and the daemons still extract into their own caches. A client's checkout also keeps its own bare clone of each repository, as it does today, outside the mirror's budget.
- Starting the mirror at login through a macOS launch agent or a systemd user unit. The CLI and the VM host daemon start it on demand (MIR-020, MIR-023). A login unit is one of the issues the first Open question names.

## Non-functional requirements

- **MIR-N01** WHILE streaming an object it is fetching from the upstream THE SYSTEM SHALL relay each received chunk to the client before the upstream response completes.
  tier:   T0
  verify: cargo nextest run -p minmirrord streamed_fetch_is_not_buffered

- **MIR-N02** WHILE answering a held artifact to the guest THE SYSTEM SHALL start the response within 100 ms at the 95th percentile on an idle host.
  tier:   T0
  verify: just bench-mirror guest_time_to_first_byte
  <!-- a new recipe over a new `scripts/bench-mirror.sh`; the existing boot benchmark takes no case argument, so this one is its own script -->

- **MIR-N03** THE SYSTEM SHALL run at most 8 upstream fetches at a time.
  tier:   T0
  verify: cargo nextest run -p minmirrord upstream_fetches_are_bounded
  <!-- the number the build orchestrator fetches with today; a client on the network cannot turn the mirror into a flood against the upstream -->

- **MIR-N04** WHILE the layer cache already holds every registered pin's evaluation THE SYSTEM SHALL compute a sync's protected set for 10 registered projects within 5 seconds on an idle host.
  tier:   T0
  verify: just bench-mirror protected_set_ten_projects
  <!-- the layer cache the build context already keeps makes a re-evaluation at a known pin cheap; this bounds what the loadout superset costs -->

## Design reasoning

**A copy of the upstream's layout, not a new protocol.** The cache reader already accepts an `http` or `https` base URL. Under it the reader fetches `index.shisha`, the per-commit objects and `<sha256>.zst` with plain GET requests. The mirror serves the same keys, so the reader changes nothing but the authority it trusts (MIR-001, MIR-009). Every check the client does today keeps its meaning. A verifier added later reads the publisher's bytes. A store with an API of its own fails this test. Every client then needs a second code path, and the publisher's signatures no longer cover what the client reads.

**Every client reads one HTTPS base.** An earlier draft used a Unix socket and `file://` paths on the host and a vsock relay in the guest. A plain loopback port is first-binder-wins, and another account on the machine can serve a crafted index on it. TLS with a configured authority closes that hole without a second transport. A squatter on the port cannot present a certificate the configured authority signed, and a client pinned to that authority accepts nothing else (MIR-008, MIR-009). So every client, on the host, in the guest and on another machine, reads one HTTPS base. The guest reaches the laptop's mirror at `host.min.internal`, the name the switch already answers with the alias that translates to the laptop's loopback, and that alias is the `cache` endpoint NET-130's node-plane baseline already names. A shared mirror on an office network is the same client code with a different URL and authority (MIR-020, MIR-021). A laptop that needs its own copy points its mirror's `upstream` at the shared one instead, so the office mirror fills from the Internet and the laptop fills from the office (MIR-021). The earlier design also made the in-VM daemon independent of any network, which holds only for a VM on the laptop. A Box Host elsewhere reaches its mirror over the network or not at all, so one network transport is the general shape.

**The laptop's mirror signs for itself.** A laptop has no authority to hand out certificates, so the mirror generates one at first start and a leaf for its names under it (MIR-008), the shape the Box Egress Proxy's interception authority already has. The authority's certificate is public and lives at a fixed path, which the host's clients read and the VM host daemon hands the guest over a door (MIR-023, MIR-024). The door delivers the certificate because the kernel command line, which delivers the other guest settings, has a byte budget a certificate strains and a group of tokens it drops under pressure. A fingerprint on the command line, with the certificate fetched over the untrusted connection and checked against it, does not fit either. It needs a custom verifier in the client and a second step at every boot. A shared mirror's operator brings a certificate instead, from the organization's authority or a public one, and its clients configure that authority or the system roots (MIR-008, MIR-009).

**Git over its dumb protocol, with a redirect for the rest.** Every client runs the git command line, which reads a repository from static files over HTTPS. The mirror keeps mirror clones and writes the two metadata files the protocol reads itself, in the order a reader needs (MIR-011). It serves only the admitted files (MIR-010). A bare clone also holds its configuration, hooks and alternates files, and git's walker follows alternates to other locations. Git hashes every object on receipt, and the checkout is by commit hash, so the copy cannot swap in other content. Git 2.55 clones and fetches this layout against a static server. It follows a redirect and records the original URL as the remote. A smart-protocol server needs a process per request, so it does not fit. A tarball of the tree at a commit does not fit either, because nothing can check it against the commit hash. An unregistered repository redirects to its upstream (MIR-010), so the rewrite never breaks an online clone. The client reads that redirect itself, before it runs git, and then runs git against the original URL with the system authorities (MIR-013). Git picks its authority once for the URL it starts with and keeps it across a redirect, so git following the redirect under the mirror's authority fails the upstream's handshake. The copy packs what each refresh fetched (MIR-011), because git keeps a small fetch as loose objects and a dumb-protocol client fetches each with one request. A compaction, when the copy's pack files pass 16, writes one pack and keeps the old files an hour (MIR-011). A dumb-protocol client lists the packs first and fetches them one by one.

**The mirror clones on request.** The mirror clones a registered repository without a copy when a client first asks for it (MIR-010), at the cost the client's own clone from the upstream had before. Registration itself records and returns (MIR-030), so a `min` command never waits for a sync. An earlier draft cloned at registration because host clients read the store as files. With one HTTPS transport that need is gone.

**One rewrite rule, the identity untouched.** Git's `insteadOf` setting replaces a URL prefix. One rule, passed to each git command, maps every `https://` repository to `<mirror>/-/git/<host><path>` (MIR-013). Git records the original URL as the remote, and the cache keys embed its slug. The rewrite touches the fetch only. A URL with user information or a port is left alone, because the replacement is textual and the credential ends up in a request path, and a port is not in the slug grammar (MIR-013). Rewriting the URL in `minimal.toml` fails because it changes the cache keys and ties the project file to one machine.

**A daemon of its own, named for its binary.** The VM host daemon runs for one VM and does not exist on a native Linux host. The session daemon owns one extracted cache, and in the VM it loses that cache with the volume. The CLI is not a service. The mirror outlives all of them (MIR-071) and serves `mip` on a host without `min`. Its lifecycle has the shape the VM host daemon's has (MIR-070). Folding it into the VM host daemon fails because a VM re-creation is the event it must survive. The crate takes the binary's name, `minmirrord`, as the other daemons' crates do, so no stale binary under a second name can linger in a build directory. `mip` uses a configured or running mirror and starts none (MIR-020). `mip` also runs on build servers and CI runners, where a detached daemon with a disk budget has no place.

**The daemon resolves packages itself, per project.** Keeping the protected set warm without a user command is the point of the mirror. So the daemon resolves packages to artifacts itself, with the graph code `mip` and the daemons share (MIR-031, MIR-032). The daemon composes a loadout's packages into a box and resolves them against the project's graph at the project's pin. One loadout yields different artifacts in different projects, and the mirror protects them per project. Every loadout on disk counts, not only the default ones, because the user can apply any of them at the next activation and the extra cost is a few more roots in a graph the layer cache already holds (MIR-N04). A separate row at the newest sealed commit of the default upstream covers the project `min init` is about to create. Resolving in the CLI and handing the daemon a list fails because the set is then fresh only when the user runs the command. Asking the running session daemon fails because it can be down, and because it couples two lifecycles. The daemon reads none of the client variables (MIR-021), so it never fetches from itself. A client of a shared mirror has no registration there, so it computes the same set itself and warms the mirror with HEAD requests (MIR-002, MIR-034), and the operator's budget decides how long it stays. On a network, a store over its budget refuses misses (MIR-040) and MIR-N03 bounds upstream fetches, because a client there is not the operator.

**Observed demand is the baseline, the lists are the promise.** Everything fetched through the mirror stays until eviction (MIR-033). That is the usage history. Registered projects, loadouts and the always list are what the user said they need (MIR-031). The mirror protects exactly those and evicts only among the rest (MIR-040). The budget is a ceiling. The mirror never exceeds it silently, and it reports a protected set larger than the ceiling instead of trimming it (MIR-042). Evicting protected objects to fit fails because an offline user then finds a promise broken with no warning. A sync runs on a project's first registration and not on every command (MIR-030, MIR-032), because every `min` command in a project registers it. Indexes and companions never leave by budget (MIR-040). A client keeps its own copy of a per-commit index for ever and asks only for the artifacts it names.

**The mirror fetches artifacts by name, with no catalogue gate.** The mirror fetches any artifact whose name parses, from the one configured base, and keeps it only when the bytes hash to the name (MIR-002, MIR-003). An earlier draft fetched an artifact only when a held index named it. That gate breaks the first run. A client whose local index copy predates the mirror asks for an artifact the mirror has no index for. It gets 404 and builds from source. The channel the gate closed is 32 bytes per request to the vendor's own cache host, which no attacker observes. The grammar and the one configured base bound what the mirror requests (MIR-007, MIR-082), and a bound on absence records bounds what a client can make the mirror remember (MIR-002).

**Pins follow sealed closures, offline too.** The closure is the publisher's sealed catalogue for one commit. A head with no closure reads from the snapshot and the root. The index-source comments call those not curated and mutable. A project pinned there can build from source what the cache was meant to supply, and offline that build fails. So `min init` and `min update` pin the newest commit within 64 first-parent commits of the head that has a closure (MIR-050). This changes what `min update` means, from the head to the newest sealed commit. The reference pages that describe the re-pin change with it. The walk runs offline because the sync already walked the same commits online and recorded which closures do not exist (MIR-002, MIR-032). Those records never expire on their own, and the mirror asks the upstream again only while it can reach it. A 502 is not a 404, so an absence the mirror never recorded ends the command rather than mis-pinning (MIR-050). Holding back the refs the mirror advertises fails twice over. The mirror then alters what it copies (MIR-001), and the rule applies only through a mirror. This document takes a closure to mean that the pipeline built every artifact of the commit. Open questions asks the publisher to make sure of that.

**Companions now, verification later.** The publisher puts the closure's sigstore bundle and the commit map beside it, and each costs one request. The trusted root is one small file. Keeping them (MIR-005, MIR-006) lets a client-side verifier, once merged, run on a laptop that is offline. The companion table is the one place that takes a new published artifact, such as a per-artifact attestation.

**What a client can make the mirror do.** The mirror fetches only keys in its grammar (MIR-007). It copies a repository only when the mirror's own machine registered it (MIR-010, MIR-081). It connects only to the cache base and the registered repositories, plus the trusted-root host (MIR-082). It follows no redirect (MIR-002). A client on the network can ask the mirror only for what a publisher catalogued or the mirror's machine registered. The one upstream contact it can cause is a refresh of a registered repository from that repository's own host.

**Messages.** Every message this document adds states one fact per line or names one command per line. The start failure names `min mirror status` and the opt-out setting on separate lines (MIR-020). A fetch the mirror does not answer, a 502 it relays, or a certificate the host does not trust each name `min mirror status` (MIR-009, MIR-063). The budget shortfall names the setting and `min mirror forget` (MIR-042). The pin lines name the pinned commit and how far the head is ahead, or what can follow (MIR-050). None prints before the box shell (MIR-062). The tests named on each requirement pin the text.

**Tiers.** The decisions that are pure functions over in-memory inputs are T1. On the serving side those are the comparison of served bytes with upstream bytes (MIR-001) and the path grammar (MIR-007). On the trust side it is the certificate verdict (MIR-009). On the fetching side they are the URL rewrite (MIR-013) and the upstream host bound (MIR-082). On the keeping side they are the protected set (MIR-031) and eviction (MIR-040). Stating each as a property constrains it to a pure function separate from I/O. Eviction decides from a store snapshot, and a recording upstream checks the host bound. Everything else is an effect with no decision of its own and stays T0. No requirement is T2, because the decisions range over unbounded strings and sets, not a small state machine. This document refuses T3: there is no Lean project.

**Generality:** a second deployment fits by construction. The laptop, the guest and a Box Host on another machine read one HTTPS base with one configured authority (MIR-009, MIR-021). A shared mirror is the same daemon with a wider `listen` and an operator's certificate (MIR-008, MIR-080). Changing the configured base points the mirror at a second upstream cache, because the grammar is the publisher's layout. What does not fit yet: registration and protection from another machine, which need the caller's identity (Non-goals). A repository host that speaks only ssh, or on a port, stays outside the rewrite (MIR-013).

## Security considerations

- **Invariant:** THE SYSTEM SHALL serve for any cache object key only bytes the upstream served for that key.
  enforced by: a store written by rename from a temporary file that passed its hash check and never rewritten (MIR-073), and the artifact hash check on ingest (MIR-003)
  covered by: MIR-001, MIR-003, MIR-073
- **Invariant:** THE SYSTEM SHALL let a client proceed only with a mirror whose certificate chains to the authority that client's host configured, for the name the client used.
  enforced by: the client's verifier pinned to one authority with no fallback (MIR-009), and git's authority setting scoped to the mirror URL (MIR-009)
  covered by: MIR-008, MIR-009
- **Invariant:** THE SYSTEM SHALL serve every repository object with bytes whose hash equals the id the upstream names.
  enforced by: git's own hashing of every object on receipt, and the checkout by commit hash
  covered by: MIR-010, MIR-013
- **Invariant:** THE SYSTEM SHALL request nothing outside its grammar. It SHALL connect to no host but the cache base and the hosts of registered repositories. The trusted-root host is the one exception.
  enforced by: the mirror decides the grammar before any connection and follows no redirect (MIR-007, MIR-002). Only the control socket can register a repository (MIR-081)
  covered by: MIR-002, MIR-007, MIR-010, MIR-081, MIR-082
- **Invariant:** THE SYSTEM SHALL let no client on the network change what the mirror holds or registers, and SHALL bound what such a client can make it remember.
  enforced by: the control verbs are on a Unix socket only the mirror's own machine reaches (MIR-081). HTTPS serves reads only. MIR-002 caps the absence records
  covered by: MIR-002, MIR-081
- **Invariant:** THE SYSTEM SHALL keep every private key readable by the user alone and never send it anywhere.
  enforced by: key files at mode 0600 under a 0700 directory, which the mirror neither serves nor logs (MIR-044, MIR-084)
  covered by: MIR-044, MIR-084
- **Invariant:** THE SYSTEM SHALL NOT hold an upstream credential or send one upstream.
  enforced by: there is no credential input. MIR-013 keeps credentialed URLs out of the registry and MIR-014 keeps the user's git configuration out of the mirror. MIR-083 sends nothing upstream that authenticates
  covered by: MIR-013, MIR-014, MIR-083

## Open questions

- [NEEDS CLARIFICATION (HIGH): the spec number and the epic. `30` is the next free number in this tree. The epic issue does not exist yet, and the header holds a placeholder. Non-goals names the follow-up issues to file with it.]
- [NEEDS CLARIFICATION (HIGH): the authority on the laptop. MIR-008 has the mirror generate its own authority and MIR-023 hands the guest its certificate over a door. The alternatives are a fingerprint on the kernel command line with the certificate fetched and pinned at first contact, or the Box Egress Proxy's key store issuing the mirror's leaf under its own root. The owner picks one. The host's git on macOS also needs a check that it negotiates TLS 1.2 or later against the mirror.]
- [NEEDS CLARIFICATION (HIGH): the shared mirror's trust. MIR-009 pins a client to one authority with no fallback, and `ca = "system"` is the way to a public certificate. Whether the first shared mirror runs under an organization's authority or a public one decides which path gets the first test.]
- [NEEDS CLARIFICATION (MEDIUM): MIR-050 changes `min update` from the head to the newest sealed commit. The publisher needs to make sure that a closure object means the pipeline built every artifact of that commit. The 64-commit range needs a check against how often `pkgs` publishes.]
- [NEEDS CLARIFICATION (MEDIUM): the default budget. 20 GiB is a guess for a laptop. A shared mirror needs a larger one, and its operator sets it.]
- [NEEDS CLARIFICATION (MEDIUM): the cache reader's TLS. The reader's HTTP library builds with its default features off and reaches TLS only through the platform verifier another dependency enables, which consults the system roots. The reader needs its own TLS feature and a client built over a one-root store for MIR-009, with the platform verifier kept for `ca = "system"`. Whoever builds this confirms the one-root client passes MIR-009's property.]
- [NEEDS CLARIFICATION (LOW): the trusted root. MIR-006 fetches the public-good trusted root as one file from the Sigstore TUF repository. A TUF client that follows the repository's own update chain is the stricter alternative, and the verifier spec can ask for it.]
- [NEEDS CLARIFICATION (LOW): a login unit. On-demand start serves each command that reads a project, but a sync runs only while the daemon is up. A laptop with no `min` command since boot syncs nothing. A user-level launch agent on macOS or a user unit on Linux can start it at login.]
- [NEEDS CLARIFICATION (LOW): companions. The publish pipeline emits SBOM and provenance outside this repository, and the tree shows a bundle for the closure only. A developer script fetches the commit map today from a second cache host, not the configured base. Once the publisher names the keys on the configured base, they become rows in the companion table (MIR-005). That includes any bundle for the snapshot and per-artifact attestations.]
- [NEEDS CLARIFICATION (LOW): a first clone from the guest. A fresh VM clones the default upstream over the switch, and MIR-N02 bounds artifacts only. The benchmark recipe can time that clone too once the copy's pack layout settles.]
