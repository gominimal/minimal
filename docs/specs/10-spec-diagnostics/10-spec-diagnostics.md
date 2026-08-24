---
id: spec-diagnostics
title: "Diagnostics subsystem: `min bug` support bundles and the logs they collect"
kind: spec
status: planned
tracking-issue: 801
supersedes:
---

# Diagnostics subsystem: `min bug` support bundles and the logs they collect

## Context

When a session transport dies silently mid-flight, diagnosis runs entirely on
files scraped off disk after the fact — and today the highest-value files do
not exist. The in-VM daemon logs to a console the VMM discards, and the host
CLI has no way to capture what the guest was doing when it died. Incidents of
this class are root-caused by hand — thread stacks, socket states, the data
volume's mtime dating the stall — with every artifact collected manually. A
"run one command and send us the output" story does not exist.

A complete reference implementation of that story exists on the branch
`min-bug-diagnostics` (head `77fc711e`): a `min bug` command producing a
redacted `minimal-diag-<ts>.tar.zst`, a daemon-side streaming subsystem
contributing an in-VM bundle, persistent daemon logs for both daemons, and
the field-incident captures (boot.log, hang triage, degraded-mode volume
harvest, sleep/wake history). It grew too large to review as a single change;
this spec re-lands it as independently mergeable units. Baselines below cite
the reference tree as `ref:` alongside the `origin/main` state each unit
lands on. Units take final-tree file states from that branch — not
cherry-picked commit sequences — because review fixes are interleaved across
its history.

Scope boundaries settled during design review:

- App-agnostic machinery lives in a dedicated `diagnostics` crate; only
  `bug`-command-specific code stays in `crates/minimal`, and `common` stays
  free of diagnostics logic.
- Correlation metadata belongs on tracing spans, not hand-stamped per-line
  fields.
- Process-global mutable state for the log-release hook is out; the release is
  owned by `ServerState` and invoked through it.

Domain vernacular (Session, Provider, the socket lifecycle) is defined in
`docs/session-domain-diag.md` and used here without redefinition. The bundle
explorer tooling on branch `diag-explore-script` (`scripts/diag-explore.py`)
is prior art for Unit 8.

## Introduction/Overview

One command, one artifact: `min bug` assembles a `minimal-diag-<ts>.tar.zst`
containing host system state, redacted config, state-dir listings, logs,
process/network/power captures, and one nested bundle per provider produced by
the daemon itself over a one-shot streaming RPC (`DiagBundleTarZst`). Every
collector is independent and failure-isolated: a fully broken install still
yields a valid archive whose `manifest.json` explains what is missing and why.
Nothing mutates state or autospawns daemons — diagnosing a wedged system must
not change it.

The subsystem stands on three legs:

1. **A `diagnostics` crate** — bundle writer (file-backed or streaming),
   manifest, fail-closed key-based redaction, metadata-only listings, and
   subprocess capture. The CLI and the daemon apply identical mechanics; both
   bundle layers carry the same `manifest.json` schema.
2. **Logs that exist before anything goes wrong** — both daemons persist
   rolling, size-capped file logs (minvmd when detached; minimald onto the
   data volume, with a release hook so the volume still unmounts cleanly), and
   log lines follow OTEL-compatible structured conventions so host and guest
   records correlate on ids, not timestamps and guesswork.
3. **A collection path with no liveness assumptions** — the daemon bundle is a
   single tar.zst blob over the existing SSH subsystem transport; when the
   daemon is unreachable, `min bug` degrades to reading the guest's log
   directory straight out of the ext4 volume image. The wedged case is the
   design center, not the edge case.

## Goals

1. A user on a broken install runs `min bug` and gets a shareable archive; the
   command never aborts because a collector failed, and `manifest.json`
   accounts for every collected, skipped, and errored entry.
2. Bundled config and captured environment are redacted fail-closed: unknown
   keys in env-shaped tables mask by default, sensitive key parts mask
   everywhere, and redaction failure withholds content rather than shipping it.
3. Both daemons produce persistent, size-capped, rotated file logs that
   survive the process — including across the microVM's volume quiesce — so a
   post-mortem always has something to read.
4. Host and guest log records correlate: span-carried ids, one trace id per
   operation across the CLI→daemon boundary, OTEL-compatible field
   conventions, no OTEL runtime dependency.
5. The daemon contributes its own view (meta, logs, state listing, sessions,
   proc/net/disk) as a nested bundle over a single-shot streaming RPC; a
   daemon that refuses the subsystem fails fast with the reason relayed to
   the user.
6. When the daemon or transport is the suspect, the bundle still captures the
   guest: socket probe stages pinpoint where contact broke, and the data
   volume's vital signs and `/logs` tree are harvested read-only from the
   image.
7. Every PR in the series is functionally complete, under 1000 changed lines,
   and CI-green alone.

## User Stories

- As a user with a wedged session, I want to run one command and send one
  file, so that I do not have to hand-collect logs I do not know exist.
- As a minimal developer triaging a field report, I want the bundle to tell me
  what was *not* collected and why, so that absence of evidence is itself
  evidence.
- As a security-conscious user, I want config and environment values scrubbed
  by default, so that sharing a bundle does not leak tokens or keys.
- As a minimal developer debugging a cross-boundary failure, I want one trace
  id to follow an attach from the CLI into the guest daemon's logs, so that
  correlation is a grep, not an inference.
- As a user whose VM will not respond at all, I want `min bug` to still say
  what the guest was doing when it died, so that "it's frozen" reports are
  self-diagnosing.

## Porting baseline — reconciling the reference tree with current `main`

The reference branch (`77fc711e`) is a single 4107-line change; the earlier
units have already merged and reshaped the tree the later ones build on. Take
file **content** from the reference, but reconcile it against the layout the
merged units have produced — the reference's private helpers have since moved
into shared crate surfaces, and a verbatim copy will not compile. Current
state a later unit must build against (verify with `ls`/`cat` before
starting, as the merged surface is the truth):

- **`diagnostics` crate (Units 1-2, merged).** App-agnostic mechanics already
  exported: `bundle` (`BundleWriter`, `BundleSink`, `LOG_TAIL_CAP`,
  `open_regular_nofollow`), `capture` (`command_capture`, `first_stdout_line`,
  `Capture`), `disk` (`disk_usage`, `DiskUsage`), `listing`, `logs`
  (`newest_rotated`), `manifest`, `redact` (`is_sensitive_key`,
  `is_env_table_name`, `redaction_placeholder`, `redact_json`, `redact_toml`,
  `masked_process_env`), `system` (`system_info`, `SystemInfo`, `DiskInfo`).
  A collector moving into the crate (Unit 5's `net`/`procs`/`power`) **must
  consume these** rather than the reference files' private near-duplicates —
  the reference's own subprocess runners become `capture::command_capture`,
  its local `statvfs` becomes `disk::disk_usage`.
- **`crates/minimal/src/diag/` (Unit 2, merged).** `mod.rs` (`cmd_bug`, the
  `collect_step!` macro, the provider skip), `collect.rs` (host collectors),
  `redact.rs` (CLI **policy** only: the env-value allowlist over the crate's
  `is_sensitive_key`). No `net`/`procs`/`power`/`guest` yet — those arrive
  with Units 5 and 7. The `--no-guest`/`--guest-timeout-secs` flags are **not
  present** (deferred to Unit 7); the provider loop currently records a skip.
- **`crates/minimald` (Unit 3, merged).** Daemon file logging is a
  `DaemonLogger` in `src/logging.rs` (console + a reloadable file layer;
  release owned by `ServerState`, run at shutdown). Rotation is
  `tracing-appender` **daily** (not size-based). Unit 6's `DiagBundleTarZst`
  arm slots into the current `handle_ssh_rpc` dispatch in `src/rpc.rs`
  **beside `STREAM_WORKSPACE_FILES`** — in both the take-and-`channel_success`
  match and the spawn match (grep the constant; do not trust a line number).
- **`crates/minimald-rpc` (Unit 4).** The `trace` module (`TraceContext`,
  `TRACEPARENT_ENV`) and the JSON-lines file format land with Unit 4; Unit 6's
  dispatch runs inside that unit's trace span, so the guest bundle's records
  already carry the propagated `trace_id`. Confirm Unit 4 has merged before
  building Unit 6's serving path.

Citations of the form `path:NN` against `77fc711e` are stable (pinned commit);
citations against `origin/main` drift — re-anchor them by grepping the named
symbol.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2). These IDs are referenced directly by the planner — do
> not renumber after approval.

---

### Unit 1: `diagnostics` crate foundation

**Purpose:** The app-agnostic machinery every later unit consumes: a bundle
writer that works file-backed (CLI) or streaming (daemon), the manifest
schema, the fail-closed redaction engine, metadata-only listings, and a
unified subprocess capture helper.

**Depends on:** None

**Affected areas:**
- `crates/diagnostics/` (new crate): `src/{lib.rs,bundle.rs,manifest.rs,redact.rs,listing.rs,capture.rs}`, `Cargo.toml`
- Root `Cargo.toml` — workspace member + `diagnostics` workspace dep

**Baseline:**
- No diagnostics crate exists on `origin/main` — **NOT YET IN CODEBASE**.
- ref: the crate exists complete on `min-bug-diagnostics`
  (`crates/diagnostics/src/{bundle.rs,manifest.rs,redact.rs,listing.rs}`)
  minus two deltas this unit adds: `BundleWriter` is file-only
  (`bundle.rs:39` `create(out_path, ...)`) — **STREAM MODE NOT YET IN
  CODEBASE** — and there is no `capture` module (three private near-duplicate
  command runners live in `crates/minimal/src/diag/{collect.rs:95,net.rs:135,procs.rs:126}`).
- ref: `walkdir.workspace = true` in `crates/diagnostics/Cargo.toml:17` is an
  unused dependency (the `walkdir` at `bundle.rs:234` is a local test fn) —
  **DROPPED IN THIS UNIT**.
- ref: `crates/diagnostics/src/lib.rs` exposes raw `pub mod`s and the manifest
  types are exhaustive with public fields — **VIOLATES
  docs/rust-coding-standards.md:50-51** (`pub use` curation,
  `#[non_exhaustive]` on public types that may grow); fixed in this unit.

**Functional Requirements:**

- **R1.1**: `crates/diagnostics` shall be a workspace member library crate
  depending only on pre-existing workspace deps (anyhow, async-compression,
  async-tar, chrono, serde, serde_json, tokio; tempfile dev-only). No
  `walkdir`.
- **R1.2**: `bundle.rs` shall define
  ```rust
  pub struct BundleWriter<W: AsyncWrite + Unpin + Send + Sync = tokio::fs::File>
  ```
  with two constructors: `create(out_path, root, version)` — file-backed,
  archive created `0600` via `OpenOptions::mode` before any content is
  written, every entry prefixed `{root}/` — and `stream(writer, version)` —
  entries at archive top level with **no root prefix** (the daemon bundle is
  rootless; exact-key consumers depend on it). The default type parameter
  keeps `&mut BundleWriter` compiling unchanged at every CLI collector call
  site. The `Sync` bound is load-bearing: `async_tar::Builder` requires it
  (see Technical Considerations).
- **R1.3**: `finish(...)` shall write the manifest as the final archive entry
  — at `{root}/manifest.json` in file-backed mode, at top-level
  `manifest.json` in stream mode — then finalize the underlying writer via a
  sealed strategy: file-backed flushes and `sync_all`s; stream mode flushes
  and shuts down the writer. Both paths produce a manifest with
  `schema_version: 1`, `created_at`, `version`, `duration_ms`,
  `collected[] {path, redaction, bytes}`, `skipped[] {what, reason}`,
  `errors[] {collector, error, duration_ms}`.
- **R1.4**: `add_file_tail` shall open collected files **without following
  symlinks** — `O_NOFOLLOW` via `OpenOptions::custom_flags`, with an
  open-then-`fstat` regular-file verification on the descriptor as the
  fallback — never a check-then-open sequence, which is TOCTOU-racy (ref:
  `bundle.rs:92-133` uses `symlink_metadata` before open; this unit upgrades
  it). The read is bounded with `Read::take(cap)` so a file growing mid-read
  cannot exceed the recorded cap.
- **R1.5**: `redact.rs` shall define the key-based policy engine:
  `is_sensitive_key` (substring parts list, with compound-key handling such
  that `public_key` only exempts when no sensitive part remains after
  stripping it — `public_key_token` masks), `is_env_table_name`,
  `redaction_placeholder` (`<redacted:len=N>`), and `redact_json` (recursive;
  env-shaped tables mask **all** child values regardless of key). Redaction is
  fail-closed: a value that cannot be parsed for selective redaction is
  withheld or masked wholesale, never passed through.
- **R1.6**: `listing.rs` shall produce metadata-only recursive listings
  (name, size, kind — with symlinks reported as symlinks, not their targets)
  bounded by an entry cap, returning a structured result that distinguishes
  failure from emptiness: an unreadable root is `Err` (the caller records a
  manifest error), per-entry read failures are recorded inline, and hitting
  the cap appends an explicit trailing truncation marker
  (`… truncated at N entries`).
- **R1.7**: `capture.rs` (new) shall define the single subprocess helper
  ```rust
  pub async fn command_capture(cmd: &str, args: &[&str], timeout: Duration) -> Result<Capture>
  ```
  with `kill_on_drop(true)`, capturing stdout+stderr+status, replacing the
  three private near-duplicates in the reference tree.
- **R1.8**: The public API shall be curated per repository standards: crate
  root `pub use` of `BundleWriter`, `Redaction`, `LOG_TAIL_CAP`,
  `capture::{command_capture, Capture}`, and the manifest types;
  `#[non_exhaustive]` on `Manifest`, `CollectedEntry`, `SkippedEntry`,
  `CollectorError`, and `Redaction`.

**Proof Artifacts:**

1. **Test:** unit tests for redaction (compound public-key regressions:
   `public_key_token`, `public_key_password`, `private_public_key`), tail-cap
   bounding, symlink rejection, listing caps and truncation marker —
   covers R1.4-R1.6.
2. **Test:** the same entry set written through `create` and through `stream`
   round-trips to identical archives modulo the root prefix, each carrying
   the manifest as its final entry at the exact mode-specific path
   (`{root}/manifest.json` file-backed; top-level `manifest.json` streamed)
   — covers R1.2, R1.3.
3. **Test:** archive created with mode `0600` — covers R1.2.
4. **Test:** a subprocess exceeding its timeout is terminated
   (`kill_on_drop`), with captured stdout/stderr/status retained alongside a
   typed timeout error — covers R1.7.

---

### Unit 2: `min bug` host bundle

**Purpose:** The command exists and is useful on day one: host system state,
environment, redacted config, state listing, and every log file the install
has produced, in a manifest-bearing archive. Collectors are failure-isolated;
the run never aborts.

**Depends on:** Unit 1

**Affected areas:**
- `crates/minimal/src/diag/mod.rs` (new) — `BugArgs`, `cmd_bug`, `collect_step!`
- `crates/minimal/src/diag/collect.rs` (new) — system/env/config/state/logs collectors
- `crates/minimal/src/diag/redact.rs` (new) — the env-value allowlist policy
- `crates/diagnostics/src/redact.rs` — grows the TOML walker (`redact_toml`,
  beside `redact_json`) and `masked_process_env` over a caller-supplied
  allowlist predicate
- `crates/diagnostics/src/logs.rs` (new) — `newest_rotated(dir, prefix, n)`
- `crates/diagnostics/src/disk.rs` (new) — `disk_usage` (statvfs)
- `crates/diagnostics/src/system.rs` (new) — `system_info`, the host
  identity/capability probe (uname facts, euid, KVM availability, disk
  capacity over caller-supplied paths)
- `crates/diagnostics/src/capture.rs` — grows `first_stdout_line`
- `crates/minimal/src/dirs.rs` — print→String refactor so the `min dirs` table can be captured
- `crates/minimal/src/lib.rs` — `Command::Bug` wiring
- `crates/minimal/Cargo.toml` — `diagnostics`, `toml`, `libc`;
  `crates/diagnostics/Cargo.toml` — `toml`
- `crates/minimal/tests/bug.rs` (new) — host-only integration test

The mechanics/policy split is deliberate and forward-looking: every
mechanism this unit introduces has a second consumer in the daemon bundle
(its own rotated volume logs, allowlisted guest env, volume disk usage), so
the mechanics land app-agnostic in the crate on first use, and the CLI
contributes only policy — the allowlist, the log prefixes, the config
paths, and the archive layout.

**Baseline:**
- No `bug` subcommand on `origin/main` — **NOT YET IN CODEBASE**.
- ref: `crates/minimal/src/diag/mod.rs:83-94` (collector step list),
  `collect.rs` (all collectors), `diag/redact.rs` (TOML + env allowlist),
  `dirs.rs` refactor. This unit takes those file states **minus** the guest
  surface: no `guest/net/procs/power` modules, no `--no-guest`/
  `--guest-timeout-secs` (flags gating nothing arrive with the behavior in
  Unit 7), no provider section (`collect.rs:415-532` defers to Unit 7), and
  the `dirs.rs` daemon-log note hunk (`dirs.rs:158-165,389-393`) defers to
  Unit 3 (those logs do not exist until then).
- `cargo build -p minimal` runs on the macOS lane but its tests do not
  (`.github/workflows/ci-macos.yml:432-439`) — **ALREADY SATISFIES** the
  cross-platform constraint provided no `mod common;` (daemon test harness)
  is included while unused (dead-code warnings fail clippy `-D warnings`).

**Functional Requirements:**

- **R2.1**: `min bug [--output <path>]` shall assemble
  `minimal-diag-<UTC ts>.tar.zst` via `BundleWriter::create`, honoring the
  same `--minimal-dir`/`--config-dir` overrides as the rest of the CLI.
- **R2.2**: Each collector shall run under a per-collector timeout (30 s);
  failure or timeout is recorded as a manifest error and the run continues
  (ref: `collect_step!`, `mod.rs:51-66`). The command mutates no state and
  spawns no daemons. Filesystem errors are never reported as absence: an
  unreadable directory is a manifest error or an `unreadable` skip, and
  absence claims ("no provider instances found", "no log directory") may
  only be made on a true NotFound.
- **R2.3**: `host/system.json` shall capture the host identity/capability
  probe (`diagnostics::system_info`): OS/arch, kernel and hostname (uname),
  cpu count, euid, KVM availability (Linux only, cfg-gated), and disk usage
  (statvfs) of the state, cache, and invoking dirs — the probed paths are
  the CLI's policy, the probe itself is crate machinery any bundle-producing
  binary can reuse. Every probe is best-effort: an unreadable fact is
  `null`, never an error. (The producing binary's version is recorded once,
  in the manifest, per R1.3.)
- **R2.4**: `host/env.json` shall enumerate via `std::env::vars_os` (never
  `vars` — panics on non-UTF-8), record allowlisted values verbatim
  (`RUST_LOG`, `HOME`, `SHELL`, `TERM`, `PATH`; prefixes `XDG_`, `MINIMAL_`,
  `MINVMD_`, `MINIMALD_`), and mask everything else to `<redacted:len=N>`.
  The allowlist grants candidacy, not exemption: an allowlisted name that
  trips the R1.5 sensitive-key policy (e.g. `MINIMAL_TOKEN`,
  `MINIMALD_SECRET`) is masked regardless. `HOME` and `PATH` are recorded
  deliberately — install-layout questions dominate field triage — and their
  user-identifying paths are covered by the review-before-sharing notice
  (R2.9).
- **R2.5**: Config files (`config.toml`, `user_policy.toml`, loadouts) shall
  be bundled through the TOML redaction walker; unparseable TOML is withheld
  with a manifest note, never shipped raw. Every content read — config
  TOMLs and the mesh-enrolment file included — goes through the shared
  no-follow open (R1.4's `open_regular_nofollow`), so a symlinked "config"
  file cannot steer unrelated data into the bundle; a refused link is a
  recorded skip.
- **R2.6**: `state/listing.txt` shall be a metadata-only recursive listing of
  the state dir (names/sizes/kinds, entry-capped) — no file contents. The
  walk is synchronous and runs on a blocking thread, so a wedged filesystem
  strands that thread rather than defeating the R2.2 timeout.
- **R2.7**: Log collection shall gather, per known prefix
  (`minimald.log*`, `minvmd.log*`) and per known name (`run.log`,
  `boot.log`), the newest **5** files per prefix by rotation order,
  tail-capped, rejecting non-regular files (no-follow discipline per R1.4).
  Absent files are manifest skips, not errors (the files only start to exist
  after Unit 3 — best-effort by design).
- **R2.8**: `host/dirs.txt` shall capture the `min dirs` report; `dirs.rs`
  refactors to return `String` with `cmd_dirs` printing it (behavior of
  `min dirs` unchanged).
- **R2.9**: The final output shall print the archive path, entry and error
  counts, and a review-before-sharing notice.

**Proof Artifacts:**

1. **Test:** `bug_without_daemon_still_produces_a_bundle` — valid tar.zst,
   manifest accounts for system.json/env.json/state listing, provider absence
   recorded as a skip — covers R2.1, R2.2, R2.6.
2. **Test:** a planted secret in a fake config dir appears as
   `<redacted:len=N>` in the bundled config and never verbatim anywhere in the
   archive — covers R2.4, R2.5.
3. **CLI:** `min bug` on a dev box; inspect manifest counts and `host/`
   entries — covers R2.3, R2.7-R2.9.

---

### Unit 3: Persistent, correlatable daemon logs

**Purpose:** The raw material `min bug` collects has to exist before the
incident. Both daemons persist rolling file logs — minvmd when detached, the
in-VM minimald onto the data volume without breaking the volume's clean
unmount — the VMM console lands in a `boot.log` by default, and lifecycle
records carry correlation ids on spans.

**Depends on:** None (order-free with Units 1-2)

**Affected areas:**
- `crates/minvmd/src/{main.rs,lib.rs,cmd/run.rs,cmd/vmm_child.rs}`, `Cargo.toml`
- `justfile`, `scripts/session-e2e.sh` — boot.log default fallout
- `crates/minimald/src/{main.rs,server.rs,rpc.rs,session_host.rs,test_harness.rs}`
- `crates/minimal/src/dirs.rs` — daemon-log note (deferred from Unit 2)
  (`tracing-appender` daily rotation; already a workspace dep, no new one added)

**Baseline:**
- minvmd detached logs to nowhere on `origin/main`; the hvc0 console is
  captured only when `MINVMD_BOOT_LOG` is exported (dev flows via `justfile`)
  — **NO DEFAULT CONSOLE PERSISTENCE**. ref: `cmd/vmm_child.rs` defaults the
  console to `<provider dir>/boot.log` (truncated per boot; env override
  kept; wiring failure warns and boots on), `main.rs` adds detached-mode
  rolling logs keyed on a `DETACHED_ENV` re-exec marker (mirrors the
  pre-existing `MINIMALD_DETACHED` pattern), and `justfile`/`session-e2e.sh`
  drop the now-redundant exports — the justfile fallout **MUST LAND IN THIS
  UNIT** or dev flows lose the console between the export removal and the
  default.
- The in-VM minimald logs to the console only; nothing survives the VM —
  **NO PERSISTED GUEST LOGS**. ref: `minimald/src/main.rs`
  installs a `tracing_subscriber::reload` layer whose activator attaches a
  rolling on-volume appender after the state volume mounts, and
  `server.rs:103-118` owns a `VolumeLogRelease` invoked from the
  **pre-existing** Shutdown→quiesce path (`rpc.rs:346` on `origin/main`) so
  the appender (and its `WorkerGuard`) drop before the ext4 unmount.
- ref: `session_host.rs:368-372` and `server.rs:398-401` stamp channel/conn
  ids as **manual per-line fields** — superseded here by spans per the
  design-review boundary above.
- `tracing-appender` rotation is time-based only; nothing caps intra-day
  growth (tokio-rs/tracing#1940) — **NO SIZE CAP EXISTS** on any log path.

**Functional Requirements:**

- **R3.1**: minvmd shall write rolling file logs (`minvmd.log*`, state dir)
  when running detached, keyed on a `DETACHED_ENV` marker set by the
  detach re-exec; foreground behavior unchanged.
- **R3.2**: The VMM child shall default the hvc0 console capture to
  `<provider dir>/boot.log`, truncated per boot; `MINVMD_BOOT_LOG` overrides;
  console wiring failure logs a warning and the boot proceeds.
- **R3.3**: The in-VM minimald shall attach a rolling file appender writing
  to the data volume, installed through a `tracing_subscriber::reload` layer
  activated only after the volume mounts; records before activation go to the
  console as today.
- **R3.4**: The volume log release shall be owned by `ServerState`
  (`VolumeLogRelease`, a boxed `FnOnce` invoked at most once via
  `release_volume_log()`), called from the quiesce path before unmount, so a
  clean shutdown leaves a clean ext4 journal. No process-global mutable state.
- **R3.5**: Binding and connection lifecycle records shall carry their ids via
  tracing spans (`info_span!("binding", channel = %id)` instrumented onto the
  spawned future; connection span created at accept, synchronous sites via
  `span.in_scope`, session future instrumented) — one style, no residual
  manual id fields.
- **R3.6**: File-log rotation for both daemons shall be time-based (daily)
  with bounded retention via `tracing_appender::rolling`
  (`Rotation::DAILY` + `max_log_files`, 14 days), wrapped in the existing
  `tracing_appender::non_blocking` + `WorkerGuard` plumbing with
  `lossy(false)`; guards drop deterministically (minimald: R3.4; minvmd: on
  shutdown). Rotation and pruning are inline (no background publication
  thread), so a release closes the appender with a plain guard drop —
  nothing to join, and no partial intermediate files left on an unmounting
  volume. Rotated files carry a date suffix (`minimald.log.<date>`);
  `newest_rotated`'s modified-time ordering (R2.7) already covers that
  scheme. (Size-based rotation via `logroller` was evaluated and adopted in
  an earlier revision; it is reverted here — see Design Considerations — for
  a smaller dependency surface and simpler shutdown, at the cost of an
  intra-day size cap.)
- **R3.7**: Building the daemon crates without a reachable git context
  (source tarballs, container mounts that exclude `.git`) shall not panic.
  Satisfied on the baseline: the shared `version` crate's build script falls
  back to the Cargo version when `git describe` is unavailable — this unit
  adds no code for it; the cross build lane is the standing verification.

**Proof Artifacts:**

1. **CLI (gate):** boot a VM, hold an idle attach, `minvmd stop`; the volume
   unmounts cleanly (no journal replay on next mount), `boot.log` is present
   in the host-side provider directory, and rotated `minimald.log*` appear on
   the data volume at next boot — covers R3.2-R3.4. The
   release-before-quiesce path is compile/unit-verified only on the reference
   branch; this live check gates the unit.
2. **Test:** log-release runs exactly once and before quiesce returns;
   harness passes `None` release unaffected — covers R3.4.
3. **Test:** the daily appender writes to its date-suffixed file; retention
   and rotation are `tracing_appender`'s own tested behavior, and the live
   gate (artifact 1) confirms rotated `minimald.log*` on the volume —
   covers R3.6.
4. **CLI:** grep a session's records by span-carried channel id across
   accept/attach/close lines — covers R3.5.

---

### Unit 4: OTEL-compatible log format and trace propagation

**Purpose:** Make correlation a grep and a future OTLP export a field-copy,
without taking any OTEL runtime dependency. File logs become JSON-lines with
span context; operations mint W3C-shaped ids; the CLI hands its trace id to
the daemon across the SSH boundary.

**Depends on:** Unit 3

**Affected areas:**
- `crates/minimald/src/main.rs` — JSON-lines fmt layer for the file appender
- `crates/minvmd/src/main.rs` — same for detached file logs
- `crates/minimal/src/client.rs` — `TRACEPARENT` env request on channel open
- `crates/minimald/src/rpc.rs` — adopt the propagated context into the dispatch span
- `crates/minimal/src/lib.rs` — root span + trace-id minting at command dispatch

**Baseline:**
- All log output is human-format text; no trace/span ids exist anywhere —
  **NOT YET IN CODEBASE** (this unit is new scope beyond the reference
  implementation, adopted by decision on 2026-07-16).
- `tracing-subscriber`'s JSON formatter does not emit span/trace ids by
  itself (tokio-rs/tracing#1481 open) — ids must be minted and stamped as
  explicit span fields.
- russh supports SSH channel `env` requests; the daemon side must accept the
  `TRACEPARENT` name (assumption ledger: `russh-env-request`).

**Functional Requirements:**

- **R4.1**: Daemon *file* logs (both daemons) shall switch to JSON-lines via
  a `json-subscriber` layer — flat records, span fields flattened per
  record, UTC RFC3339 timestamps — composed over the existing `MakeWriter`
  plumbing, leaving the Unit 3 `non_blocking`/rolling-appender/reload stack
  untouched. Console/stdout layers stay human-format.
  (`tracing-subscriber`'s built-in JSON formatter cannot emit static
  top-level fields and nests span context in a buried list;
  `json-subscriber`'s dependency closure is already in the workspace.)
- **R4.2**: The file-log layer shall stamp resource identity as **static
  top-level fields on every record**: `service.name`
  (`minimal-cli`/`minimald`/`minvmd`), `service.version`,
  `service.instance.id` (provider/VM id where applicable), `host.name`,
  `process.pid` — using the const names from
  `opentelemetry-semantic-conventions` (consts-only, zero runtime
  dependencies) so the names cannot drift from the conventions. A bundle
  holding files from three processes is self-describing, and top-level
  statics map onto the OTLP *Resource* exactly (span fields map onto
  attributes).
- **R4.3**: Top-level operations (CLI command dispatch, daemon RPC dispatch,
  session/binding lifecycles) shall mint ids in OTLP-required formats —
  `trace_id` 32 lowercase hex, `span_id` 16 lowercase hex — recorded as span
  fields. Correlation values (`channel_id`, `session_id`, …) are span fields
  with stable snake_case keys, never interpolated into messages.
- **R4.4**: The CLI shall send an SSH channel env request named exactly
  **`TRACEPARENT`** (uppercase — SSH env names are byte-exact; both ends use
  one shared constant) whose value is the W3C traceparent format
  `00-{trace_id}-{span_id}-01`, before subsystem/exec invocation; the daemon
  shall adopt a valid received value as the `trace_id` of its dispatch span
  (malformed or absent → mint fresh). No RPC envelope or wire-contract change
  **on this primary path**; the assumption-ledger fallback (an optional
  `traceparent` field on `#[non_exhaustive]` request bodies) is an
  intentional additive contract change that amends this clause if taken.
- **R4.5**: The conventions above are the acceptance contract for all future
  daemon/CLI logging (recorded in this spec; see Design Considerations for
  the OTLP mapping rationale).

**Proof Artifacts:**

1. **Test:** a file-log line parses as JSON and carries level, target,
   timestamp, flattened span fields, and top-level resource fields —
   covers R4.1, R4.2.
2. **CLI (gate):** run one attach with `min`; a single `trace_id` greps
   across the host CLI log and the guest daemon's on-volume log —
   covers R4.3, R4.4.
3. **Test:** malformed `TRACEPARENT` values are ignored (fresh mint, no
   error), and client and daemon reference the same env-name constant —
   covers R4.4.

---

### Unit 5: Incident collectors, mechanics in-crate

**Purpose:** The wedged-system captures: network state, process tree, hang
triage, and power history. Mechanics land in `diagnostics` parameterized by
app inputs — the same mechanics/policy boundary the host-bundle unit
established for its disk/log/env/system helpers.

**Depends on:** Unit 1, Unit 2

**Affected areas:**
- `crates/diagnostics/src/{net.rs,procs.rs,power.rs}` (new) — mechanics
- `crates/minimal/src/diag/mod.rs` — marker list + six `collect_step!` lines
- `crates/minimal/tests/bug.rs` — interfaces/routes/MAC-mask assertions

**Baseline:**
- ref: collectors exist as `crates/minimal/src/diag/{net.rs:21-166,
  procs.rs,power.rs}` — **IN THE WRONG CRATE** per the crate rule; the only
  minimal-ism is the `PROCESS_MARKERS` list (`procs.rs:14`), duplicated
  verbatim as `PROC_MARKERS` in `minimald/src/diag.rs:349`.
- ref: `power.rs:10` uses `super::procs::command_capture` — the modules move
  together, consuming Unit 1's `capture` module instead of private copies.

**Functional Requirements:**

- **R5.1**: `diagnostics::net` shall capture listening sockets (`ss`/
  `netstat` with raw `/proc/net` fallback — verbatim output, no typed
  re-serialization), interfaces with MACs masked to their vendor OUI, and
  routes.
- **R5.2**: `diagnostics::procs` shall produce the process tree and hang
  triage for up to 8 pids matched by **argv0 basename** against a
  caller-supplied `markers: &[&str]`. The Linux path shall be **pure `/proc`
  reads** — wchan/syscall/kernel-stack/fd readlinks, plus an
  fd→socket-inode join against the `/proc/net` tables as the binary-free
  `lsof` equivalent — so it runs as microVM pid-1 with no external binaries.
  External tools are host-side extras used when present: macOS 1 s `sample`
  per pid, and one `lsof -nP` over the set (accepting lsof's
  exit-1-with-output convention). Recorded argv strings shall be scrubbed
  token-wise: any `key=value` token whose key trips the R1.5 sensitive-key
  policy has its value replaced by the redaction placeholder.
- **R5.3**: `diagnostics::power` shall capture sleep/wake history
  (macOS `pmset`; Linux `journalctl`), event-capped.
- **R5.4**: The minimal marker list and the six `collect_step!` wiring lines
  stay in `crates/minimal`; every mechanic above consumes
  `diagnostics::capture::command_capture`.
- **R5.5**: After this unit `crates/minimal/src/diag` shall hold only
  paths/config resolution, the marker and allowlist *data*, and
  clap/orchestration — every generic mechanic lives in `diagnostics` (the
  disk/log/env/system helpers landed there with the host-bundle unit; this
  unit moves the remaining net/procs/power) — the crate rule holds at
  series end.

**Proof Artifacts:**

1. **Test:** interfaces output masks full MACs to OUI; routes/listening
   captures present in the bundle — covers R5.1.
2. **CLI:** `min bug` while a `min attach` runs: `host/proc/<pid>.sample.txt`
   (macOS) or `.stack.txt` (Linux) plus `host/proc/lsof.txt` appear for the
   process family — covers R5.2, R5.4.
3. **Test:** crate-level tests for markers matching (argv0 basename, not
   substring) and power event caps — covers R5.2, R5.3.

---

### Unit 6: Daemon bundle serving (`DiagBundleTarZst`)

**Purpose:** The daemon's own view, served as one zstd tar blob over the
existing SSH subsystem transport, built with the same `BundleWriter` and the
same `manifest.json` schema as the host bundle.

**Depends on:** Unit 1, Unit 5

**Affected areas:**
- `crates/minimald-rpc/src/lib.rs` — `DIAG_BUNDLE_SUBSYSTEM` + `DiagBundleRequest`
- `crates/minimald/src/diag.rs` (new) — collection + streaming
- `crates/minimald/src/{rpc.rs,lib.rs,server.rs}` — dispatch, `in_microvm()`, state-dir accessor ungating
- `crates/minimald/Cargo.toml` — `diagnostics`

**Baseline:**
- No diag subsystem on `origin/main` — **NOT YET IN CODEBASE**.
- ref: `minimald/src/diag.rs` (704 lines) exists but hand-rolls the tar
  stream (`Builder<ZstdEncoder<DuplexStream>>`, `diag.rs:59-84`) and emits
  `errors.json` instead of a manifest, duplicating ~150 lines of
  crate logic (`append_bytes`≡`BundleWriter::append`, `read_tail`≡tail-cap,
  log selection, session-record walk, statvfs) — **REBUILT ON
  `BundleWriter::stream` IN THIS UNIT**; the guest bundle format converges on
  `manifest.json` and `errors.json` is retired (nothing shipped, so no
  compatibility window — Unit 8 handles the one out-of-tree consumer).
- ref: the russh channel writer is not `Sync`, so the duplex-pipe +
  `tokio::io::copy` pump stays (`diag.rs:57` comment); only the tar/manifest
  half moves into the crate.
- ref: the daemon's network capture is listening tables + `/proc/net/dev`
  counters only (`diag.rs:408-430`) — **NO ROUTES, NO ADDRESSES, NO ENV, NO
  HANG TRIAGE IN-VM**. The partial-wedge case (daemon responsive, a session
  child or transport binding stuck) is invisible to the current guest bundle;
  this unit closes it via the Unit 5 mechanics.

**Functional Requirements:**

- **R6.1**: `minimald-rpc` shall define `DIAG_BUNDLE_SUBSYSTEM`
  (`minimald-v1-DiagBundleTarZst` — wire contract, never renamed) and
  `#[non_exhaustive] DiagBundleRequest { log_tail_bytes: u64 /* 0 = daemon
  default */, include_state_listing: bool /* default true */ }`; an empty
  JSON body decodes to the documented defaults. The subsystem follows the
  streaming-subsystem pattern already established by `STREAM_WORKSPACE_FILES`
  (grep the const and its two `handle_ssh_rpc` match arms in
  `crates/minimald/src/rpc.rs`), in the mirror direction: the client writes
  one JSON request and half-closes, the daemon streams one tar.zst and
  closes.
- **R6.2**: The daemon shall stream its bundle through
  `BundleWriter::stream` (rootless): `meta.json` (version, uptime, microVM
  flag), tail-capped `logs/`, metadata-only `state-listing.txt` (on
  `spawn_blocking`; caps honored), `sessions/` records with `redact_json`
  applied and read/parse failures recorded per-record, `proc.txt` (full argv
  — scrubbed per the R5.2 argv rule — only for marker-matched processes,
  `comm` otherwise), raw `/proc/net` tables, and `disk.json` — finishing
  with `manifest.json`.
- **R6.6**: The bundle shall also capture the guest-side incident
  trio via the Unit 5 mechanics (all pure `/proc`, R5.2 — the microVM rootfs
  has no `lsof`/`ss`/`ip`):
  - `net/routes.txt` — `/proc/net/route` + `/proc/net/fib_trie` (routing
    *and* addresses: the guest half of the gvproxy-subnet/CGNAT collision
    picture the host's R5.1 exposes);
  - `proc/<pid>.stack.txt` — hang triage (wchan/syscall/kernel-stack/fd
    readlinks) for the marker-matched in-VM family (minimald pid-1, session
    hosts, task children), so the partial wedge — daemon responsive, one
    binding or child stuck — is self-diagnosing;
  - `proc/sockets.txt` — the fd→socket-inode join over the family (the
    binary-free `lsof` equivalent: which process holds which socket in which
    state);
  - `env.json` — the daemon's own environment through the same
    allowlist-plus-sensitive-key policy as R2.4 (answers "which mode booted,
    why is logging off" — `RUST_LOG`, `MINIMALD_*`, detach markers).
- **R6.3**: Request reads shall be length-bounded; caller-controlled
  `log_tail_bytes` is clamped to a server cap; log collection rejects
  non-regular files and symlinks.
- **R6.4**: Errors before streaming starts shall be relayed on extended-data
  stream 1 and the channel closed without payload; a client reading zero
  payload bytes surfaces the extended data as the failure reason.
- **R6.5**: Marker matching shall reuse `diagnostics::procs` (no duplicated
  `PROC_MARKERS`).

**Proof Artifacts:**

1. **Test:** in-crate tests fetch a bundle over the test harness and assert
   `meta.json` + `manifest.json` presence, session redaction, and the
   pre-stream error path (extended data, zero payload) — covers R6.1,
   R6.2, R6.4.
2. **CLI:** raw `ssh -s` subsystem invocation against a dev daemon returns a
   decompressible rootless tar.zst — covers R6.2.
3. **Test:** oversized request body and oversized `log_tail_bytes` are
   clamped/rejected — covers R6.3.
4. **Test:** the harness bundle contains `net/routes.txt`, per-pid
   `proc/<pid>.stack.txt` for the daemon's own family, `proc/sockets.txt`
   with fd→inode-resolved sockets, and `env.json` with a planted
   `MINIMALD_TOKEN`-style variable masked — covers R6.6.

---

### Unit 7: Guest fetch and degraded-mode fallback

**Purpose:** `min bug` reaches into every provider: a staged socket probe
that says exactly where contact breaks, the bundle download over the probe's
connection, and — when the daemon or transport is the suspect — vital signs
and logs harvested read-only from the volume image.

**Depends on:** Unit 2, Unit 6

**Affected areas:**
- `crates/minimal/src/client.rs` — `download_diag_bundle`
- `crates/minimal/src/diag/guest.rs` (new) — guest collect, volume fallback, skip records
- `crates/minimal/src/diag/net.rs` (new, probe half) — `SocketProbe` stages
- `crates/minimal/src/diag/collect.rs` — provider dirs/files/status (deferred from Unit 2)
- `crates/minimal/src/diag/mod.rs` — provider loop, `--no-guest`, `--guest-timeout-secs`
- `crates/minimal/tests/bug.rs` — full-stack, stale-socket, no-guest tests (+ `mod common;`)

**Baseline:**
- ref: all of the above exists on the reference branch
  (`client.rs:230-315`, `guest.rs`, `net.rs:168-305`, `collect.rs:415-532`,
  `mod.rs:112-172`); this unit lands it against the Unit 6 manifest-bearing
  guest bundle (nested verification updates accordingly).
- ref: `tempfile` promotes dev→main dep here (`volume_fallback` staging);
  `mod common;` (daemon harness) enters `tests/bug.rs` here — earlier it
  would be unused and fail clippy dead-code.

**Functional Requirements:**

- **R7.1**: The socket probe shall record staged outcomes — socket file stat
  → connect → SSH handshake → `GetVersion` — as `socket-probe.json` per
  provider, and hand its established connection to the bundle download (no
  second handshake).
- **R7.2**: `download_diag_bundle` shall stream the daemon bundle with a
  total-size cap (256 MiB), cap accumulated extended-data (`daemon_error`,
  64 KiB), fail fast when the daemon refuses the subsystem, and honor
  `--guest-timeout-secs` (default 60) as the per-provider deadline.
- **R7.3**: The daemon bundle shall be nested **raw** (undecompressed) at
  `providers/<name>/guest/daemon-diag.tar.zst` after verification by
  **bounded streaming decode** — never full materialization of the
  decompressed stream: decompressed size capped at 4× the compressed size
  with a 1 GiB hard ceiling, entry count capped at 10,000, and the check
  requires `manifest.json` present. Cap breach or decode failure records the
  raw bytes anyway with a manifest error naming the failed check.
- **R7.4**: `--no-guest` shall skip *all* daemon contact including the probe
  (the probe handshakes), recording the skip per provider.
- **R7.5**: On probe failure, download failure, or timeout, the bundle shall
  record `providers/<n>/guest/volume-meta.json` (image size + mtime — the
  stall-dating signal) and best-effort harvest `/logs` from the ext4 image
  via `debugfs -c` (read-only, safe against a live VM) into
  `guest/volume-logs/`; without e2fsprogs the manifest carries the exact
  offline `rdump` command.
- **R7.6**: Provider discovery (`local-*` dirs) shall record per-provider
  files (`run.log`, `boot.log`, tail-capped) and liveness status
  (`minvmd`/`minimald` alive checks via `minvmd::state::StateDir`).

**Proof Artifacts:**

1. **Test:** full-stack — `min bug` against the harness daemon nests a guest
   bundle whose manifest parses; loadout redaction and client-key skip hold
   across layers — covers R7.1-R7.3.
2. **Test:** stale socket file → probe records the failed connect stage and
   `error.txt` explains the skip; volume fallback artifacts appear —
   covers R7.1, R7.5.
3. **Test:** `--no-guest` against a live harness daemon performs zero daemon
   contact — covers R7.4.
4. **CLI (gate):** kill a real VM's daemon mid-session, run `min bug`: probe
   stages + `volume-meta.json` + harvested `volume-logs/` present —
   covers R7.5 end to end.

---

### Unit 8: Bundle explorer, dual-format

**Purpose:** Keep the team-side tooling truthful across the format
convergence: `scripts/diag-explore.py` (branch `diag-explore-script`) must
read both pre-convergence (`errors.json`) and post-convergence
(`manifest.json`) guest bundles.

**Depends on:** Unit 6

**Affected areas:**
- `scripts/diag-explore.py` (on its own branch/PR)

**Baseline:**
- ref (branch `diag-explore-script`): guest-bundle detection keys on
  `errors.json` presence, `_check_guest` hard-requires it, and guest
  collector errors are read from it — **BREAKS ON THE UNIT 6 CONVERGENCE**
  (every post-Unit-6 bundle fails its doctor check).

**Functional Requirements:**

- **R8.1**: Guest-bundle detection shall key on `meta.json` presence (not
  `errors.json`).
- **R8.2**: Collector errors shall be read from `manifest.json` when present,
  falling back to `errors.json` for legacy bundles; `check` passes on both.
- **R8.3**: The explorer shall continue to assume the rootless nested layout
  (exact-key lookups) — guaranteed by R1.2/R6.2.

**Proof Artifacts:**

1. **CLI:** `summary`/`check`/`errors` against one pre-convergence bundle
   (a field-captured sample retained by the team) and one post-Unit-6 bundle
   — both pass — covers R8.1-R8.3.

## Non-Goals

- **OpenTelemetry runtime adoption (SDK, exporters, bridges)** —
  opentelemetry-rust is pre-1.0 (traces Beta), the OTLP file-exporter spec
  is a placeholder with no durability semantics, and the bundle path's
  correctness criterion is "works when everything else is dead". Unit 4's
  conventions are the seam; an OTLP exporter layer is additive later work
  (future spec; see Design Considerations). Two OTEL-orbit crates carrying
  no runtime machinery are deliberately in scope and are not exceptions to
  this rejection: `opentelemetry-semantic-conventions` (consts only) and
  `json-subscriber` (a tracing-ecosystem formatting layer whose dependency
  closure is already in the workspace).
- **Continuous/live debug streaming** — to be precise about terms: the bundle
  transport *is* a streaming RPC, in the single-shot sense — one request, one
  streamed archive, close (R6.1). What is out of scope is the long-lived
  form: an open-ended stream of live debug data from a running daemon. Reopen
  only with a use case that post-mortem files cannot serve.
- **`BundleWriter` writing directly to the russh channel** — blocked on
  `async_tar::Builder`'s `Sync` bound vs the non-`Sync` channel writer; the
  duplex pump stays (see Technical Considerations).
- **journald/oslog readers** — wrong platform or wrong weight (libsystemd
  linkage; forensic-grade tracev3 parsing). If host-Linux journald context is
  ever needed: shell out to `journalctl -o json` as a collector.
- **`procfs`-typed daemon collectors and `nix::sys::statvfs` swap** —
  worthwhile cleanups, tracked as follow-up issues under #801, not blocking.
- **`min bug --print` text report** (bugreport-style paste mode) — follow-up
  under #801.
- **Log-based alerting/telemetry pipelines** — out of scope entirely.

## Design Considerations

### Bespoke collectors vs. system-info crates

The collectors ship raw bytes (`/proc` tables, `ss` output, `pmset` logs)
because the raw bytes are the deliverable: typed scrapers (`sysinfo`,
`procfs`) re-serialize, hiding parser version-skew and turning parse failures
into collection failures. Failure isolation — every collector best-effort,
degrading to a manifest note — is easy to guarantee over ten-line readers and
hard over a large library surface. Peer CLIs corroborate: `git bugreport`,
`starship bug-report`, `bat --diagnostic` produce *less* (text reports);
sos report and `cockroach debug zip` are hand-rolled in their ecosystems too.
Re-evaluated 2026-07 against the current crate landscape; conclusion
unchanged. Reopen-trigger: collectors that *compute over* proc data instead
of shipping it raw (then `procfs`, already transitive in minimald's graph, is
the move).

### Redaction must be bespoke and fail-closed

No maintained crate does data-driven recursive key-based scrubbing of
arbitrary JSON/TOML: `secrecy`/`veil`/`redact` are type-level (annotate your
own structs — the opposite shape from walking config you did not define), and
`redactable` explicitly treats dynamic `serde_json::Value`s as opaque
wholesale-redact leaves. Vector's VRL `redact()` is the only real prior art
and is an entire language runtime. The ~200-line fail-closed key-walk stays,
shared verbatim by CLI and daemon so the two layers can never disagree about
what is sensitive.

### Rotation: `tracing-appender` (daily) over `logroller`

`tracing-appender` rotates by time only (size-based requested since 2022,
tokio-rs/tracing#1940): with daily rotation + `max_log_files`, nothing caps
intra-day growth, and a runaway error loop filling the microVM data volume is
a failure class this subsystem exists to diagnose. `logroller` (size-based
rotation, `max_keep_files`, optional gzip) was trialled for exactly that
cap — a plain `io::Write` that drops into the same
`non_blocking`/`WorkerGuard`/`reload` plumbing — but it rotates and prunes on
a **background thread**, which (a) leaves partial `.pending.` intermediate
files if the appender is dropped mid-rotation, precisely during the volume
release before an unmount, and (b) is a young crate (0.1.x, single
maintainer). It is **reverted**: `tracing-appender`'s daily appender rotates
and prunes *inline*, so the release is a plain guard drop with nothing to
join and no orphaned intermediates, and it is the same writer the reference
implementation used. The size cap is given up in exchange; the runaway-log
risk is bounded instead by `max_log_files` retention, the level filter, and
volume monitoring, and the writer stays swappable behind one constructor if
`tracing-appender` ever ships size-based rotation. Decided 2026-07-16
(logroller); reverted 2026-07-20.

### One streamed blob per request; no live telemetry stream

The bundle transport *is* a streaming RPC — deliberately the smallest
possible one. `DiagBundleTarZst` mirrors the streaming-subsystem pattern the
wire already carries for workspace upload (`STREAM_WORKSPACE_FILES` in
`crates/minimald/src/rpc.rs`), direction reversed: one JSON
request, half-close, one tar.zst streamed back with pre-stream errors on
extended-data stream 1, close. ~200 lines whose failure modes are inspectable
with the same probe that precedes it. What this spec rejects is the
*continuous* form — a long-lived live debug stream (OTLP/gRPC, otel-arrow):
that replaces the blob with a protocol stack (HTTP/2 flow control, batch
buffering, backpressure) that is opaque exactly when the transport is the
suspect — and a wedged transport is precisely the scenario this subsystem
must serve.
Every OTEL export path is push-based from a live process and loses its
in-memory tail on a hang; the only OTEL-shaped post-mortem pattern is
"write files while healthy, scrape later", which is what Unit 3 does without
the dependency. No mainstream infra tool uses OTEL for support bundles
(troubleshoot.sh, `kubectl cluster-info dump`, sos, Docker diagnose: all
plain files). A resident collector in the initramfs (Go otelcol or Rust
rotel) inverts the design: it adds a component that must be alive and healthy
to the path that must work when nothing is.

### OTEL-compatible conventions without the runtime

Unit 4 holds the format seam so a later OTLP move is mechanical:
tracing levels map exactly onto OTLP SeverityText/SeverityNumber; `target` ≙
InstrumentationScope; `fields.message` ≙ Body; resource attributes use the
OTLP names as top-level statics (R4.2 — mapping onto the OTLP *Resource*
directly); trace/span ids use the OTLP-required hex formats (R4.3), minted
by us because tracing's JSON formatter does not emit ids
(tokio-rs/tracing#1481). Conversion to OTLP-JSON, if ever wanted, is a
transform on the *analysis* machine over files already in the bundle — the
guest never takes the runtime.

Two OTEL-orbit crates are adopted because they carry none of the rejected
costs: `opentelemetry-semantic-conventions` — consts only, zero execution —
pins the attribute names; `json-subscriber` provides the flat JSON layer
with static top-level fields that `tracing-subscriber`'s built-in formatter
cannot produce, with a dependency closure already entirely in the workspace.
`json-subscriber` *is* runtime code, so the boundary is stated precisely:
its execution (per-span field capture into span extensions; per-event
serde_json serialization) is confined to the **log-write path of a healthy
process** — the same class of work as the formatter it replaces, with no
pipeline machinery of its own (no processor threads, timers, network I/O,
or shutdown choreography) — and **nothing executes at collection time**:
`min bug` and the diag RPC read files off disk, so a formatter defect can
degrade what got written but never the ability to collect what exists.
Reopen-triggers: abandonment, or `tracing-subscriber` gaining static
top-level fields natively. Const-rename churn across semconv 0.x releases is
contained to compile errors.

`tracing-opentelemetry` (the tracing→SDK bridge) stays out, and is the
named crate for the future export layer: it cannot be adopted piecemeal —
even trace-id generation requires instantiating a `TracerProvider` with its
processor machinery, and span data buffered in its batch path is lost on a
hang (the tail problem the file-first design avoids: our span fields are
flattened into every line as it is written). The Unit 4 conventions exist
so bolting it onto the host CLI later grafts cleanly. One cost correction
to the seam pricing: `prost` is already resident in this workspace for the
RPC layer, so a future OTLP-JSON emitter via `opentelemetry-proto` (serde
feature) is a smaller step than the general "pulls the tonic stack"
estimate — the posture stays convert-on-analysis, but the seam is named and
cheap.

### Guest bundle format convergence

The reference implementation's guest bundle emits `errors.json` and no
manifest — a second, weaker accounting schema. Since nothing has shipped,
Unit 6 converges both layers on `manifest.json` (same
collected/skipped/errors shape, same tooling) rather than replaying the split
and migrating later. The single out-of-tree consumer (diag-explore) is
Unit 8's dual-format rework, sequenced after Unit 6.

## Repository Standards

- Every unit lands `cargo fmt`-clean, `cargo clippy --all-targets
  --all-features -- -D warnings`-clean (feature-gated callers — the
  test-harness regression on the reference branch was caught only by
  `--all-features`), and `cargo test -- --include-ignored`-green.
- Conventional Commits; one logical change per commit; multi-scope
  (`feat(minvmd,minimald): ...`) where a unit spans crates.
- `.github/workflows/` is frozen — tests are convention-discovered; nothing
  in this series may add files named `*_integration.rs`/`*_root_integration.rs`
  unless they genuinely belong to those lanes.
- `thiserror` enums in `diagnostics` (library crate); `anyhow` +
  `.context(...)` in `minimal`/daemon application code (informed by
  ADR-0001).
- `// SAFETY:` on every `unsafe` block (statvfs/geteuid FFI); `tracing`
  structured fields, never interpolated values; no `println!` outside CLI
  user output.
- Each unit ships its tests in the same PR; proof artifacts attach to the PR
  per house convention.

## Open Questions

1. Should minvmd's *foreground* runs also tee to the file log — why not
   unconditionally? Default posture here: detached-only in Unit 3; revisit at
   Unit 3 review.
2. `service.instance.id` (R4.2): provider name vs VM/session uuid — decide in
   Unit 4 design review; must be stable across a VM's lifetime and present in
   both host and guest resource fields.
3. Retention numbers: size threshold and `max_keep_files` per daemon (volume
   is 32 GiB shared with user data; proposal: 8 MiB × 5 files guest-side,
   16 MiB × 5 host-side) — settle with measurements in Unit 3.

## Technical Considerations

- `async_tar::Builder<W>` requires `W: Sync`; the russh channel writer is not
  `Sync`, hence the daemon's duplex-pipe + `tokio::io::copy` pump
  (ref `minimald/src/diag.rs:57-101`). `tokio::io::DuplexStream` and
  `tokio::fs::File` are both `Sync` — the `BundleWriter<W>` bound set in R1.2
  follows.
- async-tar is pinned at 0.6 (post-CVE-2025-62518/"TARmageddon"; the
  nested-TAR extraction flaw was fixed in 0.5.1). Never migrate to the dead,
  unpatched `tokio-tar`; if async-tar stalls, `astral-tokio-tar` is the
  escape hatch.
- `std::env::vars()` panics on non-UTF-8 values; all env enumeration uses
  `vars_os()` (R2.4).
- Every subprocess capture sets `kill_on_drop(true)` so a collector timeout
  cannot leak children past the bundle run (R1.7).
- `debugfs -c` (catastrophic/read-only mode) is safe against an ext4 image
  with a live writer; harvested logs may be mid-write torn, which is
  acceptable for post-mortem text (R7.5).
- Rotation/pruning in the daily file appender happens on the write path — an
  idle daemon does not rotate, so a "daily" file can span days. Retention
  (`max_log_files`) bounds the file count, not intra-day size (R3.6); a
  runaway log grows until the next daily boundary.
- **The `lossy(false)` backpressure chain (R3.6) is a deliberate coupling.**
  The in-VM write path is: daemon thread → `non_blocking` bounded channel
  (~128k lines) → worker thread → the daily rolling appender (rotation
  renames/prunes run inline on the worker) → data volume. With
  `lossy(false)`, a wedged volume
  stalls the worker; once the channel fills, every daemon thread blocks at
  its next log call — the log pipeline can propagate a disk wedge into the
  RPC threads. Accepted because dropping records under pressure destroys
  exactly the evidence this subsystem exists to keep, and two mitigations
  bound the damage: the console layer keeps flowing to the VMM console
  capture (`boot.log`) independent of the volume, and a daemon wedged this
  way fails the socket probe, sending `min bug` down the volume-fallback
  path (R7.5), which reads the image without the daemon's help. The
  headroom claim behind this acceptance is an assumption-ledger row
  (`nonblocking-headroom`).
- Caps (reference values): collector timeout 30 s, log tail 5 MiB, log files
  5 per prefix, listing 100k entries, guest bundle 256 MiB compressed
  (verification: ≤4× decompressed with 1 GiB ceiling, ≤10k entries),
  daemon-error 64 KiB, hang-triage 8 pids, power events 100.

## Security Considerations

- **Trust boundary: the bundle leaves the machine.** Structured data is
  redacted fail-closed: config/env/session records (R1.5, R2.4, R2.5, R6.2),
  MACs masked to vendor OUI (R5.1). Free-text artifacts are bounded
  differently and honestly: collected logs are our own daemons' output,
  governed by the no-interpolated-values tracing standard; full argv is
  recorded only for marker-matched minimal-family processes — a concurrent
  unrelated process's command line is never captured (`comm` only) — and is
  scrubbed of sensitive `key=value` tokens (R5.2, R6.2). One free-text
  surface is *not* ours to bound this way — the host's kernel panic report —
  and is admitted only as a single bounded extract: the
  `panic(cpu N caller …)` string alone, truncated and token-scrubbed. The
  report's metadata header (device-stable `crashReporterKey`/incident id,
  hardware model) and its backtrace (an inventory of the user's loaded kexts)
  are withheld; the collector never copies a crash report's head verbatim.
  Residual risk is handled by two nets: the CLI's explicit review-before-sharing notice
  (R2.9) and the team-side explorer's `audit` secret-pattern scan (Unit 8
  prior art).
- **The collector must not be a read gadget.** Every content read on both
  layers — log tails, config TOMLs, the mesh-enrolment file — goes through
  one shared no-follow open with descriptor-based verification (R1.4's
  `open_regular_nofollow`, R6.3) — not a racy check-then-open — so a
  crafted `minimald.log.evil` or symlinked loadout cannot exfiltrate
  `/etc/shadow` into a bundle.
- **The archive is private by default**: created `0600` before content is
  written (R1.2).
- **The daemon endpoint is DoS-bounded**: request reads length-capped,
  caller-supplied tail sizes clamped server-side, listing entry caps,
  streaming size caps client-side (R6.3, R7.2).
- **The client is bomb-bounded**: nested-bundle verification is a streaming
  decode under decompressed-size and entry-count caps, never full
  materialization (R7.3) — a malicious or corrupt guest bundle cannot
  exhaust host memory.
- **Diagnosis must not mutate**: no state writes, no daemon autospawn, no
  volume writes (`debugfs -c` is read-only) — a bundle taken during an
  incident cannot contaminate the incident.

## Verification

| Unit | Req | Proof type | Command / observable |
|------|-----|-----------|----------------------|
| 1 | R1.4-R1.6 | Test | `cargo test -p diagnostics` — redaction compound keys, tail cap, no-follow open, listing cap + truncation marker |
| 1 | R1.2, R1.3 | Test | file-vs-stream round-trip identical modulo root; manifest last at `{root}/manifest.json` / top-level `manifest.json` |
| 1 | R1.7 | Test | capture timeout kills the child, retains stdout/stderr/status + typed error |
| 2 | R2.1, R2.2, R2.6 | Test | `bug_without_daemon_still_produces_a_bundle` (Linux lane) |
| 2 | R2.4, R2.5 | Test | planted secret → `<redacted:len=N>`, never verbatim |
| 2 | R2.3, R2.7-R2.9 | CLI | `min bug` on dev box; manifest counts, `host/` entries |
| 3 | R3.2-R3.4 | CLI (gate) | idle attach + `minvmd stop` → clean ext4 journal; `boot.log` in provider dir, `minimald.log*` on volume next boot |
| 3 | R3.4 | Test | release runs exactly once, before quiesce returns |
| 3 | R3.6 | Test | size-threshold rotation + retention pruning |
| 3 | R3.5 | CLI | grep one channel id across accept/attach/close records |
| 4 | R4.1, R4.2 | Test | file-log line parses as JSON with flattened span fields + top-level resource fields (semconv names) |
| 4 | R4.3, R4.4 | CLI (gate) | one `trace_id` greps across host CLI log and guest on-volume log for one attach |
| 4 | R4.4 | Test | malformed `TRACEPARENT` value → fresh mint, no error; shared env-name constant both ends |
| 5 | R5.1 | Test | MAC→OUI masking; interfaces/routes in bundle |
| 5 | R5.2 | Test | argv0-basename matching; sensitive `key=value` argv tokens masked |
| 5 | R5.2, R5.4 | CLI | `min bug` during `min attach` → per-pid sample/stack + lsof for family |
| 6 | R6.1, R6.2, R6.4 | Test | harness fetch: `meta.json` + `manifest.json`; pre-stream error via extended data |
| 6 | R6.2 | CLI | raw `ssh -s` subsystem fetch decompresses, rootless |
| 6 | R6.3 | Test | oversized request/tail clamped |
| 6 | R6.6 | Test | guest bundle carries routes, per-pid stacks, fd→socket join, allowlisted env (planted secret masked) |
| 7 | R7.1-R7.3 | Test | full-stack nested-bundle test with redaction across layers |
| 7 | R7.3 | Test | oversize/entry-bomb nested bundle → verification fails within caps, raw bytes + manifest error recorded |
| 7 | R7.1, R7.5 | Test | stale socket → connect-stage failure + fallback artifacts |
| 7 | R7.4 | Test | `--no-guest` → zero daemon contact against live harness |
| 7 | R7.5 | CLI (gate) | kill VM daemon mid-session; `min bug` → probe stages + volume-meta + harvested logs |
| 8 | R8.1-R8.3 | CLI | explorer `check` green on pre- and post-convergence bundles |
