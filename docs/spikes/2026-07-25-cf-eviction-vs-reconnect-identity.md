---
id: "TBD"
title: "S4: eviction-vs-reconnect identity probe (per-boot token vs bare liveness)"
status: in-progress
date: 2026-07-25
budget_hours: 4
actual_hours: 1
progress: "code-adjacent checks done: boot-id stamping is ABSENT (probe is greenfield); CORRECTION — minimald traps NO signals, so P4 must ADD a SIGTERM→drain trap (there is no 'SIGTERM hook' to extend; dcd5bac only improved the RPC-driven shutdown sequence). Eviction-behavior gate still fully live-gated."
related:
  - "plan: /home/.claude/plans/look-at-the-lessons-silly-stallman.md (Phase 0, S4)"
  - "sibling: norrietaylor/minimal-sessions docs/adr/0018-container-identity-reconnect-token.md"
  - "sibling: norrietaylor/minimal-sessions docs/risks.md (R-030)"
  - "sibling: norrietaylor/minimal-sessions docs/patterns/failure/no-graceful-shutdown-persist-before-destroy.md"
tags:
  - cloudflare
  - remote-provider
  - durability
  - eviction
  - reconnect
  - de-risk
---

# Question

After a Cloudflare host eviction, does `getSandbox(id)` return a **fresh, empty**
container under the same Durable Object id that still passes a naive liveness
check (`exec('true')`) — silently losing `/workspace`? And does a per-boot
identity token reliably distinguish a genuine reconnect from an eviction-respawn?

# Hypothesis

Yes to both. The sibling found eviction masquerades as reconnect: the respawned
container is empty but live, so bare liveness is unsafe (R-030 / ADR-0018). A
per-boot UUID stamped into container tmpfs (`/run`) at boot and persisted DO-side,
verified **after** liveness, detects the swap: absent/mismatch ⇒ treat as eviction
⇒ re-provision + restore the Cache B workspace snapshot instead of attaching to an
empty container.

# Method

1. Create a session; write a sentinel file into `/workspace` and stamp a per-boot
   UUID into `/run` (persist the UUID in DO SQLite).
2. Force or await a host eviction (deploy-reset or idle past the platform's
   behaviour; record how the eviction was induced and its timing).
3. Reconnect via `getSandbox(id)`; run: (a) bare liveness `exec('true')`, then
   (b) read `/run` UUID and compare to the DO-persisted value, then (c) check the
   `/workspace` sentinel.
4. Confirm liveness-then-identity flags the eviction that bare liveness misses,
   and that the restore-from-Cache-B path recovers the sentinel.

# Gate

**PASS** ⇒ identity-after-liveness reliably separates reconnect from eviction, and
restore-from-snapshot recovers `/workspace` ⇒ the P4 durability design (boot-id
probe + eager snapshot) is sound. **FAIL** ⇒ if no stable per-boot signal survives
(or a real generation-id is exposed that is better), record it and revise the
reconnect contract before P4.

# Findings

## Code-level pre-verification (2026-07-25, local — no deploy)

S4's own gate (does `getSandbox(id)` return empty-but-live after eviction) is a pure
CF-runtime behavior with **no local code surface**. But two tree facts that the
plan's neighboring durability design (P4) rests on were checked, and one is a
correction:

- **Boot-id / instance-identity / generation stamping is ABSENT** from both
  `minimald` and `minimal` (grep for `boot.?id|instance.?id|generation.?id|
  reconnect.?token|/run/*uuid` finds nothing). So the per-boot-UUID probe this spike
  designs is **greenfield** — nothing to reuse and nothing to collide with. ✓
- **CORRECTION: there is no SIGTERM hook to "extend."** `minimald` traps **no**
  process signals — `SignalKind` / `unix::signal` / `ctrl_c` appear nowhere in the
  crate. Shutdown today is **RPC-driven** (`Shutdown` RPC → `serve_shutdown`,
  `crates/minimald/src/rpc.rs:427`) plus an **internal** stop/drain
  (`Server::run` stop signal, `crates/minimald/src/server.rs:284`;
  `session.rs stop_running(for_shutdown)`). Commit `dcd5bac` improved the shutdown
  *sequence* (terminal reset + attached-session message) along that path — it did
  **not** add a signal trap. Consequence for P4: CF eviction delivers **SIGTERM to
  pid-1 then SIGKILL after the grace**; an untrapped `minimald` never runs its
  graceful drain and is simply killed. So P4 must **add** a process-level
  `SignalKind::terminate` handler that invokes the existing `Server::stop`/`Shutdown`
  drain (a new trap wired to an existing drain), not "extend an existing SIGTERM
  hook." This *reinforces* the plan's core stance — **eager snapshotting, never rely
  on shutdown hooks** — because even with the new trap, `destroy()` (uncatchable
  SIGKILL) and hard evictions bypass it.

## Live probe results

_TBD — fill on execution. Record: how eviction was induced + timing; the
liveness/identity/sentinel results; whether a platform generation-id exists that
beats a self-stamped UUID._

# Conclusion

_TBD._

# Action items

_TBD._

# Residual Risks / Live Trial Needed

- Requires live CF Containers + the ability to induce/observe an eviction; eviction
  is unbounded and no-SLA, so timing is opportunistic (the sibling saw ~16 min once).
- `destroy()` is an uncatchable SIGKILL ⇒ durability must be eager-snapshot, not
  shutdown-hook; S4 validates detection, P4 implements the snapshot loop.

# Artifacts

_TBD — probe script, DO state dump, eviction timeline, restore logs._
