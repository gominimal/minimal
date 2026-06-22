---
id: spec-sessions-composition-pipeline
title: "sessions composition pipeline — shared policy gate, split client/daemon composers, single-round wire"
kind: spec
status: planned
tracking-issue:
supersedes:
---

# sessions composition pipeline — shared policy gate, split client/daemon composers, single-round wire

## Context

This spec was derived retrospectively from pull request #528 ("chore(sessions): Split client
and daemon loadout resolution logic"), implemented on the `evan/split03` branch without a prior
specification. It documents the session composition pipeline as shipped and surfaces gaps between
what was built and a complete end-to-end gated session flow.

The PR refactors the `sessions` crate's composition machinery from a monolithic `Composer` into
a shared policy gate (`core::compose`) plus two narrow composers: `UserComposer` on the client
side and `SessionComposer` on the daemon side. It also simplifies the wire protocol from a
multi-round exchange to a single round-trip, and fixes a policy-precedence bug where
`Source::UserLoadout` items bypassed explicit `deny` rules.

Prior related work (not yet specced):
- #348 introduced `Composable`/`Contribution`/`Composer` that this PR refactored.
- #427 reorganized `sessions/src/client/composer.rs` in the same area.
- #443 added the multi-round `SessionCreate`/`SubmitVerdict`/`SessionAbort` RPC shapes whose
  multi-round wire fields this PR collapses to a single round.

## Demoable Units of Work

### Unit 1 — Shared `core::compose` gate pipeline

The composition pipeline lives in `crates/sessions/src/core/compose.rs`, shared by both composers.

**R1.1** — `Contribution` accumulates `ProvenancedVar`, `ProvenancedPatch`,
`ProvenancedPackage`, and `ProvenancedHook` from one contributor. `merge` concatenates two
contributions; its return type is `Result<Contribution, Conflict>`, reserved for upcoming
conflict-detection rules.

**R1.2** — The `Composable` trait exposes one method, `contribute(env) -> Result<Contribution,
Error>`. Any type implementing it can contribute to a composer.

**R1.3** — `gate_vars` runs a 3-pass categorize/prompt/apply loop over `ProvenancedVar` items.
Pass 1 calls `VarsPolicy::check` per item; Pass 2 calls `hooks.on_var_unapproved` for
`NeedsApproval` items; Pass 3 applies the returned `ItemDecision` values. Returns
`(Vec<SessionVar>, VarsPolicy)`.

**R1.4** — `gate_patches` runs the same 3-pass loop over `ProvenancedPatch` items, preceded by
a filesystem pre-walk: `expand_patch_sources` expands `~/` and `$VAR` in source patterns, walks
the filesystem, and fans out to individual `PatchFile` entries before Pass 1.

**R1.5** — `compose_contribution` is the top-level orchestrator: runs `gate_vars`, then
`gate_patches` with the gated vars as the expansion context, and assembles a `Composition`.
Returns `(Composition, UserPolicy)`.

**R1.6** — When `hooks` is `None` (user-only path), any item reaching `NeedsApproval` returns
`ComposeError::HookRequired`, not a prompt.

**Proof Artifacts:**

1. **Test** — `cargo test -p sessions 'core::compose::tests::vars_gating'` passes, covering
   allow/deny/ignore, user-origin auto-allow bypass, hook flows (AllowOnce, UseRule, Abort,
   policy mutation + re-check), HookContract and HookRequired error paths.
2. **Test** — `cargo test -p sessions 'core::compose::tests::patches_gating'` passes, covering
   single-file user-origin pass-through, project-origin prompting, deny, tilde expansion
   (session var and env fallback), symlink policy (link vs target, follow mode), and
   `extend_from_wire` atomicity.
3. **Test** — `cargo test -p sessions 'core::compose::tests::vars_gating::user_loadout_honors_deny'`
   passes, proving that `Source::UserLoadout` items still hit the deny gate.

### Unit 2 — Client `UserComposer`

**R2.1** — `UserComposer` accumulates `Loadout` instances via `add(loadout)` and
`add_all(loadouts)`. Each call invokes `Loadout::contribute(&env)` and merges the result onto a
clone, so a `Conflict` error leaves the accumulated state intact.

**R2.2** — `UserComposer::compose(policy, options)` calls `compose_contribution` with
`hooks = None`, uses the process environment as `home_fallback`, and returns a `WireContribution`
ready to ship to the daemon.

**R2.3** — `UserComposer` satisfies `Send + Sync` (verified via a static assertion).

**R2.4** — `with_env(StoredEnv)` replaces the default `std::env::var` lookup for tests.

**Proof Artifacts:**

1. **Test** — `cargo test -p sessions 'client::composer::tests'` passes, covering vars into wire
   form, ignore filtering, packages/hooks pass-through, multi-loadout accumulation via
   `add_all`, env override, and an end-to-end all-four-kinds case.
2. **Test** — `cargo test -p sessions 'client::composer::tests::ignore_filters_user_vars'` passes,
   confirming the ignore policy applies on the client-only path (no hook invocation needed).

### Unit 3 — Daemon `SessionComposer`

**R3.1** — `SessionComposer::new(client: WireContribution)` seeds the composer with the
client's already-gated contribution. Daemon-side `Composable` items are added via `add` /
`add_all`.

**R3.2** — `SessionComposer::compose(policy, options)` reconstitutes client wire vars as
`expansion_vars`, runs `compose_contribution` over daemon-side items with
`home_fallback = None`, then calls `Composition::extend_from_wire(self.client)` to append the
pre-gated client items. Returns `Composition`.

**R3.3** — The daemon never reads `HOME` from its own process environment. `$VAR` / `~/`
expansion in daemon-side patches resolves against client-supplied wire vars only.

**R3.4** — `SessionComposer` satisfies `Send + Sync` (verified via a static assertion).

**Proof Artifacts:**

1. **Test** — `cargo test -p sessions 'daemon::composer::tests'` passes, covering empty inputs,
   client vars surviving into the merged composition, and the `extend_from_wire` integration.
2. **Test** — `cargo test -p sessions 'daemon::composer::tests::client_vars_appear_in_merged_composition'`
   passes, confirming client wire vars reach the final `Composition` with source preserved.

### Unit 4 — Wire protocol single-round-trip

**R4.1** — `SessionCreateRequest.contribution` is typed `WireContribution` (replacing
`ResolvedContribution`). The client's already-gated items ship in one message with no round
counter.

**R4.2** — `ContributionResponse` carries `(session_id, vars, patches, lifecycle_hooks)`.
The `round` and `complete` fields are removed; the daemon batches all pending items into one
response.

**R4.3** — `ContributionVerdict` carries `(session_id, vars, patches)`. The `round` field is
removed.

**R4.4** — `SessionStep::Round` is renamed `SessionStep::Response`. The serde `kind` tag
emits `"response"` (not `"round"`); callers must treat this tag as the stable discriminator.

**R4.5** — `Abort` / `AbortReason` types are introduced with structured reasons:
`PolicyDenied`, `UserCancelled`, `HookContract`, and `Other`.

**R4.6** — All wire types round-trip through `serde_json` without data loss.

**Proof Artifacts:**

1. **Test** — `cargo test -p sessions 'wire::request::tests'` passes, covering round-trips for
   `SessionCreateRequest`, `WireContribution`, `ContributionResponse`, `ContributionVerdict`,
   `Abort` (all four `AbortReason` variants), and both `SessionStep` variants, including
   explicit `kind` tag assertions.
2. **Test** — `cargo test -p sessions 'wire::request::tests::session_step_uses_explicit_kind_tag'`
   passes, confirming `"kind":"fault"` is stable in serialized form for `SessionStep::Fault`
   (by parity, `"kind":"response"` is equally stable for `SessionStep::Response`).

### Unit 5 — Policy gate semantics and module vocabulary

**R5.1** — In `VarsPolicy::check` and `ExpandedPatchPolicy::decide`, `deny` is evaluated
before the `Source::UserLoadout` auto-allow. A user-loadout item matching a `deny` rule is
rejected with `ComposeError::Denied`.

**R5.2** — `ItemDecision::DenyOnce` is removed. To reject a single item a hook now returns
`Abort`, which terminates the whole composition. There is no per-item partial denial.

**R5.3** — `client::enumerate` and `client::hooks` are relocated to `core::enumerate` and
`core::hooks`, eliminating a layering inversion where `core::compose` previously imported
from `client::`.

**R5.4** — The vocabulary is enforced in names and documentation: "resolve" = turn a deferred
reference into a concrete value (`ResolvedVar::resolve_with`, patch source expansion);
"gate" = apply `UserPolicy` (`gate_vars`, `gate_patches`); "compose" = the top-level pipeline
(`compose_contribution`, `UserComposer::compose`, `SessionComposer::compose`).

**R5.5** — `crates/sessions/docs/COMPOSITION.md` describes the 4-phase pipeline, the shared
gate pipeline (with flowchart), key invariants, and the resolve/gate/compose vocabulary.

**Proof Artifacts:**

1. **Test** — `cargo test -p sessions 'user_loadout_honors_deny'` passes in both
   `core::compose::tests::vars_gating` and `core::compose::tests::patches_gating`, proving
   R5.1 for both domains.
2. **File** — `crates/sessions/docs/COMPOSITION.md` exists and contains headings "End-to-end
   flow", "Phases in detail", "The shared client-side gate pipeline", and "Vocabulary".

## Design Considerations

- **Hooks are a client-only concept.** The daemon carries no `PolicyHooks`. Non-user-origin
  items the daemon's policy cannot auto-decide route back to the client via `ContributionResponse`
  (Phase 2). Until that path is wired, `ComposeError::HookRequired` is the fallback.
- **`home_fallback` is asymmetric.** The client uses its process environment for `HOME`; the
  daemon uses `None`, so `~/` patterns in daemon-side patches must resolve against the client's
  wire vars. This prevents the daemon's `HOME` from silently substituting a different directory.
- **`Contribution::merge` is pure concatenation today.** Two contributors pushing the same
  variable name both survive. The `Conflict` enum with its `Result` return type is the
  reserved site for future conflict-detection rules; no rework of callers is needed when
  those rules land.
- **Source travels end-to-end.** Every primitive retains its `Source` through all gate layers
  into the final `Composition`, enabling audit and attribution downstream.
- **Atomic wire extension.** `Composition::extend_from_wire` converts all items up-front; if
  any conversion fails (e.g. a malformed lifecycle hook), `self` is left unchanged.

## Security Considerations

- **`deny` beats user-origin.** The policy-precedence fix (R5.1) ensures a user cannot
  accidentally bypass their own deny rule via a loadout entry. `deny` wins regardless of
  `Source`.
- **Wire items from the client are trusted on the daemon.** `WireContribution` and
  `ContributionVerdict` are accepted verbatim — the daemon does not re-gate them. This is
  correct: the policy is a client-side concern, and the daemon cannot second-guess the user's
  own decisions.
- **Daemon does not expand tilde from its own environment.** `home_fallback = None` in
  `SessionComposer::compose` prevents the daemon's `$HOME` from silently substituting into
  patch patterns whose intent was to reference the user's home directory.
- **Symlink policy checks both link and target paths.** In follow-symlinks mode, a `deny`
  pattern matched on either the link path or the canonical target rejects the file, preventing
  a link-allowed / target-denied bypass.

## Repository Standards

- All public types and functions in `core::compose`, `client::composer`, and
  `daemon::composer` carry rustdoc comments (100% docstring coverage per the pre-merge
  check).
- Error types use `#[derive(Debug, thiserror::Error)]`; public error enums carry
  `#[non_exhaustive]`.
- `#[allow(clippy::unnecessary_wraps)]` on `Contribution::merge` includes a `reason` comment
  explaining why the `Result` shape is load-bearing despite being always-`Ok` today.
- `Send + Sync` bounds are enforced via static assertions in both composer modules.

## Gap Analysis

- **Phases 2–4 not wired** — `crates/sessions/src/daemon/composer.rs:19-21`. The daemon
  does not yet emit a `ContributionResponse` for items needing approval; they surface as
  `ComposeError::HookRequired`. Phase 3 (client generates a `ContributionVerdict` from the
  response) and Phase 4 (daemon applies verdicts to assemble the final `Composition`) are both
  absent. `SessionComposer::compose` is explicitly marked as a placeholder. **Gap class:
  demoable unit absent.**

- **`Contribution::merge` conflict detection absent** — `crates/sessions/src/core/compose.rs:63`.
  The `Conflict` enum is uninhabited. Two contributors pushing the same variable name both
  survive into the `Composition`. **Gap class: implementation gap.**

- **No test for var-name collision across wire boundary** — When `extend_from_wire` appends
  client wire vars and daemon-gated vars share a name, both survive (correct per the pure-concat
  spec). No test asserts this collision case. **Gap class: failure path / missing test coverage.**

- **`ItemDecision::DenyOnce` removal is a breaking hook-API change** — Callers implementing
  `PolicyHooks` that returned `DenyOnce` to reject a single item must now return `Abort`
  (session-wide termination). The PR body names this change but there is no migration note in
  the code. **Gap class: acceptance criteria — behavioral change without in-code guidance.**

## Open Questions

1. **Phase 2–4 timeline.** Is there a tracking issue for wiring the daemon
   `ContributionResponse` emission and the client Phase 3 verdict handler? This is the most
   significant gap relative to the documented 4-phase pipeline.

2. **Conflict-detection rules.** When two contributors push the same variable name, which wins —
   last-write, first-write, or error? The merge site is reserved but the rules are not yet
   specified. This needs to be settled before `Conflict` variants land.
