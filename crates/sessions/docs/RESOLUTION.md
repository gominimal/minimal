# Session Resolution Data Flow

How contributions move through the session-construction pipeline, from
declarative sources (loadout, project, packages) to the final
`Resolution` consumed by the apply layer.

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  user Loadout   │  │ project config  │  │  package specs  │
│  (Loadout)      │  │ (mfile-derived) │  │  (per package)  │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         │  Composable::contribute(env) -> Contribution
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ▼
                  ┌───────────────────────┐
                  │      Composer         │  Composer::add(c) drains
                  │                       │  each contributor's
                  │  vars:       Vec<PV>  │  Contribution into here.
                  │  patches:    Vec<PP>  │
                  │  packages:   Vec<Pkg> │   PV  = ProvenancedVar
                  │  lifecycle:  Vec<H>   │   PP  = ProvenancedPatch
                  │  env:        lookup   │   Pkg = ProvenancedPackage
                  └───────────┬───────────┘   H   = ProvenancedHook
                              │
                              │ Composer::resolve(
                              │   UserPolicy,        ◄── consumed by value
                              │   &dyn PolicyHooks,
                              │   ResolveOptions,    ◄── follow_symlinks etc.
                              │ ) -> (Resolution, UserPolicy)
                              │                     ◄── returned with any
                              │                         hook-applied updates
                              ▼
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌────────────────┐  ┌──────────────────┐  ┌────────────────────┐
│ resolve_vars   │  │ resolve_patches  │  │ packages, hooks    │
│ (policy-gated) │  │ (policy-gated)   │  │ (pass-through; no  │
└───────┬────────┘  └────────┬─────────┘  │  policy gate)      │
        │                    │            └─────────┬──────────┘
        │                    │ pre-walk:            │
        │                    │   expand `~` in each │
        │                    │   FileSet source     │
        │                    │   pattern, and in    │
        │                    │   each PatchPolicy   │
        │                    │   allow/deny/ignore  │
        │                    │   pattern, against   │
        │                    │   the host home.     │
        │                    │                      │
        │                    │ for each Patch:      │
        │                    │   FileSet::resolve() │
        │                    │   ── walkdir + glob ►│
        │                    │   Vec<PatchFile>     │
        │                    │   (per-file fanout)  │
        │                    │                      │
        ▼                    ▼                      │
┌─────────────────────────────────────────────────────────────┐
│  PASS 1 — Categorize (vars + patches only)                  │
│  ──────────────────────────────────────────                 │
│  For each item (item: T where T: Provenanced):              │
│    Policy::check(name_or_path, item)                        │
│      ignore matches?              ─── Ignored, drop         │
│      else, source == UserLoadout? ─── Allowed (bypass)      │
│      else, deny matches?          ─── Denied, error         │
│      else, allow matches?         ─── Allowed, push         │
│      else                         ─── NeedsApproval, batch  │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ unapproved.is_empty()?
                             ├─── yes ──► return allowed
                             │
                             ▼ no
┌─────────────────────────────────────────────────────────────┐
│  PASS 2 — Prompt (batch)                                    │
│  ───────────────────────                                    │
│  hooks.on_*_unapproved(                                     │
│      Policy,           ◄── owned copy; hook cannot mutate   │
│                            the resolver's state directly    │
│      &[Unapproved<_>]                                       │
│  ) -> HookResult<Policy>                                    │
│       │                                                     │
│       ├── Abort       ── return ResolveError::Aborted       │
│       └── Decided { decisions, updated_policy }             │
│              │                                              │
│              │  updated_policy: Some(p) installs p          │
│              │  before Pass 3 re-checks `UseRule` items     │
│              │  decisions length must match unapproved.len()│
│              │  else ─── ResolveError::HookContract         │
│              ▼                                              │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│  PASS 3 — Apply                                             │
│  ──────────────                                             │
│  For each (item, decision):                                 │
│    AllowOnce ── push to `allowed`                           │
│    DenyOnce  ── return ResolveError::Denied                 │
│    UseRule   ── Policy::check(item) again                   │
│                  → Ignored / Allowed / Denied as before     │
│                  → NeedsApproval ── ResolveError::HookContract
└────────────────────────────┬────────────────────────────────┘
                             │
                             │       ┌─── packages, hooks (unchanged) ───┐
                             ▼       ▼                                    │
                  ┌──────────────────────────────────────────┐            │
                  │             Resolution                   │◄───────────┘
                  │                                          │
                  │  vars()            -> &[SV]              │   SV = SessionVar
                  │  patches()         -> &[SP]              │        { var, source }
                  │  packages()        -> &[Pkg]             │   SP = SessionPatch
                  │  lifecycle_hooks() -> &[H]               │        { patch, source }
                  │  into_parts() -> (vars, patches,         │
                  │                   packages, hooks)       │
                  └────────────────────┬─────────────────────┘
                                       │
                                       ▼
                  (downstream: apply layer builds sandbox,
                   materializes vars, copies files, installs hooks)
```

## Key invariants

- **Composer accumulates; resolve decides.** All contribution happens
  first, then a single resolution pass. No interleaving.
- **`Composable::contribute` is the only entry point.** Contributors
  produce a [`Contribution`] value; `Composer::add` drains it into the
  composer's internal accumulators. There is no public way to push raw
  primitives — the boundary forces every item to have a known source.
- **Env lookup lives on the composer.** `Composer::new()` defaults to
  `std::env::var`; `Composer::with_env(...)` pins a custom closure for
  tests. Each `add` call threads the lookup into `contribute` so
  inheriting var values can be resolved at contribute time.
- **Source travels end-to-end.** Every primitive (vars, patches,
  packages, lifecycle hooks) carries its `Source` through resolution
  and into `Resolution`, so downstream layers (audit, inspection
  commands, error reporting) can attribute every surviving item back
  to its contributor.
- **Vars and patches are policy-gated; packages and hooks are not.**
  Package selection happens in the graph layer downstream; lifecycle
  hooks run inside the sandbox's isolated environment. Neither needs
  an `allow`/`deny`/`ignore` gate at this layer.
- **User-origin items bypass `allow`/`deny`.** Pass 1's `check`
  short-circuits to `Allowed` for `Source::UserLoadout` after the
  `ignore` test. The user is the authority for their own Loadout;
  `allow`/`deny` only gate other sources. `ignore` still applies
  uniformly.
- **Patches fan out before policy check.** A single `Patch` with a
  glob source becomes N `PatchFile`s; each is checked independently. A
  `Denied` on any one file kills the whole session.
- **Hook gets narrow policy by value.** The resolver hands the hook an
  owned `VarsPolicy` or `PatchPolicy` — never `&mut UserPolicy`. Hooks
  cannot cross domains and cannot mutate the resolver's state in place.
  To add a rule, the hook returns the modified copy in
  `HookResult::Decided.updated_policy`; the resolver installs it before
  Pass 3 re-checks `UseRule` items.
- **`HookContract` is the safety net.** Two ways it fires: decision
  count mismatch, or `UseRule` returning to a check that still says
  `NeedsApproval`. Both mean the application lied to the resolver. The
  error variant carries a context string naming the offending item.
- **Patch enumeration errors split by audience.** All errors are
  accumulated. After the walk, they're partitioned: configuration
  errors (`NoWalkRoot` — unfixable without changing the loadout)
  surface as `ResolveError::PatchConfig` and take priority over
  transient IO failures, which surface as `ResolveError::PatchWalk`.
  Nothing is silently dropped.
- **Source `~` is expanded at resolution; dest has no `~` to expand.**
  Patch source `FileSet` patterns and `PatchPolicy` patterns have
  their leading `~` expanded against the host home (via `Composer`'s
  home lookup — `dirs::home_dir` by default) before the walker runs.
  Patch *destination* paths (`PatchDest`) are always relative to the
  sandbox user's home directory; `~` and absolute paths are rejected
  at construction, so nothing needs to be expanded for dests. Patterns
  retain their `~` form in returned policies, so save/load is
  lossless. When any `~`-prefixed pattern is in scope, the home
  lookup is invoked once up-front; failures surface as
  `ResolveError::HomeUnresolved` (with an inner
  `HomeResolutionFailure::{Unavailable, NotUtf8}` distinguishing the
  cause) rather than silently matching nothing.
- **`Composer::merge` is pure aggregation today.** Two contributors
  pushing the same var name both survive into `Resolution.vars()`.
  Conflict resolution (precedence, dedup, error-on-conflict) will live
  in this single internal method when it lands; the merge site is
  intentionally one place to make that change local.
- **Internal invariants panic, not error.** `compute_dest` documents
  two preconditions (`enumerate_patch_files` upholds them) and panics
  with a precise message if either is violated. These are bug signals,
  not recoverable conditions.
- **Five failure modes terminate.** `Denied` (explicit policy reject),
  `Aborted` (user cancelled), `HookContract` (application bug),
  `PatchConfig` (loadout has unwalkable patterns), `PatchWalk` (IO-level
  walk failures).
