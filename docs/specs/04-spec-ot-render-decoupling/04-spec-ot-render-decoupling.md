---
id: spec-ot-render-decoupling
title: "ot render decoupling — separate operation state from indicatif, render per SSH channel"
kind: spec
status: planned
tracking-issue:
supersedes:
---

# ot render decoupling — separate operation state from indicatif, render per SSH channel

## Context

`crates/ot` tracks a hierarchy of long-running operations (package builds,
fetches, checks, …) so progress can be drawn to the terminal. It was written
when `minimal` was a one-shot CLI: a single process owned a single terminal.

Today `ot` conflates three responsibilities inside one
`Arc<Mutex<TrackerInner>>` (`crates/ot/src/lib.rs`):

1. **Operation-tree state** — `depth`, `parent`, `children`, `op:
   Option<Operation>`. The genuinely reusable part.
2. **Progress data** — not actually stored; position/length live only inside
   the indicatif `ProgressBar`.
3. **Rendering** — `set_op` directly builds an indicatif `ProgressBar` with a
   hardcoded `ProgressStyle`, installs it into a process-global
   `static MP: MultiProgress`, which renders to **stderr** from indicatif's own
   thread. `StdoutWriter` exists only to `suspend()` that global render so
   plain logs do not collide with the bars.

Two process-global statics — `static ROOT` and `static MP` — encode the
assumption "one process == one terminal."

That assumption is now wrong. `minimal` is becoming a daemon (`minimald`) whose
long-running sessions are driven over an in-process SSH server. Progress must be
drawn to a **specific SSH channel** — one per session, each its own terminal,
each an async `AsyncWrite` (`Binding` in `crates/minimald/src/session_host.rs`
owns `ws.make_writer()`), none of them this process's stderr. There can be many
concurrent.

The plumbing is already in the right shape: `Option<OpTracker>` is threaded
through `mctx` (`config.rs`, `with_operation_tracker`), `minimald/src/env.rs`,
`op`, `rcache`, etc., via `OpTracker::new_with_root(&Option<OpTracker>)`. Almost
nothing outside `ot` needs to change except **where the root comes from** and
**who renders it**.

A future move to the `strides` crate for rendering should require no change to
the state core — only a new renderer.

## Introduction/Overview

Split `ot` into three layers:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 3  Drivers (per-context, own the I/O loop)            │
│   • IndicatifShim    → local CLI, renders tree to stderr     │
│   • (daemon) Host select! arm → renders subtree, sends       │
│                        bytes to the Binding actor            │
│   • (future) StridesDriver                                   │
├─────────────────────────────────────────────────────────────┤
│ Layer 2  Observation (pure data, no I/O)                     │
│   • OpTracker::snapshot() -> Vec<OpSnapshot>  (the "slice")  │
│   • OpTracker::version() / changed()          (change signal)│
├─────────────────────────────────────────────────────────────┤
│ Layer 1  State core (`ot`, no render deps)                  │
│   • OpTracker / TrackerInner: tree + Progress{pos,len}       │
│   • no indicatif, no process globals                         │
└─────────────────────────────────────────────────────────────┘
```

The `Operation` enum stays **semantic only**. All template/styling strings move
out of the core and into the drivers, so each renderer (indicatif now, strides
later, the daemon ANSI path) styles independently.

## Layer 1 — pure state core

`TrackerInner` drops the indicatif `ProgressBar` and stores progress numbers
itself:

```rust
pub struct OpId(u64);                 // stable id, for renderer diffing

#[derive(Clone, Debug)]
pub struct Progress { pub pos: u64, pub len: Option<u64> }

struct TrackerInner {
    id: OpId,
    depth: usize,
    parent: Option<OpTracker>,
    op: Option<Operation>,
    progress: Option<Progress>,
    children: Vec<Weak<Mutex<TrackerInner>>>,
    shared: Arc<RootShared>,          // every node points at its root's shared bits
}

struct RootShared {
    version: AtomicU64,               // bumped on every mutation
    notify: tokio::sync::Notify,      // wakes async drivers; notify_* is sync-callable
    next_id: AtomicU64,
}
```

Every mutator (`set_op`, `set_done`, `set_length`, `increment`) bumps `version`
and notifies — both callable from sync code, so the synchronous build threads in
`op`/`graph` are unchanged and still wake the async renderer.

`OpTracker`'s public mutation API (`with_op`, `set_op`, `set_done`,
`set_length`, `increment`, `new_child`, `depth`) stays **identical**, so the
~20 call sites do not change. What changes is `new_with_root`'s fallback:
instead of a process-global `root()`, callers construct an explicit root via
`OpTracker::new_root()`. The CLI builds one; `minimald` builds one **per
session**.

### Decision: `tokio sync` in the core

`ot` gains `tokio = { workspace = true, features = ["sync"] }` for `Notify` and
the atomics' ergonomics. Pragmatic, matches the rest of the repo, async drivers
wake cheaply. (The dependency-free alternative — an `Arc<dyn Fn()>` callback —
was rejected as clunkier wiring for no real portability win here.)

## Layer 2 — observation (the "handle to a slice of progress")

A driver never touches the live tree under its render loop. It takes an
immutable snapshot (lock briefly, clone, release) and renders without holding
the lock:

```rust
#[derive(Clone, Debug)]
pub struct OpSnapshot {
    pub id: OpId,
    pub depth: usize,
    pub op: Option<Operation>,
    pub progress: Option<Progress>,
}

impl OpTracker {
    /// Pre-order DFS flatten of this subtree, in display order.
    pub fn snapshot(&self) -> Vec<OpSnapshot>;
    /// Current change version; cheap to poll.
    pub fn version(&self) -> u64;
    /// Await the next change (best-effort wake; pair with version()).
    pub async fn changed(&self);
}
```

A flat `Vec<OpSnapshot>` with `depth` is deliberately better than a nested tree:
it is already in render order, maps trivially to "rows," and is what both
indicatif and strides ultimately want. This Vec **is** the slice of progress a
renderer takes a handle to.

`changed()` is a best-effort wake; `version()` is the source of truth. Drivers
loop: render, read version, `changed().await`, re-check version. Per root there
is at most one driver, so missed-wakeup races are bounded and reconciled by the
version check plus a steady tick (needed anyway for spinners).

## Layer 3 — drivers

A driver owns its I/O loop: wait for a change (or a tick) → `snapshot()` →
paint.

- **`IndicatifShim`** (deferred; see Decisions): keeps a `MultiProgress` + a
  `HashMap<OpId, ProgressBar>`, diffs each snapshot against live bars (add new
  ids, update pos/len/message, `finish_and_clear` vanished ids). All the
  `ProgressStyle` templates from today's `set_op` move here. Preserves current
  CLI behavior and the `StdoutWriter`/`suspend` log coordination, with no
  global — the shim owns its `MultiProgress`.

- **Daemon path (no separate writer).** `Binding`
  (`session_host.rs`) already owns the channel writer and is the single
  serialized writer via its `select!` loop. `Host` (the surrounding
  process-management actor) owns the session lifecycle, the vt100 `parser`
  screen, and the live binding's mailbox. Therefore:

  - Render is a **pure function** in `ot`:
    `render_frame(&[OpSnapshot], &mut RenderState) -> Vec<u8>` — produces the
    ANSI diff (cursor moves, clears, repaint) against the previous frame. No
    I/O.
  - The **`Host`** drives repaints: it holds the session `OpTracker` root and a
    persistent `RenderState`; its `mainloop` `select!` gains one arm = the
    root's `changed()` future plus a steady tick. On fire → `snapshot()` →
    `render_frame()` → send bytes to the binding.
  - The **`Binding`** just writes bytes: a new `BindingMsg::Progress(Bytes)`
    variant is written in the same `select!` family as process stdout, so
    progress and process output are serialized by construction — zero tearing,
    no extra lock.

  Render state lives in the `Host`, not the `Binding`, because it must survive
  detach/re-attach: the `Host` already replays
  `parser.screen().state_formatted()` on `attach()`, so the progress overlay
  repaints there alongside it.

- **`StridesDriver`** (future) — additive, Layers 1–2 untouched.

## Migration plan

Each step compiles and keeps tests green.

| Step | Change | Blast radius |
|---|---|---|
| 1 | Add `Progress{pos,len}`, `OpId`, `RootShared` to the core; keep the `ProgressBar` field, feed both. Add `snapshot()`, `version()`, `changed()`. | `ot` only; existing tests pass |
| 2 | Carve `set_op`'s indicatif templates into an `IndicatifShim` that renders from `snapshot()`. Drop `pg` from `TrackerInner`; move indicatif behind a feature. **Core is now render-dep-free.** | `ot` only |
| 3 | Replace `static ROOT`/`root()` with `OpTracker::new_root()`. CLI builds one root; `minimald` builds one per session. Audit the `new_with_root(&None)` sites. | `ot` + entry points |
| 4 | Daemon render: `render_frame` + `RenderState`, a `Host` `select!` arm, and `BindingMsg::Progress`. Thread the session root via existing builders. | `minimald` |
| 5 | *(future)* `StridesDriver`. | new driver only |

## Decisions

- **Defer the CLI side.** indicatif stays as a thin shim over the new core
  (step 2); no effort re-imagining the local TTY UX now. It is an isolated
  later swap touching only Layer 3.
- **`tokio sync` in the core** for change signalling (above).
- **Styling moves wholesale into drivers**; the state core stays semantic.

## Non-Goals

- Re-designing the local CLI progress UX (deferred).
- The vt100/overlay interaction in the daemon (whether progress renders in a
  reserved bottom region or is fed through the parser) — resolved in step 4; it
  affects only the daemon render path, not the `ot` core.
- Adopting `strides` (future, additive).
