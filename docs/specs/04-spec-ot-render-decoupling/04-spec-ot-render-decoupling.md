---
id: spec-ot-render-decoupling
title: "ot render decoupling, separate operation state from indicatif, render per SSH channel"
kind: spec
status: shipped
tracking-issue:
supersedes:
---

# ot render decoupling - separate operation state from indicatif, render per SSH channel

## Context

`crates/ot` tracks a hierarchy of long-running operations (package builds,
fetches, checks, …) so progress can be drawn to the terminal. It was written
when `minimal` was a one-shot CLI: a single process owned a single terminal.

Today `ot` conflates three responsibilities inside one
`Arc<Mutex<TrackerInner>>` (`crates/ot/src/lib.rs`):

1. **Operation-tree state**: `depth`, `parent`, `children`, `op:
   Option<Operation>`. The genuinely reusable part.
2. **Progress data**: not actually stored; position/length live only inside
   the indicatif `ProgressBar`.
3. **Rendering**: `set_op` directly builds an indicatif `ProgressBar` with a
   hardcoded `ProgressStyle`, installs it into a process-global
   `static MP: MultiProgress`, which renders to **stderr** from indicatif's own
   thread. `StdoutWriter` exists only to `suspend()` that global render so
   plain logs do not collide with the bars.

Two process-global statics, `static ROOT` and `static MP`, encode the
assumption "one process == one terminal."

That assumption is now wrong. `minimal` is becoming a daemon (`minimald`) whose
long-running sessions are driven over an in-process SSH server. Progress must be
drawn to a **specific SSH channel**, one per session, each its own terminal,
each an async `AsyncWrite` (`Binding` in `crates/minimald/src/session_host.rs`
owns `ws.make_writer()`), none of them this process's stderr. There can be many
concurrent.

The plumbing is already in the right shape: `Option<OpTracker>` is threaded
through `mctx` (`config.rs`, `with_operation_tracker`), `minimald/src/env.rs`,
`op`, `rcache`, etc., via `OpTracker::new_with_root(&Option<OpTracker>)`. Almost
nothing outside `ot` needs to change except **where the root comes from** and
**who renders it**.

A future move to the `strides` crate for rendering should require no change to
the state core, only a new renderer.

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

## Layer 1 - pure state core

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
    version: tokio::sync::watch::Sender<u64>, // bumped on every mutation; the
                                              // channel value *is* the counter
    next_id: AtomicU64,
}
```

Every mutator (`set_op`, `set_done`, `set_length`, `increment`) bumps `version`
via `send_modify`, callable from sync code, so the synchronous build threads in
`op`/`graph` are unchanged and still wake the async renderer. `watch` (not
`Notify`) is used so **any number of drivers** can observe one root: each holds
its own `watch::Receiver`, every bump wakes all of them, and each tracks its own
last-seen version with no missed wakeups. (A single `notify_one` would wake only
one of several waiters.)

`OpTracker`'s public mutation API (`with_op`, `set_op`, `set_done`,
`set_length`, `increment`, `new_child`, `depth`) stays **identical**, so the
~20 call sites do not change. What changes is `new_with_root`'s fallback:
instead of a process-global `root()`, callers construct an explicit root via
`OpTracker::new_root()`. The CLI builds one; `minimald` builds one **per
session**.

### Decision: `tokio sync` in the core

`ot` gains `tokio = { workspace = true, features = ["sync"] }` for `Notify` and
the atomics' ergonomics. Pragmatic, matches the rest of the repo, async drivers
wake cheaply. (The dependency-free alternative, an `Arc<dyn Fn()>` callback,
was rejected as clunkier wiring for no real portability win here.)

## Layer 2 - observation (the "handle to a slice of progress")

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
    /// Subscribe to changes; each driver owns its own receiver.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64>;
}
```

A flat `Vec<OpSnapshot>` with `depth` is deliberately better than a nested tree:
it is already in render order, maps trivially to "rows," and is what both
indicatif and strides ultimately want. This Vec **is** the slice of progress a
renderer takes a handle to.

Drivers loop: render, then `rx.changed().await` (which also returns immediately
if the version advanced since the last observation, so missed wakeups are
impossible), then re-snapshot. A steady tick is still useful for spinner
animation. `changed()` resolves to `Err` once every `OpTracker` handle for the
tree is dropped, giving drivers a clean exit, and multiple receivers are fully
supported, so a root may have more than one driver.

## Layer 3 - drivers

A driver owns its I/O loop: wait for a change (or a tick) → `snapshot()` →
paint.

- **`IndicatifShim`** (deferred; see Decisions): keeps a `MultiProgress` + a
  `HashMap<OpId, ProgressBar>`, diffs each snapshot against live bars (add new
  ids, update pos/len/message, `finish_and_clear` vanished ids). All the
  `ProgressStyle` templates from today's `set_op` move here. Preserves current
  CLI behavior and the `StdoutWriter`/`suspend` log coordination, with no
  global, the shim owns its `MultiProgress`.

- **Daemon path, a scoped, exclusive renderer (revised).** The earlier
  `render_frame` + `BindingMsg::Progress` + `Host` `select!`-arm design (a
  progress overlay multiplexed into the PTY mainloop) is **superseded** by a
  simpler model: for the duration of one operation future, a renderer takes
  **exclusive** ownership of an async sink and paints the live tree onto it with
  indicatif; when the future resolves it clears the bars and hands the sink
  back. No second writer, no `Host`/`Binding` changes, no vt100 interaction.

  Two pieces:

  - **`ot` (indicatif feature): a generic scoped primitive.**
    ```rust
    pub async fn render_operations_while<W, F>(
        root: &OpTracker,
        sink: W,
        size: (u16, u16),          // (cols, rows); required — no hardcoded default
        fut: F,
    ) -> F::Output
    where W: tokio::io::AsyncWrite + Unpin + Send + 'static, F: Future;
    ```
    Internals: a `ChannelTerm` implementing indicatif's `TermLike` translates
    indicatif's sync cursor ops into ANSI bytes and pushes them onto an
    **unbounded** `mpsc` (a sync→async bridge, indicatif draws from its own
    steady-tick OS threads, which must never block on an async write; unbounded
    because dropping a frame mid-sequence would corrupt the stateful cursor
    stream). A pump task drains the `mpsc` into `sink`. The primitive feeds a
    `MultiProgress::with_draw_target(term_like(..))` into the **reused**
    `IndicatifShim` and runs a `select!` between `fut` and `root.subscribe()`
    (reconcile on each change). On `fut` completion: `mp.clear()`, drop the
    shim (stops tickers, drops the `mpsc` sender), `await` the pump so the clear
    is flushed, return the output. Generic over `AsyncWrite` so it is unit-
    testable against a `tokio::io::duplex` pipe.

  - **`minimald`: `ChannelProgress`**, the russh-concrete wrapper (keeps
    `russh` out of `ot`):
    ```rust
    pub struct ChannelProgress { channel: Channel<Msg>, tracker: OpTracker, size: (u16, u16) }
    impl ChannelProgress {
        pub fn new(channel: Channel<Msg>, tracker: OpTracker, size: (u16, u16)) -> Self;
        pub async fn run<F: Future>(self, fut: F) -> (Channel<Msg>, F::Output) {
            let w = self.channel.make_writer();        // 'static clone of the channel sender
            let out = ot::render_operations_while(&self.tracker, w, self.size, fut).await;
            (self.channel, out)                        // writer dropped; channel intact, returned
        }
    }
    ```
    `make_writer(&self)` clones the channel's internal sender, and the pump only
    ever `write_all`/`flush`es (never `shutdown`), so dropping the writer does
    not EOF the channel, handing it back is sound.

  **Exclusive-ownership constraint.** While the future runs, the wrapped
  operation must **not** write its own text to the same sink: this is a
  "compute under a progress bar, then print the result" model. It fits
  `check`/compute-style operations; live build-log streaming (which
  `run_patched_pkg` does today) is out of scope for v1 and would need the
  indicatif-`suspend` shared-writer path instead.

  **Wiring is deferred.** This step lands the reusable building block (the `ot`
  primitive + the `Channel<Msg>` wrapper) and tests it via the generic
  `AsyncWrite` seam. Which call sites adopt it, and reconciling that the
  current progress-producing handlers (`run_check`, `run_patched_pkg`) write to
  a per-request `UnixStream` rather than a `Channel<Msg>`, plus plumbing the real
  PTY `WinSize` down to supply `size`, is a separate follow-up.

- **`StridesDriver`** (future), additive, Layers 1-2 untouched.

## Migration plan

Each step compiles and keeps tests green.

| Step | Change | Blast radius |
|---|---|---|
| 1 | Add `Progress{pos,len}`, `OpId`, `RootShared` to the core; keep the `ProgressBar` field, feed both. Add `snapshot()`, `version()`, `changed()`. | `ot` only; existing tests pass |
| 2 | Carve `set_op`'s indicatif templates into an `IndicatifShim` that renders from `snapshot()`. Drop `pg` from `TrackerInner`; move indicatif behind a feature. **Core is now render-dep-free.** | `ot` only |
| 3 | Replace `static ROOT`/`root()` with `OpTracker::new_root()`. CLI builds one root; `minimald` builds one per session. Audit the `new_with_root(&None)` sites. | `ot` + entry points |
| 4 | Scoped renderer: `ot::render_operations_while` (generic `AsyncWrite` primitive: `TermLike`→`mpsc`→pump, reusing `IndicatifShim`) + a `minimald` `ChannelProgress` wrapper that consumes a `Channel<Msg>` + `OpTracker` + future and returns the channel + result. Building block only; call-site wiring + `WinSize` plumbing deferred. | `ot` + `minimald` |
| 5 | *(future)* `StridesDriver`. | new driver only |

## Decisions

- **Defer the CLI side.** indicatif stays as a thin shim over the new core
  (step 2); no effort re-imagining the local TTY UX now. It is an isolated
  later swap touching only Layer 3.
- **`watch` (not `Notify`) in the core** for change signalling (above), so a
  root supports multiple concurrent drivers with lossless wakeups.
- **Styling moves wholesale into drivers**; the state core stays semantic.
- **Daemon progress is scoped + exclusive** (step 4): a renderer owns the sink
  for one future's duration and returns it, rather than multiplexing a
  persistent overlay through the `Host`/`Binding` PTY loop. Simpler, no tearing,
  no `Host` changes; trades away live-log-plus-progress interleaving (deferred).
- **Step-4 primitive is generic over `AsyncWrite`**; the `russh`-concrete
  `ChannelProgress` wrapper is the only `Channel<Msg>`-aware piece, keeping
  `russh` out of `ot` and the core testable via a pipe.

## Non-Goals

- Re-designing the local CLI progress UX (deferred).
- Live operation output (build logs) interleaved with progress on the same sink
, the step-4 renderer is exclusive-ownership/compute-then-print; interleaving
  would need the indicatif-`suspend` shared-writer path (deferred).
- Wiring the step-4 renderer into specific call sites and plumbing the real PTY
  `WinSize` to supply its `size` (deferred follow-up; step 4 lands the building
  block only).
- Adopting `strides` (future, additive).
