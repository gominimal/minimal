---
id: spec-min-dash-tui
title: "min dash — session manager TUI for minimal"
kind: spec
status: shipped
tracking-issue:
supersedes:
---

# min dash — session manager TUI for minimal

## Context

`minimal` is the CLI that pairs with `minimald`. It exposes session
lifecycle commands — `ls`, `activate`, `attach`, `destroy`, `session policy` —
as flat one-shot subcommands. Each invocation connects, does one thing, prints
to stdout, and exits. There is no way to browse sessions, inspect their live
state, and act on them without re-issuing commands and re-connecting each time.

Meanwhile `minimald` already tracks rich per-session state: a live vt100
terminal parser (`session_host.rs:508`), terminal title, audible/visual bell
counts, last stdin/stdout timestamps, and effective networking policy. The CLI
surface (`ListSessions`, `GetSessionRecord`, `GetSessionPolicy`) returns this
data, but only as flat text output. The user cannot glance at "what is my
session doing right now" without attaching to it.

This spec describes `min dash` — a subcommand that opens an interactive
terminal UI for browsing, inspecting, and managing sessions across all
available providers on the host.

## Introduction/Overview

`min dash` is a new subcommand on `minimal` backed by a new `minimal-tui`
sub-crate. It renders a master-detail split: a filterable session list on the
left (grouped by provider), and a detail pane on the right that stacks the
Info, Policy, and Preview sections vertically. The Preview section shows a
read-only snapshot of the session's live terminal output via a new
`GetSessionScreen` RPC.

The TUI follows an Elm-style architecture (model/update/view) with a tokio
event loop driving crossterm input and a periodic refresh tick. It uses the
shared `minimal-client` SSH transport (extracted from `minimal`) for all RPCs.

### Layout

```
┌─ sessions ──────────────────────┐ ┌─ api-staging · a1b2… ──────────────────────────┐
│ / st_                           │ │ project  ~/src/api        net   OwnIp          │
│ ────                            │ │ user     chroma           idle  12s            │
│ ▼ host  minimald v0.1  ●        │ │ title    vim: src/api/main.rs                  │
│   ▸ api-staging    OwnIp    ●   │ │ bells    ●2 (last 3m)                          │
│     (unnamed)      Host         │ │ ─ Policy ────────────────────────────────      │
│ ▼ vm    minvmd kvm     ●        │ │ egress   allow all                             │
│     bench          NoNet        │ │ ─ Preview (live screen snapshot) ────────      │
│                                 │ │ $ cargo run                                    │
│                                 │ │    Finished `dev` profile in 3m 04s            │
│                                 │ │ $ ▏                                            │
└─────────────────────────────────┘ └────────────────────────────────────────────────┘
 ↑↓ move · / filter · enter attach · d destroy · r rename · n new · q quit
```

(Implemented revision: `enter` attaches in place — suspend TUI, ssh, resume
on detach.)

## Goals

- G1: `min dash` opens a full-screen TUI that lists all sessions across every
  available provider on the host (native `minimald` and `minvmd`).
- G2: The session list is filterable by fuzzy match against name, ID, and
  project path, reusing `common::fuzzy_match`.
- G3: A master-detail split shows session metadata, networking policy, and a
  read-only preview of the session's live terminal output.
- G4: The user can create, destroy, and rename sessions from within the TUI.
- G5: The TUI remembers the last-focused session across invocations via a
  small state file, so re-opening `min dash` restores the cursor.
- G6: The TUI is isolated in a sub-crate so `ratatui`/`crossterm` do not enter
  the compile path of the lean `minimal` CLI binary.

## Non-Goals

- N1: An embedded in-TUI terminal for attach. `enter` attaches in place by
  suspending the TUI, shelling out to `ssh`, and resuming on detach (see the
  "Implemented revision" note above). A rendered in-pane terminal emulator —
  attach living inside the TUI rather than replacing it — is not in scope.
- N2: Remote `minimald` session management. The `mesh` subcommand
  (`main.rs:101-143`) provides WireGuard networking for inter-PTask traffic,
  not remote session RPC. No remote daemon transport exists yet (see Possible
  Future Work).
- N3: Multi-round session creation wizard. The `SessionCreate`/`SubmitVerdict`/
  `SessionAbort` RPCs exist in `minimald-rpc` but the daemon-side composition
  flow is not wired (`COMPOSITION.md:44-51`). The TUI's create form uses the
  simple `CreateSession` RPC until the multi-round flow lands (see Possible
  Future Work).
- N4: Customizable keybindings. The initial keybind set is fixed.
- N5: Windows support. The SSH transport is UDS-based; the TUI targets the
  same platforms `minimal` already supports (Linux, macOS).

## Architecture

### Crate structure

A new sub-crate `crates/minimal-tui` (library + the TUI logic) is called from
a new `Dash` subcommand in `minimal`. The `minimal/src/client.rs` SSH client
(~167 lines) is extracted into a shared `minimal-client` lib so both the CLI
and the TUI use the same transport without duplicating it.

```
crates/
  minimal-tui/      ← new: ratatui, crossterm, Elm-style loop
    src/
      lib.rs         re-exports
      app.rs         model, update, view entry points
      event.rs       crossterm event → Msg
      rpc.rs         wraps minimal-client for TUI-specific calls
      render.rs      ratatui widgets
      filter.rs      fuzzy filter over session list
      state.rs       dash-state.json load/save
    Cargo.toml
  minimal-client/   ← new: extracted from minimal/src/client.rs
    src/lib.rs
    Cargo.toml
```

Both are added to the workspace `members` list and `workspace.dependencies`.

### Dependencies

Added to `[workspace.dependencies]` (per `docs/rust-coding-standards.md`,
check [blessed.rs](https://blessed.rs) first):

- `ratatui` — immediate-mode TUI rendering.
- `crossterm` — terminal raw mode, event polling, alternate screen.

`tokio`, `serde`, `serde_json`, `tracing`, `chrono`, `dirs`, `camino`,
`sessions`, `minimald-rpc`, `paths` are already workspace deps.

### Elm-style loop

The TUI is a standard Elm architecture:

```
Model          → App state: sessions, filter, cursor, focus, detail, ...
Msg            → enum of events: KeyPressed, Tick, RpcResult(...), ...
update(Model, Msg) -> Model + Effect
view(Model)    -> ratatui::Frame (pure; no side effects)
```

The tokio runtime drives:

1. A crossterm event poll task → `Msg::KeyPressed`.
2. A 1–2s refresh tick → `Msg::Tick` (re-fetches `ListSessions` and the
   focused session's detail/screen).
3. RPC tasks spawned from `update` → `Msg::RpcResult`.

### Provider discovery

On startup the TUI probes both known socket paths:

| Provider | Socket path | Source |
|---|---|---|
| Host minimald | `$XDG_STATE_HOME/minimal/providers/local-0/ssh.sock` | `client::resolve_socket_path(false)` |
| VM minvmd | `$XDG_RUNTIME_DIR/minimal/minimald.sock` | `client::resolve_socket_path(true)` / `minvmd::sock::resolve_uds_path()` |

Each reachable socket becomes a "provider" in the model. The TUI connects to
each, calls `ListSessions`, and aggregates the results into one list grouped
by provider. On macOS only the VM path exists (no native minimald); both
probes resolve to the same socket there, so discovery dedupes by socket path
and keeps a single provider (labeled `vm`). On Linux both can run
simultaneously — they are independent daemons on independent sockets. If
neither is running, the TUI auto-spawns the default provider (reusing
`autospawn::ensure_daemon_running`).

Discovery is not one-shot: a throttled rediscovery pass (~every 10s)
connects providers that appear mid-run. A provider whose refresh fails keeps
its sidebar slot, marked unreachable (red health dot, sessions cleared),
and rejoins when the daemon comes back. Sessions are keyed by provider
label, never by list index, so a provider dropping out of one refresh cannot
misroute actions to another daemon. UI-loop RPCs carry a short deadline so
an unresponsive daemon fails the refresh instead of freezing the TUI.

### Sidebar row indicators

Each session row in the sidebar carries a small indicator strip to the
right of the network mode. The indicator is computed from
`RunningSessionAttrs` on each refresh tick (and in a future streaming
model, updated immediately on push).

| Indicator | Glyph | Meaning | Heuristic |
|---|---|---|---|
| **Active** | `◐◑◒◓` (cycling) | Session produced stdout recently | `last_stdout` within 5s |
| **Waiting** | `○` | Session read stdin recently but no stdout since | `last_stdin` within 5s, `last_stdout` older than 5s or absent |
| **Bell** | `●` | Unacknowledged audible or visual bell | `audible_bell.last` or `visual_bell.last` more recent than the last time this session was focused in the TUI |
| **Idle** | (blank) | No recent activity | Neither of the above |

The `●` bell is client-side state: when the user focuses a session, the
TUI records "bells seen up to now" in the model. If a new bell arrives
with a later timestamp, the `●` lights up. When the user focuses the
session again, it clears. No daemon change needed.

The `○` / spinner distinction is a heuristic, not a daemon signal. The
daemon records `last_stdin` (user typed something) and `last_stdout`
(session wrote something). If the user typed recently but nothing came
back, we infer the session is waiting — `cat`, `python` REPL, a
password prompt, etc. This can misfire (e.g. a slow command between
keystroke and output) but is right often enough to be useful.

### Last-session memory

A tiny JSON state file at `$XDG_STATE_HOME/minimal/dash-state.json` stores:

```json
{ "last_session_id": "a1b2...", "last_provider": "host" }
```

On launch the TUI restores the cursor to `last_session_id` if it still exists
in the refreshed list. Written on every cursor change (debounced — write on
exit and on explicit selection, not on every key press).

## New RPC: GetSessionScreen

### Motivation

The daemon's `Host` actor owns a live `vt100_ctt::Parser`
(`session_host.rs:508`) that continuously processes PTY output. On `attach`
it writes `self.parser.screen().state_formatted()` to the new SSH channel
(`session_host.rs:1140`). There is no way to read the screen without
attaching — and attaching opens a live I/O relay and triggers a PTY resize
(`set_size` → `SIGWINCH`).

The Preview section needs read-only access to the screen without these side
effects. A new oneshot RPC provides it.

### Wire contract

Added to `crates/minimald-rpc/src/lib.rs`:

```rust
/// An RPC to snapshot a session's terminal screen without attaching.
pub struct GetSessionScreen;

/// Request for [`GetSessionScreen`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetSessionScreenRequest {
    Id(SessionId),
    Name(String),
}

/// A single terminal cell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenCell {
    pub ch: char,
    pub fg: Option<String>,   // ANSI color name or hex, None = default
    pub bg: Option<String>,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub reverse: bool,
}

/// A row of terminal cells.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenRow {
    pub cells: Vec<ScreenCell>,
}

/// The terminal screen snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenSnapshot {
    pub rows: u16,
    pub cols: u16,
    pub cursor_row: Option<u16>,
    pub cursor_col: Option<u16>,
    pub lines: Vec<ScreenRow>,
}

impl OneshotSshRpc for GetSessionScreen {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionScreen");
    type Request<'a> = GetSessionScreenRequest;
    type Response = Errorable<ScreenSnapshot>;
}
```

Structured cells (not raw ANSI) so ratatui renders `Cell`s directly without
an embedded ANSI parser. The `rows`/`cols` are the terminal dimensions the
session process sees (its PTY size), which may differ from the TUI's own
terminal size — the Preview pane scrolls if the session is larger.

### Daemon-side handler

The handler resolves the session by ID/name (same path as
`GetSessionRecord`), sends a new `Message::GetScreen` to the `Host` actor,
and the `Host` returns a snapshot of `self.parser.screen()`. The vt100 crate
exposes per-cell access via `screen().state_formatted()` (ANSI) but for
structured output the handler iterates the grid and builds `ScreenRow`s.
The `Host`'s existing `select!` loop gains a `Message::GetScreen` arm.

This is the one piece of daemon-side work the spec depends on; everything
else uses existing RPCs.

## Demoable Units of Work

### Unit 1 — Scaffolding: sub-crate and subcommand

**R1.1** Create `crates/minimal-tui` with `Cargo.toml` (deps: `ratatui`,
`crossterm`, `tokio`, `tracing`, `sessions`, `minimald-rpc`, `paths`,
`common`, `chrono`, `serde`, `serde_json`, `dirs`, `camino`). Add to
workspace `members` and `workspace.dependencies`.

**R1.2** Extract `minimal/src/client.rs` into `crates/minimal-client`
(shared lib). Update `minimal` to depend on `minimal-client`. Both
`minimal` and `minimal-tui` depend on `minimal-client`.

**R1.3** Add `Dash` subcommand to `minimal`'s `Command` enum. The handler
calls `minimal_tui::run(global_args)` which enters the TUI event loop and
returns when the user quits.

**R1.4** Elm-style skeleton: `Model`, `Msg`, `update`, `view`. Crossterm
raw-mode enter/leave, alternate screen, a `Frame` that renders "no sessions"
placeholder. Tokio loop with crossterm event poll + 2s tick. `q` quits.

### Unit 2 — Provider discovery and session list

**R2.1** On startup, probe both socket paths (`resolve_socket_path(false)`
and `resolve_socket_path(true)`). For each reachable socket, connect and call
`ListSessions`. Aggregate into `Model::providers: Vec<Provider>` where each
`Provider` has a label (`host` / `vm`), version string, and `Vec<ListSessionsEntry>`.

**R2.2** Render the left pane: provider group headers (collapsible) with
session rows beneath. Each row shows name (or generated short name), network
mode, and an activity indicator (● if `last_stdout`/`last_stdin` within 60s).

**R2.3** `↑`/`↓` moves the cursor within the filtered set. `Enter` on a
group header toggles collapse/expand.

**R2.4** Refresh tick: re-call `ListSessions` on every reachable provider and
update the model. The cursor stays on the same session if it still exists.

### Unit 3 — Fuzzy filter

**R3.1** `/` enters filter mode; typing narrows the list; `Esc` clears the
filter. While filtering, the input line replaces the footer.

**R3.2** The filter calls `common::fuzzy_match` against each session's name,
ID, and project path (last path segment). Results are ranked by match quality
(`SearchMatch` ordering) and the provider grouping is preserved in the
filtered view.

**R3.3** When the filter is active and the list narrows, the cursor clamps to
the first visible row if the previously focused row was filtered out.

### Unit 4 — Detail pane: Info and Policy sections

**R4.1** When a session is focused, call `GetSessionRecord` and
`GetSessionPolicy` (debounced: one RPC per focus change, not per tick). Cache
in the model.

**R4.2** Info section: project path, username, network mode, session ID. Live
attrs from `ListSessions` (title, last stdin/stdout, bell counts) are merged
from the list-refresh data — no separate RPC.

**R4.3** Policy section: egress (allowed subnets, DNS hosts, protocols) and
ingress (port mappings, dynamic range) rendered as a readable list. If the
session is not `OwnIp`, show "No network policy (HostNet/NoNet)".

### Unit 5 — Preview section: GetSessionScreen RPC

**R5.1** Add `GetSessionScreen` RPC types to `minimald-rpc`.

**R5.2** Add `Message::GetScreen` to the `Host` actor's `Message` enum
(`session_host.rs`). The handler snapshots `self.parser.screen()` into a
`ScreenSnapshot` and returns it via a oneshot channel. The `Host`'s `select!`
loop gains the arm. The snapshot is read-only — no PTY resize, no I/O relay.

**R5.3** Add the RPC handler in `minimald/src/rpc.rs`: resolve session by
ID/name (reusing the `GetSessionRecord` path), send `Message::GetScreen` to
the `Host` actor, serialize the `ScreenSnapshot` as the response.

**R5.4** TUI Preview section: on each refresh tick, call
`GetSessionScreen` for the focused session. Render the `ScreenSnapshot` as a
read-only ratatui `Paragraph` or custom widget. If the session's terminal is
larger than the pane, scroll (cursor follows the session's cursor position).
If the session has no screen (not running), show "Session not active".

### Unit 6 — Session actions

**R6.1** `d` on a focused session opens a confirmation prompt ("Destroy
<name>? y/n"). On `y`, call `DestroySession`. On success, remove from model
and move cursor to the next session.

**R6.2** `r` opens an inline input pre-filled with the current name. On
`Enter`, call `RenameSession`. On success, update the model.

**R6.3** `n` opens a create form: name (optional), project path (default:
cwd), network mode (HostNet/OwnIp/NoNet, default: HostNet). The create
targets the provider the cursor points at (the focused session's provider,
or the provider whose group header is selected). On confirm, call
`CreateSession` with a `sessions::Record`. On success, refresh the list and
focus the new session. The upload root resolves like the CLI's (walk up to
the nearest `minimal.toml` repo root); a root that is not a VCS checkout is
refused with a pointer to `min session activate` (the CLI's #770
confirmation has no TUI form). The create sends the loadout contribution the
CLI composed at `min dash` startup, so `default_loadouts` and the user
policy apply to dashboard-created sessions too.

### Unit 7 — Last-session memory

**R7.1** On every cursor change (debounced: write on quit and on explicit
selection, not every key press), write
`$XDG_STATE_HOME/minimal/dash-state.json` with `last_session_id` and
`last_provider`.

**R7.2** On startup, after the first `ListSessions` refresh, if
`last_session_id` exists in the list, set the cursor to it. If it doesn't
exist (session was destroyed), fall back to the first row.

### Unit 8 — Testing and polish

**R8.1** Unit tests for `update`: key events produce expected model
transitions; filter narrows correctly; cursor clamping on filtered list.

**R8.2** Snapshot tests for `view` using ratatui's `TestBuffer` + `insta`:
empty list, single provider, two providers, filtered, detail pane with
policy.

**R8.3** Integration test for `GetSessionScreen`: spin up the test harness,
create a session, write to its PTY, call `GetSessionScreen`, assert the
snapshot contains the expected output.

**R8.4** Run `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo
test -- --include-ignored` per `CLAUDE.md`.

## Possible Future Work

These items are called out for feedback. They are not in scope for v1 but are
natural follow-ups.

### F1: Attach/detach from within the TUI

Currently `cmd_attach` shells out to `ssh` via `CommandExt::exec()`, which
replaces the process. A TUI-native attach would: suspend the TUI (leave
alternate screen, `disable_raw_mode`), spawn `ssh` as a child, wait for it
to exit, then resume the TUI (re-enter alternate screen, `enable_raw_mode`,
refresh). The user detaches with the negotiated chord (default `ctrl-]` then
`d`), handled per channel by the daemon's session-key matcher in
`session_host.rs`, which tears down the SSH channel; `ssh` exits; the
TUI resumes.

Complexity: the detach chord is now configurable. The leader key (default
`ctrl-]`, `0x1d`) is negotiated per-channel at attach — the client sends it
as env vars alongside `MINIMAL_SESSION_ID`, and the daemon re-validates it
(termios-special chords are rejected as a safety backstop). The daemon's
matcher derives the full encoding set (plain byte, kitty, modifyOtherKeys)
from the negotiated key, so a remapped leader gets its CSI forms
automatically. The old `ctrl-w` default was itself termios-special
(`VWERASE`) and is retired; `0x17` is now an ordinary forwarded key.

### F2: Remote minimald sessions

The `mesh` subcommand (`main.rs:101-143`) establishes WireGuard tunnels for
inter-PTask networking, not remote session management. To show remote
sessions in the TUI sidebar, a remote-daemon transport is needed: either
`ssh`-based (connect to a remote host and reuse the same UDS path there —
`russh` is already a workspace dep) or a TCP/TLS socket exposed by a remote
`minimald`. A provider registry (e.g. `~/.config/minimal/providers.toml`)
would name and configure remote providers. The TUI's provider-grouped
sidebar already accommodates this — each remote becomes another group.

### F3: Multi-round session creation wizard

The `SessionCreate`/`SubmitVerdict`/`SessionAbort` RPCs exist in
`minimald-rpc` (lines 253-278) and the wire types are defined
(`sessions/src/wire/request.rs`). The flow is a client/daemon negotiation:
the client sends its loadouts, the daemon collects project- and
package-level contributions that need client-side policy gating, the client
runs the policy and prompts the user, and sends back per-item verdicts.

This is a natural fit for a TUI wizard: the `ContributionResponse` becomes a
checklist the user approves/denies, and the TUI sends a `ContributionVerdict`.
However, the daemon-side flow is not yet wired — `SessionComposer::compose`
errors with `HookRequired` instead of batching pending items
(`COMPOSITION.md:44-51`). This is blocked on daemon-side work.

### F4: Streaming session events

The TUI polls `ListSessions` and `GetSessionScreen` on a refresh tick.
A streaming `WatchSessions` RPC could push events in real time — title
changes, bell events, stdin/stdout activity, create/destroy lifecycle
— using the same `version()`/`changed()` pattern the `ot` crate uses
(`crates/ot/src/lib.rs:69-94`). The daemon already captures every event
in the `Host` actor (`SetTitleCallback`, `AudibleBellCallback`,
`VisualBellCallback`, `stdout_last`, `stdin_last` at
`session_host.rs:1060-1094`). A long-lived streaming channel would
eliminate polling latency, enable immediate sidebar indicator updates
(spinner → `○` transitions visible in real time), and reduce wasted
RPCs. The current `OneshotSshRpc` contract would need a `StreamingSshRpc`
counterpart. This also subsumes a per-session `WatchSessionScreen` for
the Preview section — the same stream carries screen-change events.

### F5: Customizable keybindings

The initial keybind set is fixed. A future keybind configuration (e.g. via
`dash-state.json` or a `minimal.toml` section) would let users remap keys,
particularly important if the attach/detach leader chord (F1, default
`ctrl-]`) conflicts with in-session applications.

## Security Considerations

- The TUI connects to the same UDS sockets the CLI already uses. No new
  network surface. The `GetSessionScreen` RPC is read-only and returns the
  same data that `attach` already sends — it does not expose new
  information.
- The `dash-state.json` file is written to `$XDG_STATE_HOME/minimal/` with
  owner-only permissions (matching the existing socket directory convention).
  It stores only a session ID and provider label — no credentials, no
  secrets.

## Open Questions

- O1: Should `GetSessionScreen` return the full scrollback buffer or only the
  visible screen? The vt100 parser's `screen()` exposes the visible grid. A
  scrollback-capable variant would need a larger buffer and more data per
  snapshot. v1 returns the visible screen only; scrollback is future work.
- O2: The create form's project path picker — should it support tab-completion
  of filesystem paths? v1 uses a plain text input (cwd default, user types a
  path). A path-completing picker is a polish item for later.

## Verification

**Proof artifact 1 (Test):**
`cargo test -p minimal-tui` passes, covering `update` unit tests and `view`
snapshot tests (insta). The `GetSessionScreen` integration test in
`minimald` passes: `cargo test -p minimald -- get_session_screen`.

**Proof artifact 2 (File):**
`grep -q 'Command::Dash' crates/minimal/src/lib.rs` — the subcommand exists.
`grep -q 'GetSessionScreen' crates/minimald-rpc/src/lib.rs` — the RPC is
defined.
`grep -q 'ratatui' Cargo.toml` — the dependency is pinned.

**Proof artifact 3 (Manual):**
`min dash` opens the TUI, shows sessions from all running providers, and the
Preview section shows live terminal output for a focused session without
attaching.
