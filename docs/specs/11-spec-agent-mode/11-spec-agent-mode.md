---
id: spec-agent-mode
title: "minimal agent mode: declarative agents and subagent forking"
kind: spec
status: planned
tracking-issue:
supersedes:
---

# minimal agent mode: declarative agents and subagent forking

## Context

`minimal.toml` today makes two execution concepts first-class:

- **Tasks** — one-shot commands run in a sandbox. `Task`
  (`crates/mfile/src/tasks.rs:6`) carries execution/sandbox concerns:
  a flattened `TaskAction` (`exec`/`bash`/`cmdcmd`/`echo`,
  `tasks.rs:112`), `packages`, `vars`, `patch`, `inherit_cwd`, `args`,
  and an `interactive: bool` flag (`tasks.rs:37`). Resolved to
  `Vec<Invocation>` by `op::TaskEnv` (`crates/op/src/task_env.rs:21`)
  and run to completion via `sandbox2::run` with piped stdio.
- **Sessions** — a long-lived, PTY-backed isolation environment.
  The project contribution is the `[session]` block (`Session`,
  `crates/mfile/src/lib.rs:374`), which carries *composition*
  primitives (packages, vars, patches, lifecycle hooks). At runtime a
  session is a persisted `Record` + actor + PTY session-host
  (`crates/minimald/src/session.rs`, `session_host.rs`).

There is **no agent concept**. AI/coding agents (Claude Code, and
other harnesses) are run today only by hand-writing a task, e.g. the
repo's own `[tasks.claude]` (`.minimal/minimal.toml`) that execs a
single hard-coded harness binary. That approach hard-codes one
harness, carries no reusable descriptor (instructions, tool scope,
model), and has no notion of an agent spawning subagents.

Two adjacent facts shape this design:

1. **`interactive` tasks are declarable but not runnable.** Both the
   daemon env-socket runner (`crates/minimald/src/env.rs:887`) and the
   local mctx runner (`crates/mctx/src/env.rs:373`) explicitly refuse
   `interactive = true` ("cannot run interactive tasks from within an
   environment"). Real interactivity today comes only from an SSH
   `shell_request` + PTY (`session.rs:687`, `connection.rs:384`), while
   `exec_request` + piped stdio is the non-interactive path
   (`exec.rs:773`). This is the seam agent interactivity builds on.
2. **An in-sandbox → daemon control channel already exists.** The
   baseline session installs `socat` and an in-sandbox `min` helper
   that relays to the daemon over `/run/minenv_sock`
   (`crates/sandbox2/src/lib.rs:267`, `session_host.rs`). A running
   process can already ask the daemon to do more work; subagent
   spawning is a new verb over an existing channel.

**Naming.** "agent" and "harness" are already load-bearing terms in
this repo: *agent* means the in-VM guest-agent (libkrun/kata) and the
CI automation bot (`docs/ci-strategy.md §10`); *harness* means the
build-stack (`[stack]`, formerly `[harness]`). This spec's **agent** is
an AI/coding agent, and the thing that actually executes one is called
an **agent runtime** or **adapter** — never a "harness" — to avoid the
collision.

## Introduction/Overview

Make **agents** a third first-class citizen in `minimal.toml`, in a way
that is deliberately *not* tied to any one AI harness. Four additions:

1. **A `[agents.<name>]` mfile block.** A hybrid of the task's
   execution surface and a generic, harness-agnostic *descriptor*
   (identity, instructions, tool scope, model, MCP servers, skills),
   plus a **subagent/fork policy**. Modelled field-for-field on the
   established `Session`/`Task` conventions (snake_case keys,
   `#[serde(default)]`, a flattened `extra` catch-all, a drift-guarding
   `is_empty()`).

2. **Descriptor materialization.** minimal does not know how any
   specific harness takes its instructions or tool list. Instead it
   *materializes* the generic descriptor into a fixed convention — a
   set of `MINIMAL_AGENT_*` environment variables plus a normalized
   spec file pointed to by `MINIMAL_AGENT_SPEC` — and runs the agent's
   **launch action** (`exec`/`bash`, exactly like a task). A thin
   per-harness adapter (a small wrapper script or the harness's native
   config-from-env support) translates that convention into the
   harness's own flags/frontmatter. The generic subset mirrors the
   useful Claude sub-agent frontmatter fields
   (`https://code.claude.com/docs/en/sub-agents#supported-frontmatter-fields`)
   while dropping the Claude-specific ones (`hooks`, `memory`, `color`,
   `effort`, `permissionMode`, model aliases such as `sonnet`/`opus`).

3. **A subagent fork/spawn control surface.** A running agent forks
   subagents — either **named** `[agents.<name>]` definitions or
   **ad-hoc** inline ones — via an in-sandbox `min agent spawn` verb
   relayed to the daemon. Each spawn independently chooses its
   **sandbox scope** (share the parent's sandbox/codebase, or a fresh
   one) and its **interactivity** (prompt vs interactive), at the
   discretion of the instantiating agent, gated by the parent's
   declared `subagents` policy.

4. **An interactive spawn path.** Spawns requesting `interactive` are
   wired to a PTY-backed session-host (the `shell_request` seam),
   lifting the interactive-execution gap for the agent path
   specifically, while prompt-mode spawns keep the piped-stdio
   one-shot model.

This is a **planning spec**. It fixes the config surface, the
materialization convention, and the fork semantics; concrete
per-harness adapters and the harness matrix are out of scope
(Non-Goals).

## Goals

1. A `[agents.<name>]` block parses into a typed `Agent` in `mfile`,
   following existing conventions, with a forward-compatible `extra`
   catch-all and `warn_unknown_fields` coverage — no harness-specific
   field names anywhere in the schema.
2. The generic descriptor (identity, instructions, tools, model,
   max-turns, MCP, skills) is materialized into a documented,
   stable `MINIMAL_AGENT_*` + `MINIMAL_AGENT_SPEC` convention that any
   adapter can consume, decoupling minimal from any single harness.
3. An agent is launched through the existing task-action/`Invocation`
   machinery, reusing package/var/patch/cwd plumbing rather than a
   parallel executor.
4. A running agent can spawn subagents — named or ad-hoc — into a
   **shared** or **fresh** sandbox, choosing **prompt** or
   **interactive** interactivity per spawn, gated by a declared policy.
5. Interactive spawns attach to a PTY session-host; prompt spawns run
   as piped one-shots. The instantiating agent picks per spawn.
6. No behavioural change to existing task/session paths; agents are
   additive.

## User Stories

- As a developer, I want to declare a reusable code-review agent in
  `minimal.toml` — its instructions, allowed tools, and model — so that
  every contributor invokes the same agent without hand-wiring a task.
- As a platform team, I want the agent config to be harness-agnostic,
  so that I can point the same descriptor at a different agent runtime
  by swapping the launch command, not rewriting the config.
- As an agent author, I want my running agent to fork a focused
  "explorer" subagent in the *same* sandbox to search the codebase and
  return a summary, so that exploration doesn't pollute the main
  context.
- As an agent author, I want to fork a subagent into a *fresh* sandbox
  for an untrusted or destructive step, so that it can't touch the
  parent's working tree.
- As an agent author, I want to choose whether a subagent runs
  headless (prompt) or attaches an interactive terminal, so that I can
  hand control to a human or keep it fully automated as the task
  demands.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2). These IDs are referenced directly by the planner — do
> not renumber after approval.

---

### Unit 1: `[agents.<name>]` schema + parsing in `mfile`

**Purpose:** Add a typed, harness-agnostic `Agent` config that parses
from `[agents.<name>]` tables, mirroring the `Task`/`Session`
conventions.

**Depends on:** None

**Affected areas:**
- `crates/mfile/src/agents.rs` (new) — `Agent` + descriptor types
- `crates/mfile/src/lib.rs` — `File::agents: HashMap<String, Agent>`;
  `warn_unknown_fields` walk over each agent's `extra`
- `crates/mfile/src/tasks.rs` — reuse `TaskAction`, `StrOrList`,
  `EnvPatches`, `EnvVarValue` (already `pub`)
- `docs/reference/minimal-dot-toml.md` — document the `[agents]` table

**Baseline:**
- `File` (`lib.rs:606`) has `tasks` and `session` but no `agents`.
- `warn_unknown_fields` (`lib.rs:746`) walks top-level, `defaults`,
  `stack`, `session`, each task, each output — not agents.

**Reference schema (the block this unit parses):**

```toml
[agents.reviewer]
description  = "Reviews diffs for correctness"

# Launch action — same shape as a task action (exec | bash | cmdcmd | echo)
exec         = "my-agent-runtime"          # or bash = """ ... """

# Generic descriptor (harness-agnostic; materialized in Unit 2)
instructions = "You are a meticulous code reviewer."   # or { file = "agents/reviewer.md" }
model        = "provider/model-id"          # opaque string; the adapter interprets
max_turns    = 20
tools        = { allow = ["read", "grep"], deny = ["write"] }
mcp          = ["github", { name = "db", command = "db-mcp", args = ["--ro"] }]
skills       = ["code-review"]

# Environment (Task-like; reuses existing plumbing)
packages     = ["ripgrep"]
vars         = { RUST_LOG = "info" }
patch        = { dir = { "config" = "read-only" } }
inherit_cwd  = true

# Subagent / fork policy
[agents.reviewer.subagents]
allow        = ["explorer", "*"]            # named defs; "*" also permits ad-hoc
sandbox      = "shared"                     # default scope:  shared | fresh
mode         = "prompt"                     # default mode:   prompt | interactive
```

**Functional Requirements:**

- **R1.1**: `crates/mfile/src/agents.rs` (new) shall define
  `pub struct Agent` with `#[serde(default)]` fields:
  `description: Option<String>`, a `#[serde(flatten)] action: TaskAction`
  (reusing `tasks::TaskAction`), `instructions: Option<Instructions>`,
  `model: Option<String>`, `max_turns: Option<u32>`, `tools: ToolPolicy`,
  `mcp: Vec<McpServer>`, `skills: Vec<String>`, `packages: Vec<String>`,
  `vars: HashMap<String, EnvVarValue>` (alias `env_vars`),
  `patch: EnvPatches` (alias `patches`), `inherit_cwd: bool`,
  `subagents: SubagentPolicy`, and a `#[serde(flatten)] extra:
  HashMap<String, toml::Value>`. Keys are snake_case; the struct derives
  `Debug, Default, Clone, Serialize, Deserialize, PartialEq` (no `Eq`,
  matching `Session`'s `extra`-map rationale at `lib.rs:405`).
- **R1.2**: `Instructions` shall be an untagged enum — bare string
  (inline system prompt) or `{ file = <config-relative path> }` — with
  the file variant validated as a project-relative path (no absolute /
  `..` traversal), reusing the existing `ConfigRelPath` precedent
  (`crates/sessions/src/core/lifecyclehook.rs`). `ToolPolicy` shall be
  `{ allow: Vec<String>, deny: Vec<String> }`, both `#[serde(default)]`.
  `McpServer` shall be an untagged enum — a bare string (reference to a
  named server) or an inline `{ name, command, args, env }` table.
  `SubagentPolicy` shall be `{ allow: Vec<String>, sandbox:
  SandboxScope, mode: Interactivity }` with `SandboxScope`
  (`shared`|`fresh`, `#[serde(rename_all = "lowercase")]`) and
  `Interactivity` (`prompt`|`interactive`) enums; `sandbox` defaults to
  `shared`, `mode` to `prompt`.
- **R1.3**: `File` (`lib.rs`) shall gain
  `#[serde(default)] pub agents: HashMap<String, Agent>` and
  `warn_unknown_fields` shall walk each agent's `extra`, emitting the
  existing per-section unknown-key warning.
- **R1.4**: `Agent` shall provide `#[must_use] fn is_empty(&self) ->
  bool` using an exhaustive `let Self { .. } = self` destructure so a
  new field fails to compile until handled — mirroring
  `Session::is_empty` (`lib.rs:427`). An `AgentName` newtype
  (validated: non-empty, `[a-z0-9-]`) shall wrap the map key at the
  boundary where agents are resolved, via `nutype`.

**Proof Artifacts:**
1. **Test:** `agents::tests::populated_block_parses_every_field` — a
   TOML block exercising action + every descriptor + `[agents.*.
   subagents]` round-trips to the expected `Agent`.
2. **Test:** `agents::tests::unknown_field_lands_in_extra` and
   `mfile::tests::warn_unknown_fields_covers_agents` — forward-compat
   parity with the `session_unknown_field_lands_in_extra` precedent
   (`lib.rs:1499`).
3. **Test:** `agents::tests::instructions_file_rejects_absolute_path`
   and `defaults_are_shared_prompt` — validation + policy defaults.
4. **Code:** `crates/mfile/src/agents.rs` — the `is_empty` exhaustive
   destructure drift guard.

---

### Unit 2: Descriptor materialization + launch

**Purpose:** Turn a parsed `Agent` into a runnable invocation: resolve
its launch action through the task machinery, with the generic
descriptor exposed via the `MINIMAL_AGENT_*` convention.

**Depends on:** Unit 1

**Affected areas:**
- `crates/op/src/task_env.rs` — an `AgentEnv` alongside `TaskEnv`, or a
  descriptor-materialization step feeding the same `Invocation` build
- `crates/mctx/src/env.rs` — agent resolution (`Context::agent(...)`),
  paralleling `task(...)`/`make_env(...)`
- `crates/mip/src/cmd_run.rs` (or a new `cmd_agent.rs`) — the CLI entry
  that materializes + launches

**Baseline:**
- `TaskEnv::resolve` (`task_env.rs:35`) builds `Vec<Invocation>` from a
  `TaskAction`; `Invocation` is executable + args + envs.
- No descriptor materialization or `MINIMAL_AGENT_*` convention exists.

**Functional Requirements:**

- **R2.1**: A materialization step shall serialise an `Agent`'s
  descriptor into a normalized, harness-neutral spec file (JSON) written
  to the sandbox `TMPDIR`, and set `MINIMAL_AGENT_SPEC` to its path. The
  spec shall contain `name`, `description`, `instructions` (resolved to
  literal text — the `{ file = ... }` variant read and inlined),
  `model`, `max_turns`, `tools.{allow,deny}`, `mcp`, and `skills`.
- **R2.2**: The same fields shall also be exposed as individual
  environment variables for adapters that prefer env over a file:
  `MINIMAL_AGENT_NAME`, `MINIMAL_AGENT_DESCRIPTION`,
  `MINIMAL_AGENT_INSTRUCTIONS`, `MINIMAL_AGENT_MODEL`,
  `MINIMAL_AGENT_MAX_TURNS`, `MINIMAL_AGENT_TOOLS_ALLOW`,
  `MINIMAL_AGENT_TOOLS_DENY`, `MINIMAL_AGENT_MCP`, `MINIMAL_AGENT_SKILLS`
  (list-valued vars newline- or JSON-encoded, documented once). These
  are merged with the agent's own `vars` (agent `vars` win on conflict,
  with a warning).
- **R2.3**: The agent's launch action shall be resolved to
  `Vec<Invocation>` by reusing the task action machinery
  (`TaskAction::exec_and_args`/`cmdcmd`), and run in a sandbox built
  from the agent's `packages`/`vars`/`patch`/`inherit_cwd` via the
  existing `make_env`/`Env` path — no parallel executor.
- **R2.4**: The field-name → convention mapping shall be documented as
  a table in `docs/reference/minimal-dot-toml.md`, and shall use *only*
  generic names (no `sonnet`/`opus`/`claude`-shaped values or keys),
  satisfying the "not harness specific" requirement.

**Proof Artifacts:**
1. **Test:** `op::agent::tests::materializes_spec_and_env` — a resolved
   agent yields an `Invocation` whose env contains `MINIMAL_AGENT_SPEC`
   and the `MINIMAL_AGENT_*` set, and whose spec file round-trips to the
   descriptor.
2. **Test:** `op::agent::tests::instructions_file_is_inlined` — a
   `{ file = ... }` instruction is read and inlined into the spec.
3. **CLI:** `minimal agent run reviewer` with a stub runtime that prints
   `$MINIMAL_AGENT_SPEC` contents shows the normalized descriptor —
   proving harness-neutral hand-off end to end.

---

### Unit 3: Subagent fork/spawn control surface

**Purpose:** Let a running agent fork subagents (named or ad-hoc) into a
shared or fresh sandbox, over the existing in-sandbox → daemon relay,
gated by the parent's `subagents` policy.

**Depends on:** Unit 2

**Affected areas:**
- `crates/minimald/src/env.rs` — a `SpawnAgent` verb on the env socket
  (`/run/minenv_sock`), beside `run_task` (`env.rs:841`)
- `crates/minimald-rpc/src/lib.rs` and/or the in-sandbox `min` helper —
  the `min agent spawn` client verb
- `crates/minimald/src/session.rs`, `sessions.rs` — spawn into the
  parent's live session (shared) vs. mint an isolated sandbox one-shot
  (fresh)

**Baseline:**
- The in-sandbox `min` helper relays to the daemon over
  `/run/minenv_sock` (`sandbox2/src/lib.rs:267`, `session_host.rs`);
  `run_task` is the only env-socket execution verb today.
- No parent/child agent registry exists.

**Functional Requirements:**

- **R3.1**: The in-sandbox client shall provide
  `min agent spawn <name> [--sandbox shared|fresh] [--mode
  prompt|interactive] [-- <args…>]`, relayed to a daemon `SpawnAgent`
  handler. `<name>` resolves against `[agents.<name>]`; `--sandbox`/
  `--mode` override the named agent's `subagents` defaults for that
  spawn.
- **R3.2**: Ad-hoc spawns (`min agent spawn --exec <cmd> …`, no named
  definition) shall be admitted only when the parent agent's
  `subagents.allow` contains `"*"`; a named spawn is admitted only when
  `allow` contains that name or `"*"`. A disallowed spawn fails with an
  actionable error and is not executed.
- **R3.3**: `--sandbox shared` shall run the subagent in the parent's
  live sandbox (shared filesystem/env — the session-host path);
  `--sandbox fresh` shall run it in a newly built, isolated sandbox
  (the task/`Exec` one-shot model, `sandbox2::run`). Both honour the
  subagent definition's own `packages`/`vars`/`patch`.
- **R3.4**: The daemon shall track spawned subagents in a
  parent-keyed registry so they can be listed
  (`min agent list`) and are cleaned up (killed) when the parent exits —
  respecting the fork/PDEATHSIG thread-affinity constraint
  (`sandbox2/src/lib.rs:823-850`): sandbox launches are never driven
  from a `spawn_blocking`/`block_in_place` thread.

**Proof Artifacts:**
1. **Test:** `minimald::agent::tests::disallowed_spawn_is_rejected` and
   `wildcard_allows_adhoc` — the `subagents.allow` gate.
2. **Test:** `minimald::agent::tests::fresh_scope_uses_isolated_sandbox`
   (mock launcher) — a fresh spawn does not share the parent's working
   tree.
3. **CLI:** from inside a running agent, `min agent spawn explorer
   --sandbox shared --mode prompt -- "find TODOs"` returns the
   subagent's captured output; `min agent list` shows it under the
   parent.

---

### Unit 4: Interactive spawn path

**Purpose:** Give spawns a real interactive terminal when requested,
closing the interactive-execution gap for the agent path.

**Depends on:** Unit 3

**Affected areas:**
- `crates/minimald/src/session_host.rs` — PTY wiring for an interactive
  spawn (reusing `Pty::open`/`SandboxLauncher`)
- `crates/minimald/src/exec.rs`, `connection.rs` — route
  `--mode interactive` through the PTY seam rather than the piped
  `exec` seam
- `crates/minimald/src/env.rs`, `crates/mctx/src/env.rs` — the
  interactive-task rejection is scoped so it no longer blocks the agent
  spawn path

**Baseline:**
- Interactive execution exists only via `shell_request` + `Pty::open` +
  slave-wired stdio (`session.rs:687`, `session_host.rs`); `exec` is
  no-PTY (`exec.rs:773`); task runners reject `interactive`
  (`env.rs:887`, `mctx/env.rs:373`).

**Functional Requirements:**

- **R4.1**: A `--mode interactive` spawn shall open a PTY and wire the
  subagent process's stdio to the slave side (reusing the
  `SandboxLauncher`/`Pty` path in `session_host.rs`), so a TUI-style
  agent runtime runs correctly; a `--mode prompt` spawn shall use piped
  stdio (the `Exec` path).
- **R4.2**: The `interactive`-task rejection (`env.rs:887`,
  `mctx/env.rs:373`) shall be scoped so it continues to reject
  interactive *tasks* while permitting interactive *agent spawns* routed
  through R4.1 — no regression to existing task behaviour.
- **R4.3**: An interactive `--sandbox shared` spawn shall attach to the
  parent session's host; an interactive `--sandbox fresh` spawn shall
  mint a fresh PTY-backed session-host. Window-resize events shall be
  propagated (reusing `WinSize`/`set_size`, `session_host.rs`).

**Proof Artifacts:**
1. **Test:** `session_host::tests::interactive_spawn_wires_pty`
   (MockLauncher) — an interactive spawn allocates a PTY and wires
   stdio to the slave, mirroring the existing session-host PTY test.
2. **Test:** `minimald::agent::tests::interactive_task_still_rejected` —
   R4.2 regression guard: a plain `interactive = true` task is still
   refused by the task runner.
3. **CLI:** `min agent spawn shell-agent --mode interactive` yields a
   working interactive terminal inside the subagent; resizing the
   client terminal resizes the subagent PTY.

---

## Non-Goals

- **Concrete per-harness adapters.** This spec defines the
  `MINIMAL_AGENT_*`/`MINIMAL_AGENT_SPEC` convention; shipping adapters
  for Claude Code, aider, codex, etc. (and a supported-harness matrix)
  is separate work.
- **Model routing, provider auth, billing, or token accounting.**
  `model` is an opaque string handed to the adapter.
- **Agent conversation/transcript persistence** and replay.
- **Remote / cross-host agents and agent-to-agent messaging (teams).**
  Subagents here are local forks under one parent; a message bus is out
  of scope.
- **Enforcing the tool allow/deny policy inside the runtime.** minimal
  passes `tools` through as descriptor data; only the adapter/runtime
  can enforce it (see Security Considerations).
- **Changing task or session behaviour.** Agents are additive; the
  interactive-task gap is closed only for the agent spawn path.

## Design Considerations

- **Agent = Task's execution surface + a generic descriptor + a fork
  policy.** Reusing `TaskAction`, `StrOrList`, `EnvPatches`, and
  `EnvVarValue` (all already `pub` in `mfile`) keeps one action grammar
  and one sandbox-env plumbing path, rather than a parallel executor.
- **Harness-agnosticism lives in the materialization boundary, not the
  schema alone.** The schema is generic by construction (no
  harness-named fields/values); the `MINIMAL_AGENT_*` + spec-file
  convention is the single, documented contract an adapter binds to. A
  new harness is "a launch command + a ~10-line adapter", never an mfile
  change.
- **`[agents.<name>]` is a map, like `[tasks.<name>]`**, not a singleton
  like `[session]`: there are many named agents, and named subagents are
  simply other entries in the same map referenced via
  `subagents.allow`.
- **Two fork scopes map onto two existing runtime seams.** "shared" is
  the PTY session-host; "fresh" is the `sandbox2::run` one-shot. No new
  isolation primitive is introduced.
- **Drop the Claude-specific fields.** `hooks`, `memory`, `color`,
  `effort`, `permissionMode`, and the `sonnet`/`opus`/`haiku` model
  aliases are Claude-Code concepts; `mcp` and `skills` are kept because
  they are cross-harness (MCP is an open protocol; "skills" generalises
  to named instruction/capability bundles the adapter loads).

## Repository Standards

- `mfile` is a library crate: typed errors via `thiserror`,
  `#[non_exhaustive]` on any public enum that may grow (`McpServer`,
  `SandboxScope`, `Interactivity`), `#[serde(default)]` + flattened
  `extra` on every section, `#[must_use]` on `is_empty`.
- `AgentName` and any trivially-invariant descriptor value use `nutype`
  for the validating constructor (non-empty, `[a-z0-9-]`), matching the
  `StrictVarName`/newtype precedent in `sessions`.
- Application/daemon layers (`minimald`, `mip`) use `anyhow` with
  `.context`; user-facing CLI output stays on the color-eyre path.
- Structured `tracing` (no `println!` outside CLI output); requirement
  IDs anchored in code/tests as `// R{n}.{m}` comments.

## Open Questions

- **Spec-file format and version key.** JSON is proposed for the
  normalized descriptor; should it carry a `schema_version` so adapters
  can evolve independently? (Leaning yes.)
- **`mcp`/`skills` validation.** Does minimal validate MCP server
  references and skill names, or pass them through opaquely for the
  adapter to resolve? Opaque pass-through is simpler and more
  harness-neutral; validation catches typos earlier.
- **Fresh-subagent identity.** Does a `--sandbox fresh` spawn get its
  own persisted session `Record` (visible to `minimal ls`), or a
  lighter ephemeral handle tracked only in the parent registry?
- **List-valued env encoding.** Newline-delimited vs JSON for
  `MINIMAL_AGENT_TOOLS_ALLOW`/`MCP`/`SKILLS` — pick one and document it;
  the spec file avoids the ambiguity, the env vars reintroduce it.
- **Depth/fan-out limits.** Should there be a default cap on subagent
  depth or count to bound runaway forking, configurable on the parent?

## Technical Considerations

- **Fork/PDEATHSIG thread affinity.** `sandbox2` forks in-process and
  arms `PR_SET_PDEATHSIG` tied to the forking thread
  (`sandbox2/src/lib.rs:823-850`); a subagent-spawning design that runs
  many launches concurrently must never drive a sandbox from a
  `spawn_blocking`/`block_in_place` pool thread, or the container dies
  with a spurious SIGKILL.
- **Interactive path is genuine greenfield.** No code today runs an
  `interactive` unit through the task runner; Unit 4 wires the PTY
  session-host into the spawn path and must scope the existing rejection
  rather than removing it.
- **Nested sandboxes are already supported** (`locked_mount_flags`,
  `sandbox2/src/lib.rs:1177`), so a fresh subagent launched from within
  a sandboxed parent is a considered case, not a new capability.

## Security Considerations

- **`tools` allow/deny is advisory at the minimal layer.** minimal
  cannot enforce which tools an opaque runtime uses; it only materializes
  the policy for the adapter/runtime to honour. This must be documented
  so operators don't treat it as a sandbox boundary — the real isolation
  boundary is the sandbox scope (fresh vs shared), not the tool list.
- **`--sandbox fresh` is the isolation control.** Untrusted or
  destructive subagent steps should run `fresh` so they cannot mutate
  the parent's working tree; `shared` deliberately grants full access to
  the parent's filesystem and env, including any secrets in `vars`.
- **Spec file + env carry instructions/secrets.** The normalized spec
  file lives in the sandbox `TMPDIR` and inherits its lifetime and
  permissions; `vars` may carry inherited secrets into a subagent —
  `fresh` scope plus explicit `vars` is the way to withhold them.
- **Spawn admission is policy-gated.** A running agent can only spawn
  what its `subagents.allow` permits (named entries, or `"*"` for
  ad-hoc); the daemon enforces this at the `SpawnAgent` handler, not the
  in-sandbox client.

## Verification

| Req | Proof type | Command / observable |
|-----|------------|----------------------|
| R1.1/R1.2 | Test | `cargo test -p mfile agents::tests::populated_block_parses_every_field` |
| R1.3 | Test | `cargo test -p mfile mfile::tests::warn_unknown_fields_covers_agents` |
| R1.4 | Test | `cargo test -p mfile agents::tests::defaults_are_shared_prompt` + `instructions_file_rejects_absolute_path` |
| R2.1/R2.2 | Test | `cargo test -p op op::agent::tests::materializes_spec_and_env` |
| R2.2 | Test | `cargo test -p op op::agent::tests::instructions_file_is_inlined` |
| R2.3/R2.4 | CLI | `minimal agent run reviewer` with a stub runtime prints `$MINIMAL_AGENT_SPEC` — a harness-neutral normalized descriptor |
| R3.1/R3.2 | Test | `cargo test -p minimald minimald::agent::tests::{disallowed_spawn_is_rejected,wildcard_allows_adhoc}` |
| R3.3 | Test | `cargo test -p minimald minimald::agent::tests::fresh_scope_uses_isolated_sandbox` |
| R3.4 | CLI | inside a running agent: `min agent spawn explorer --sandbox shared -- "find TODOs"` then `min agent list` shows the child |
| R4.1/R4.3 | Test | `cargo test -p minimald session_host::tests::interactive_spawn_wires_pty` |
| R4.2 | Test | `cargo test -p minimald minimald::agent::tests::interactive_task_still_rejected` |
| R4.1 | CLI | `min agent spawn shell-agent --mode interactive` yields a working PTY; resizing the client resizes the subagent |
