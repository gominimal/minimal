---
id: spec-github-sessions
title: "GitHub-integrated minimald sessions — daemon-held auth, mediated repo access, PR on exit"
kind: prd
status: planned
supersedes:
---

# PRD — GitHub-integrated minimald sessions

## Context

`minimald` hosts isolated development **sessions**: a client (`min`) talks to the daemon
over SSH-on-a-Unix-socket, and each session owns a workspace directory that a user (or an
agent such as Claude) attaches into for interactive work. Today a session is seeded either
by a one-shot **tarball copy-up** of the client's directory or by a host→session
`git push min://<session>` bridge. Neither path talks to GitHub: there is no GitHub API
client, no credential store, no notion of which GitHub user a session belongs to, and no
end-of-session action. Any GitHub work today is entirely manual — a token is injected by
hand and `git`/`gh` are run inside the sandbox.

This makes the most common developer loop — *start work on a branch, commit, push, open a
PR* — awkward, and it forces a live credential into the sandbox. This PRD defines the
**user requirements** for first-class GitHub support so that branch-based development in a
session is as easy as it is on a laptop, **without any GitHub token ever entering the
sandbox**.

### Security model (the load-bearing decision)

**`minimald` is the GitHub App client.** It runs the OAuth **device flow**, holds the
resulting user token in the daemon, and is the only component that ever touches it.

**The token never enters the sandbox.** Git operations and GitHub API calls made from
inside a session are proxied back to `minimald` over the existing trusted transport (a
`min git` facade, and the same facade for GitHub MCP). `minimald` performs the
authenticated operation on the token's behalf and returns the result. The agent gets
**scoped repo access without ever holding the credential.**

**Access dies with the sandbox.** Because access is mediated by a live RPC channel to
`minimald`, when the sandbox exits its ability to reach GitHub ends with it — there is no
lingering token on disk to leak or reuse. This is deliberately preferred over injecting a
short-lived token, and over a man-in-the-middle **egress proxy** that would intercept git
traffic to splice in credentials: the facade is an explicit, auditable request surface
rather than transparent interception, and it binds access to the sandbox lifetime.

The design is grounded in what a **public GitHub App** grants (see
[Authentication model](#authentication-model)): a user-to-server token obtained through
the device flow, attributing work to the **real user**, scoped to the repositories and
permissions the task needs.

## Goals

- **G1 — Branch-ready on activate.** Activating a session pre-primes one or more repos and
  puts each on the requested branch (checked out if it exists, else created from a base),
  so the workspace is a ready git repo the moment the user attaches.
- **G2 — Push during a session.** A user or agent can explicitly push commits at any time
  through the mediated facade, attributed to the real user.
- **G3 — PR on exit (opt-in).** At the end of work the user is prompted to open a pull
  request, and can accept or decline.
- **G4 — Real-user attribution.** Commits and PRs are authored by the actual user and
  appear in GitHub audit logs as that user.
- **G5 — No credential in the sandbox.** The token lives only in `minimald`; the sandbox
  reaches GitHub exclusively through the mediated facade, and that access ends when the
  sandbox exits.
- **G6 — Least privilege with consent.** Access is scoped to the declared repos and a
  minimal permission set; the requested scopes are always shown to the user; the task spec
  may narrow them further.
- **G7 — Grounded & incremental.** Every requirement maps to an existing extension seam
  in the codebase (notably the `git push min://` bridge as prior art for the facade);
  nothing depends on capabilities GitHub does not offer.

## Non-goals

- **NG1** — User-*selectable* fine-grained scope control at launch. We **show** the
  requested scopes (the OAuth obligation), but a per-scope toggle UI is not shipping at
  launch (see [Future work](#future-work)). "Show our work, don't make it user-selectable
  out of the gates."
- **NG2** — Multi-*user* / multi-tenant operation inside one daemon. Local is treated as a
  single **anonymous user** with prior authentications associated to it. The agreed
  scaling axis is **multiple `minimald`s per host**, not multi-tenancy within one; remote
  multi-user needs more thought.
- **NG3** — Bot/app-attributed automation identity. Attribution is the real user. (The
  installation-token, `app[bot]` path is retained only as a possible future transport
  mode.)
- **NG4** — A general merge/review workflow (approvals, required checks, auto-merge). We
  open a PR; we do not manage its lifecycle.
- **NG5** — GitHub Enterprise Server. Public GitHub.com only for the MVP.
- **NG6** — `workflows` scope. GitHub Actions workflow permission is **explicitly
  excluded** from the default and is not requested at launch.
- **NG7** — Replacing the existing tarball / `git push min://` seeding paths; GitHub
  support is additive.

## Personas

- **Solo developer (primary).** Runs `min` on their own machine, works on their own or
  their org's repos, wants the laptop git loop inside a session without ever handling a
  token.
- **Agent-in-session (Claude).** An automated coding agent running inside a session that
  is told `min git` exists and uses it to push/pull and to reach the GitHub API — with no
  credential in its environment.

## User stories

- **US1** — *As a developer, I declare `owner/repo@feat/x` (and optionally more repos) in
  my task spec; when I attach, each is cloned and on the right branch (created from `main`
  if absent).*
- **US2** — *As a developer already in a local checkout, I activate from it and its
  `origin` is wired so I can push/PR as me, without pasting a token.*
- **US3** — *As an agent, I run `min git push` / `min git pull`; the operation succeeds and
  is attributed to the user, and I never see a token.*
- **US4** — *As a developer, when I finish I'm asked whether to open a PR from my branch
  into its base; if I accept, the PR is created and authored by me.*
- **US5** — *As a security-conscious user, no GitHub credential ever lands in my sandbox,
  and when the sandbox exits its GitHub access is gone.*
- **US6** — *As a security-conscious user creating a second sandbox, I'm asked whether to
  reuse my existing authentication or mint a fresh, separately-scoped one.*
- **US7** — *As a developer, at launch I can see exactly which repositories and permissions
  are being requested before I approve.*

## Current state (grounding)

| Capability | Today | Reference |
|---|---|---|
| Session activate | `min activate` = `CreateSession` → `ConfigureLoadout` [→ `SubmitVerdict`] → tarball upload; **no git/branch/repo flags** | `crates/minimal/src/lib.rs:943,239` |
| git-over-our-transport (prior art for the facade) | `git push min://<session>` bridges git's pack protocol over the RPC/SSH transport into a session (`git-receive-pack`) | `crates/minimal/src/git_remote.rs`, `crates/minimald/src/exec.rs:746` |
| GitHub API / PR | **None** anywhere | — |
| git CLI on the daemon host | Yes (used for package sources) | `crates/checkouts/src/repo.rs` |
| Credential injection | **Deferred** — `class='Credential` file mappings are dropped; only env-var inherit works | `crates/mfile/src/package_composable.rs:26`, `crates/graph/src/env_setup.rs:132` |
| Daemon egress to github.com | Reachable (HostNet default); egress policy gating exists | `crates/sessions/src/lib.rs:20`, `crates/minimald/src/net/policy.rs` |
| Identity / user auth | **None** — `username` is an unauthenticated label over trusted local transport | `crates/minimald/src/connection.rs:271` |
| Task spec / session config | Free-form `attrs` on `SessionConfig`/`Record`; project `minimal.toml` `[session]` block | `crates/minimald-rpc/src/lib.rs:206`, `crates/mfile/src/lib.rs:374` |
| CLI extension points | `Session` subcommand group; client `config.toml` | `crates/minimal/src/lib.rs:117`, `crates/sessions/src/client/config.rs` |
| Hosted providers | Named as placeholders (`MinHosted`/`MinCloud`) | `docs/session-domain-diag.md` |

**Implication:** greenfield, but the transport already exists. The `git push min://` bridge
proves that git's pack protocol can be tunnelled over `minimald`'s RPC channel; the `min
git` facade is the inverse direction (sandbox → daemon → GitHub) of the same idea. The MVP
adds (a) a device-flow auth client **in `minimald`** with a token store; (b) the `min git`
facade + GitHub-MCP proxy; (c) multi-repo pre-priming from the task spec; (d) scope
resolution/consent; and (e) a client-driven PR-on-exit prompt. It must **unblock the
deferred secrets path** — but only inside the daemon, never into the sandbox.

## Authentication model

**A GitHub App** (not an OAuth App) named e.g. "minimal", **installed** on the user's
account or org — installation is what grants private-repo access and lets access be scoped
to specific repositories.

**`minimald` is the OAuth client.** It runs the **device flow** (the `min` CLI is only the
surface that shows the verification URL + `user_code`); the user approves in a browser; and
`minimald` receives and stores a **user access token** (~8h) plus a rotating **refresh
token** (~6mo), associated with the local anonymous user. `minimald` refreshes
transparently, so long sessions keep working. Because it is a user-to-server token, every
operation `minimald` performs with it is attributed to the **real user** (G4).

**Mediated access, no token in the sandbox.** The sandbox never receives the token.
Instead:

- **`min git`** — a facade available inside the session that proxies git operations
  (`push`, `pull`, `fetch`, `clone`, …) back to `minimald` over the trusted transport;
  `minimald` runs the real, authenticated operation against GitHub and streams the result
  back. Agents are told `min git` exists and use it in place of raw `git`.
- **GitHub MCP** — GitHub API access (issues, PRs, reviews) uses the **same facade**: the
  MCP calls route through `minimald`, which holds the token and enforces scope.

This means the sandbox does **not** need direct `github.com` egress for GitHub work; only
`minimald` does. Access is bound to the live facade channel and ends when the sandbox exits
(G5).

**Scopes (least privilege + consent).**

| Permission | Default | Notes |
|---|---|---|
| `contents` | **read/write** | clone, fetch, push, branches, commits |
| `pull_requests` | **read/write** | open/update PRs |
| `issues` | **read/write** | standard dev work (via GitHub MCP) |
| `metadata` | read | mandatory baseline |
| `workflows` | **excluded** | not requested at launch (NG6) |

- **Decision rule.** If the **task spec declares explicit required scopes** (optionally
  per repo), use them. Otherwise fall back to the **defaults above and prompt the user at
  launch** to approve.
- **Show, don't (yet) select.** The requested scopes are always **displayed** to the user
  before approval (the OAuth obligation to show requested access). A per-scope toggle UI is
  deferred (NG1).
- **Reuse-or-mint.** On creating a **subsequent** sandbox, prompt the user to either
  **reuse** the existing authentication or **mint a fresh** token — keeping per-sandbox
  scoping possible for the security-conscious.

**Transport.** When `minimald` talks to GitHub it uses the token as the HTTP password:
`https://x-access-token:<token>@github.com/<owner>/<repo>.git`. PR creation is
`POST /repos/{owner}/{repo}/pulls`, run by `minimald` with the user token so the PR is
authored by the user.

**Why not an egress proxy.** A MITM egress proxy could splice credentials into git traffic
transparently, but that hides access behind interception and still exposes authenticated
egress to sandbox code. The `min git` facade is an explicit, auditable request surface,
keeps the token entirely in the daemon, and ties access to the sandbox lifetime.

## Requirements

Requirement IDs (`Rx.y`) are stable once this spec is approved; this is a pre-approval
revision, so IDs are still being settled.

### R1 — Authentication & identity (daemon-held)

- **R1.1** `minimald` MUST authenticate to GitHub via the GitHub App **device flow**, and
  MUST store the resulting user + refresh tokens **in the daemon** (never in a
  workspace/sandbox). The `min` CLI MUST surface the verification URL and `user_code`.
- **R1.2** `minimald` MUST refresh the user access token transparently for the life of any
  session using it; an expired refresh token MUST trigger re-auth rather than silent
  failure.
- **R1.3** Tokens MUST be associated with the local **anonymous user** (NG2). Prior
  authentications MUST be reusable across sandboxes (subject to R6.4 reuse-or-mint).
- **R1.4** A first-class command surface MUST exist to sign in and inspect status (e.g.
  `min github login` / `min github status`), reporting the authenticated login, token
  validity, and whether the App is installed on each target repo.
- **R1.5** If the App is **not installed** on a target repo/org, the flow MUST detect this
  and guide the user to the installation URL rather than failing opaquely.

### R2 — Repo pre-priming & branch-aware activation

- **R2.1** The **task spec** MUST support a repo pre-priming field listing **one or more**
  repositories to prepare in the session (monorepo splits or multi-repo working sets, e.g.
  `min-vm-mac` + shim + `minimal`).
- **R2.2** For each repo, activation MUST accept a working branch and an optional base
  branch (default = repo default branch), and MUST prepare it **checkout-or-create**:
  check out `branch` if it exists on the remote, else create it from the base. When the
  user attaches, each repo is already on its branch with a working `origin` (G1).
- **R2.3** **Server-side clone mode:** given `owner/repo@branch`, `minimald` clones the
  repo into the workspace using the daemon-held token.
- **R2.4** **Adopt-local mode:** when activating from an existing local checkout (the
  tarball path), the session MUST wire `origin` to route through the facade and reconcile
  the branch (checkout-or-create, defaulting to the checkout's current branch). Existing
  tarball / `git push min://` seeding MUST keep working when no GitHub target is given
  (NG7).
- **R2.5** Branch creation MUST NOT push implicitly; a new branch exists only in the
  workspace until an explicit push (R3).
- **R2.6** Activation MUST fail cleanly and actionably (repo inaccessible, missing scope,
  base branch absent, App not installed) without leaving a half-primed workspace.
- **R2.7** Cloning MUST reuse the existing git-CLI wrapper pattern (`crates/checkouts`) and
  the established activate RPC sequence.

### R3 — Mediated repo access (`min git` + MCP)

- **R3.1** A **`min git`** facade MUST be available inside the session that proxies git
  operations (`push`, `pull`, `fetch`, `clone`, `remote`, …) to `minimald`, which performs
  the authenticated operation. **No GitHub token may enter the sandbox** (G5).
- **R3.2** The session MUST advertise `min git` to agents (e.g. surfaced in the agent's
  in-sandbox instructions) so Claude uses it in place of raw `git`.
- **R3.3** GitHub **MCP** access MUST use the same facade — API calls route through
  `minimald`, which holds the token and enforces scope — so issues/PR/review tooling works
  without a credential in the sandbox.
- **R3.4** A **first-class explicit push** action MUST exist (`min git push` and/or a
  `min session push` convenience). Pushing MUST be explicit; the system MUST NOT auto-push.
- **R3.5** Mediated access MUST be **bound to the sandbox lifetime**: when the sandbox
  exits, its facade channel and thus its GitHub access MUST end (G5).
- **R3.6** `minimald` (not the sandbox) MUST have egress to `github.com`. The sandbox MUST
  NOT require direct `github.com` egress for facade-mediated GitHub operations.

### R4 — Pull request on exit

- **R4.1** At end of work, the user MUST be **prompted** whether to open a PR for a session
  branch into its base; no PR is created without confirmation (G3).
- **R4.2** Because attach-shell exit is not observed by the daemon today, the prompt MUST
  be **client-driven** — on `min attach` shell exit and/or an explicit teardown command
  (e.g. `min session finish` / enhanced `min destroy`).
- **R4.3** On confirmation, the branch MUST be pushed (via the facade) and the PR created
  by `minimald` using the daemon-held user token, so the PR is authored by the user (G4).
- **R4.4** The PR body SHOULD pre-populate from the repo's PR template if present; base
  defaults to the branch's base; draft-vs-ready is an open question (OQ2).
- **R4.5** If a PR already exists for the branch, the flow MUST detect and surface/update
  it rather than duplicating.
- **R4.6** Declining MUST leave the pushed branch intact and MUST NOT block teardown. In a
  multi-repo session, the prompt MUST cover each repo with unpushed/PR-able work.

### R5 — Scopes & least privilege

- **R5.1** The default scope set MUST be `contents:rw`, `pull_requests:rw`, `issues:rw`,
  `metadata:read`; `workflows` MUST be excluded (NG6).
- **R5.2** If the task spec declares explicit required scopes (optionally per repo), the
  system MUST use them; otherwise it MUST apply the defaults and **prompt at launch**.
- **R5.3** The requested scopes (and repos) MUST be **displayed** to the user before
  approval. A per-scope selection UI is out of scope for launch (NG1).
- **R5.4** Token scope MUST be bounded to the declared repositories (least repo) and the
  resolved permission set (least privilege).

### R6 — Token lifecycle & security

- **R6.1** The token MUST live only in `minimald`; it MUST NOT be written into the
  workspace, the sandbox environment, the session tarball, or any sandbox-visible file.
- **R6.2** Tokens MUST be short-lived and refreshable (R1.2), and MUST be **redacted** from
  logs and diagnostic bundles (extend the existing redaction denylist).
- **R6.3** On sandbox exit/destroy, the facade channel MUST close so mediated access ends;
  no credential material may persist in the workspace (R3.5).
- **R6.4** **Reuse-or-mint:** creating a subsequent sandbox MUST prompt to reuse the
  existing authentication or mint a fresh, separately-scoped token, preserving per-sandbox
  scoping.

### R7 — Configuration, task spec & CLI surface

- **R7.1** Repo pre-priming and optional per-repo scopes MUST be expressible in the **task
  spec** (project `minimal.toml` `[session]` and/or the activation request); carried first
  via `SessionConfig.attrs` and promotable to typed fields, with new persisted fields
  `#[serde(default)]` for back-compat.
- **R7.2** New commands SHOULD live under the existing `Session` group (`min session
  push`/`pr`) plus a small `github` group (`min github login`/`status`); `min git` is the
  in-sandbox facade.

### R8 — Observability & errors

- **R8.1** Auth, clone/branch, facade, push, and PR steps MUST emit structured `tracing`
  spans and actionable, non-secret errors (e.g. "App not installed on owner/repo", "scope
  contents:write not granted", "base branch main not found").
- **R8.2** `min github status` MUST let a user self-diagnose: identity, token validity, App
  installation state, and each session repo's target/branch/scope.

## UX flows

**First-time auth (device flow owned by `minimald`):**

```
min github login
# → minimald starts the device flow; min shows:
#     "Open https://github.com/login/device and enter code ABCD-1234"
# → user approves in browser; minimald stores the token (local anonymous user)
```

**Activate with pre-primed repos + scope consent:**

```
# task spec lists repos (and optionally per-repo scopes)
min activate --attach
# → if the spec declares scopes: used directly
#   else: "This session will request  repos: owner/api@feat/x, owner/web@feat/x
#          scopes: contents:rw, pull_requests:rw, issues:rw  [approve? y/N]"
# → (subsequent sandbox) "Reuse existing GitHub auth, or mint a fresh one? [reuse/mint]"
# → each repo cloned and on its branch; user attaches
```

**Work & push (no token in sandbox):**

```
# inside the session (human or agent)
git commit -am "…"
min git push                 # proxied to minimald; attributed to the user
```

**Exit → PR:**

```
exit
# → "Open a PR for owner/api feat/x → main? [y/N]"
#    on y: facade pushes, minimald creates the PR authored by the user
```

## Technical grounding & integration seams

- **Auth in `minimald`:** device-flow + token-refresh + token store in the daemon; unblock
  the deferred secrets path (`crates/mfile/src/package_composable.rs:26`,
  `crates/graph/src/env_setup.rs:132`) **daemon-side only**, never into the sandbox.
- **`min git` facade:** model on the existing git-over-transport bridge
  (`crates/minimal/src/git_remote.rs`, `crates/minimald/src/exec.rs:746`) — the inverse
  direction (sandbox → daemon → GitHub). Reuse the `crates/checkouts` git-CLI wrapper for
  the daemon-side operations.
- **Pre-priming & activation:** extend `ActivateArgs` (`crates/minimal/src/lib.rs:239`) and
  the `CreateSession`/`ConfigureLoadout` sequence; carry repos/scopes via
  `SessionConfig.attrs` (`crates/minimald-rpc/src/lib.rs:206`).
- **Scope consent / reuse-or-mint:** client-side prompts in the activate flow
  (`crates/minimal/src/lib.rs:943`), driven by resolved scopes from the task spec.
- **PR on exit:** client-driven prompt around `min attach`/`min destroy`
  (`crates/minimal/src/lib.rs:1109,1322`); the API call is made by `minimald` with the
  token. (A future headless path could implement the deferred `on_destroy` lifecycle-hook
  executor — `crates/sessions/src/core/lifecyclehook.rs`,
  `crates/minimald/src/session_host.rs:245`.)
- **Egress:** `minimald` needs `github.com` egress (`crates/minimald/src/net/policy.rs`);
  the sandbox does not, for mediated operations.

## Future work

- **FW1** Remote / multi-user auth (NG2) — associating tokens beyond the local anonymous
  user; the agreed scaling axis is **multiple `minimald`s per host**, not multi-tenancy
  within one. `MinHosted`/`MinCloud` in `docs/session-domain-diag.md` are the anchor; in a
  hosted model the same device grant is driven from the hosted side (`user_code` shown in
  the session/web UI).
- **FW2** User-selectable fine-grained scope control at launch (NG1).
- **FW3** Dynamic per-task-launch scope requests (see OQ1 — an active POC).
- **FW4** Headless PR-on-exit via the deferred `on_destroy` lifecycle-hook executor.
- **FW5** GitHub Enterprise Server (NG5).
- **FW6** Optional bot/installation-token transport mode for automation identities (NG3).

## Open questions

- **OQ1** Whether scopes can be **dynamically requested per task launch** (POC in
  progress), rather than fixed at first auth.
- **OQ2** How to **present the scope list back through the `min` client** — the exact
  consent UX (and draft-vs-ready default for PRs).
- **OQ3** Reuse-or-mint default and granularity (per-repo vs per-session).

## Appendix — GitHub token reference

| Property | User-to-server (chosen) | Installation (future/alt) |
|---|---|---|
| Client / holder | **`minimald`** (device flow) | `minimald`/backend (App JWT) |
| Obtain | OAuth **device flow** | `POST /app/installations/{id}/access_tokens` |
| Lifetime | ~8h token + rotating ~6mo refresh token | ~1h, not refreshable (re-mint) |
| Attribution | **Real user** | `app[bot]` |
| Repo scoping | user access ∩ App install ∩ declared repos | `repositories`/`repository_ids` at mint |
| In sandbox? | **Never** — mediated via `min git` / MCP facade | Never |
| Default scopes | `contents:rw`, `pull_requests:rw`, `issues:rw`, `metadata:read`; **no `workflows`** | same policy |

### Sources

- Generating an installation access token for a GitHub App — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app>
- Create an installation access token for an app (REST) — <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>
- Authenticating as a GitHub App installation — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation>
- Generating a user access token for a GitHub App — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app>
- Authenticating on behalf of a user (device flow / attribution) — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user>
- Device flow — <https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-a-cli-with-a-github-app>
- Refreshing user access tokens — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens>
- Choosing permissions for a GitHub App — <https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app>
