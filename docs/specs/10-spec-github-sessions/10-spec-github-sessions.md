---
id: spec-github-sessions
title: "GitHub-integrated minimald sessions — branch-ready activate, in-session push, PR on exit"
kind: prd
status: planned
supersedes:
---

# PRD — GitHub-integrated minimald sessions

## Context

`minimald` hosts isolated development **sessions**: a client (`min`) talks to the
daemon over SSH-on-a-Unix-socket, and each session owns a workspace directory that a
user attaches into for interactive work. Today a session is seeded either by a one-shot
**tarball copy-up** of the client's directory (`min activate --sync tarball`, the
default) or by a host→session `git push min://<session>` bridge. Neither path talks to
GitHub: there is no GitHub API client, no credential store, no notion of which GitHub
user a session belongs to, and no end-of-session action. Any GitHub work today is
entirely manual — the user injects a token by hand and runs `git`/`gh` inside the
sandbox.

This makes the single most common developer loop — *start work on a branch, commit,
push, open a PR* — awkward in a session. This PRD defines the **user requirements** for
first-class GitHub support so that branch-based development in a session is as easy as it
is on a laptop, while keeping credentials short-lived and least-privilege.

The design is grounded in what a **public GitHub App** can grant (see
[Authentication model](#authentication-model)): short-lived, repo-scoped, refreshable
tokens obtained through the OAuth **device flow**, attributing work to the **real user**.

## Goals

- **G1 — Branch-ready on activate.** A user can activate a session against a branch and,
  once attached, the workspace is a real git repository already on that branch — whether
  the branch already exists on the remote or is created fresh from a base branch.
- **G2 — Push during a session.** A user can explicitly push commits from the session to
  the branch on GitHub at any time, using their own identity.
- **G3 — PR on exit (opt-in).** At the end of work the user is prompted to open a pull
  request for their branch, and can accept or decline.
- **G4 — Real-user attribution.** Commits and PRs are authored by the actual user, not a
  bot, and appear in GitHub audit logs as that user.
- **G5 — Least-privilege, short-lived credentials.** GitHub access is scoped to the one
  repository the session targets, limited to the permissions actually needed, expires
  quickly, and is never persisted in the workspace.
- **G6 — Grounded & incremental.** Every requirement maps to an existing extension seam
  in the codebase; nothing depends on capabilities GitHub does not offer.

## Non-goals

- **NG1** — Multi-repository sessions. One primary repo per session (see
  [Future work](#future-work)).
- **NG2** — Multi-tenant hosted operation (`minhosted`/`mincloud`, server-held tokens,
  session→user authorization at scale). Primary scope is today's **single-user,
  local-transport `minimald`**. Hosted operation is a documented downstream dependency.
- **NG3** — Bot/app-attributed automation identity. Attribution is the real user.
- **NG4** — A general merge/review workflow (approvals, required checks, auto-merge).
  We open a PR; we do not manage its lifecycle.
- **NG5** — Hosting or proxying arbitrary git forges. GitHub.com (public GitHub) only;
  GitHub Enterprise Server is out of scope for the MVP.
- **NG6** — Replacing the existing tarball / `git push min://` seeding paths; GitHub
  support is additive.

## Personas

- **Solo developer (primary).** Runs `min` on their own machine, works on their own or
  their org's repos, wants the laptop git loop inside a session without hand-managing
  tokens.
- **Agent-in-session.** An automated coding agent (e.g. Claude) running inside a session
  that needs the same credential to `git push` and open a PR on the user's behalf.

## User stories

- **US1** — *As a developer, I activate a session against `owner/repo` on branch
  `feat/x`; when I attach, the workspace is already cloned and checked out to `feat/x`
  (created from `main` if it didn't exist), with an authenticated `origin`.*
- **US2** — *As a developer already in a local checkout, I activate a session from it and
  the session's `origin` is wired to authenticate as me so I can push and open PRs
  without pasting a token.*
- **US3** — *As a developer, while working in a session I run one command to push my
  branch to GitHub, and the push is attributed to me.*
- **US4** — *As a developer, when I finish a session I'm asked whether to open a PR from
  my branch into its base; if I accept, the PR is created and authored by me.*
- **US5** — *As a security-conscious user, the GitHub token in my session is limited to
  the one repo, expires within hours, refreshes transparently for long sessions, and is
  never written into my project files.*
- **US6** — *As an agent running in a session, I can use the same credential helper as a
  human to push and open PRs, with no token embedded in the repo.*

## Current state (grounding)

| Capability | Today | Reference |
|---|---|---|
| Session activate | `min activate` = `CreateSession` → `ConfigureLoadout` [→ `SubmitVerdict`] → tarball upload; **no git/branch/repo flags** | `crates/minimal/src/lib.rs:943,239` |
| Seed workspace | Tarball copy-up (one-shot) or `git push min://<session>` (host→session) | `crates/minimal/src/file_upload.rs`, `crates/minimal/src/git_remote.rs`, `crates/minimald/src/exec.rs:746` |
| GitHub API / PR | **None** anywhere | — |
| git CLI available on host | Yes (used for package sources) | `crates/checkouts/src/repo.rs` |
| Credential injection | **Deferred** — `class='Credential` file mappings are dropped; only env-var inherit works | `crates/mfile/src/package_composable.rs:26`, `crates/graph/src/env_setup.rs:132` |
| Network egress to github.com | Reachable by default (HostNet); policy gating exists (allow-all default) | `crates/sessions/src/lib.rs:20`, `crates/minimald/src/net/policy.rs` |
| Identity / user auth | **None** — `username` is an unauthenticated label over trusted local transport | `crates/minimald/src/connection.rs:271` |
| Lifecycle hooks | Schema exists (`on_activate`/`on_destroy`/`on_failure`); **execution deferred** (logged only) | `crates/sessions/src/core/lifecyclehook.rs`, `crates/minimald/src/session_host.rs:245` |
| Extension seams | `SessionConfig.attrs`, client `config.toml`, `Session` CLI subcommand group, `MinHosted`/`MinCloud` placeholders | `crates/minimald-rpc/src/lib.rs:206`, `crates/sessions/src/client/config.rs`, `docs/session-domain-diag.md` |

**Implication:** this is greenfield. The MVP introduces (a) a GitHub App + device-flow
auth client on the `min` side, (b) a git credential mechanism that injects short-lived
tokens into a session without persisting them, (c) branch-aware activation, and (d) a
client-driven PR-on-exit prompt. It must **unblock the deferred secrets path** for
credential injection.

## Authentication model

Public GitHub offers exactly the primitives this PRD needs; the requirements below are
built on them.

**A GitHub App** (not an OAuth App — GitHub steers new integrations to Apps) named e.g.
"minimal". It is **installed** on a user's account or org, which is what grants access to
private repos and lets us scope to specific repositories.

**User-to-server tokens via the device flow** (headless-friendly): the `min` CLI runs the
OAuth **device flow** once, the user approves in a browser, and `min` receives a
**user access token** (default **8-hour** expiry) plus a **refresh token** (rotating,
**6-month** expiry). Requests made with this token attribute commits and PRs to the
**real user** (`GIT_AUTHOR` = user), satisfying G4. `min` refreshes transparently, so
sessions longer than 8 hours keep working.

**Roles.** There is **one registered GitHub App** ("minimal"), owned by the project. The
**`min` CLI is the device-flow client**: it uses the App's *public* `client_id` (the
device authorization grant needs no client secret or private key) to obtain a
**user-to-server** token for the human at the terminal. The **`minimald` daemon performs
no OAuth** in this single-user MVP — it receives already-minted short-lived tokens via
the in-session credential helper, and no App private key is stored anywhere.
Authenticating (device-flow *login*) is distinct from **installing** the App on a
repo/org: login proves the user's identity; installation lets that user token reach the
repo. Both are required for private repos (R1.4). `minimald`/a backend would act *as the
App* (server-to-server installation tokens minted from the private key) only in the
future hosted/bot path — NG3/FW2/FW5, not the MVP.

**Least privilege.** The App requests only the permissions the loop needs:

| Permission | Level | Why |
|---|---|---|
| `contents` | write | clone, fetch, push, create branches, commit |
| `pull_requests` | write | open/update PRs |
| `metadata` | read | mandatory baseline |
| `workflows` | write | **only** if the branch touches `.github/workflows/` (edge case; request lazily / document) |

A user-to-server token is intersected with what the user can access *and* where the App
is installed, so scope is naturally bounded to the single target repo (G5, NG1).

**Git transport.** Tokens are used as the HTTP password:
`https://x-access-token:<token>@github.com/<owner>/<repo>.git`. (The username field is a
convention; GitHub ignores it when a valid token is supplied.)

**PR creation.** `POST /repos/{owner}/{repo}/pulls` with the user token, so the PR is
authored by the user.

**Why not the alternatives** (recorded for reviewers):

- *Installation access token only* (server-to-server, 1-hour, re-minted from the App
  private key): simplest, but attributes work to `minimal[bot]` — rejected by the
  attribution decision (NG3). Retained as a possible transport-only credential for a
  future headless/hosted mode.
- *Fine-grained PAT pasted by the user*: worst UX, user-managed expiry — rejected.

## Requirements

Requirement IDs are stable (`Rx.y`); do not renumber after approval.

### R1 — Authentication & identity

- **R1.1** `min` MUST authenticate the user to GitHub via the GitHub App **device flow**,
  storing the resulting user + refresh tokens in the client's existing credential
  location (never in a repo/workspace).
- **R1.2** `min` MUST refresh the user access token using the refresh token before/at
  expiry, transparently to the session, for the duration of the session.
- **R1.3** A first-class command MUST exist to sign in and show status, under the
  existing `Session`/top-level CLI surface (e.g. `min github login` / `min github status`),
  reporting the authenticated GitHub login and whether the App is installed on the target
  repo.
- **R1.4** If the App is **not installed** on the target repo/org, `min` MUST detect this
  and guide the user to the installation URL rather than failing opaquely.
- **R1.5** A session MUST record which authenticated GitHub identity it is associated with
  (for display and for scoping the credential), carried via `SessionConfig`/`Record`
  (`attrs` initially, promotable to typed fields).

### R2 — Branch-aware activation

- **R2.1** `min activate` MUST accept a GitHub target: repository (`owner/repo`), a
  working branch, and an optional base branch (default = repo default branch).
- **R2.2** **Server-side clone mode:** given `owner/repo@branch`, the session MUST clone
  the repo into its workspace using the user's short-lived token and prepare the branch
  **checkout-or-create**: if `branch` exists on the remote, check it out; otherwise create
  it from the base branch. When the user attaches, the workspace is already on `branch`
  with an authenticated `origin` (G1, US1).
- **R2.3** **Adopt-local mode:** when activating from an existing local checkout (today's
  tarball path), the session MUST wire `origin` to authenticate as the user and reconcile
  the branch (checkout-or-create the requested branch, defaulting to the checkout's
  current branch) so the user can push/PR without pasting a token (US2). The existing
  tarball/`git push min://` seeding MUST continue to work unchanged when no GitHub target
  is given (NG6).
- **R2.4** Branch creation MUST NOT push implicitly; a newly created branch exists only in
  the workspace until an explicit push (see R3), consistent with the explicit-push model.
- **R2.5** Activation MUST fail cleanly with an actionable message when the repo is
  inaccessible, the token lacks scope, or the base branch does not exist — never leaving a
  half-prepared workspace.
- **R2.6** Reuse the existing git-CLI wrapper pattern (`crates/checkouts`) and the
  established activate RPC sequence rather than introducing a new git library or transport.

### R3 — In-session credential & push

- **R3.1** A session targeting GitHub MUST expose a git credential inside the sandbox such
  that plain `git fetch`/`git push origin` works with **no token written into the
  workspace** (G5, US5, US6).
- **R3.2** *(Recommended mechanism)* The credential SHOULD be delivered via a **git
  credential helper** in the session that fetches a **fresh short-lived token on demand**
  from `min`/the daemon over the existing trusted transport, so the token is never
  persisted to disk and is always current. Env-var injection MAY be offered as a fallback,
  with its weaker security documented.
- **R3.3** Delivering a GitHub credential into a session MUST go through the credential
  path (unblocking the deferred `class='Credential` secrets strategy), and MUST be subject
  to the existing env/patch **policy gating** (allow/deny).
- **R3.4** A first-class **explicit** push action MUST exist (e.g. `min session push`
  and/or plain `git push origin` inside the session). Pushing MUST be explicit; the system
  MUST NOT auto-push commits (G2, US3).
- **R3.5** The session MUST have network egress to `github.com` (443). Where egress policy
  is restrictive (`own-ip` allowlist), github.com MUST be allowed for GitHub-enabled
  sessions.

### R4 — Pull request on exit

- **R4.1** At end of work, the user MUST be **prompted** whether to open a PR for the
  session branch into its base; no PR is created without confirmation (G3, US4).
- **R4.2** Because attach-shell exit is not observed by the daemon and no daemon exit hook
  runs today, the prompt MUST be **client-driven** — triggered on `min attach` shell exit
  and/or an explicit teardown command (e.g. `min session finish` / enhanced `min destroy`).
- **R4.3** On confirmation, `min` MUST ensure the branch is pushed (R3) and create the PR
  via the GitHub API using the **user token**, so the PR is authored by the user (G4).
- **R4.4** The PR body SHOULD be pre-populated from the repo's PR template if present, and
  the PR MAY default to **draft**; base defaults to the branch's base (R2.1).
- **R4.5** If a PR already exists for the branch, `min` MUST detect it and offer to update
  / surface it rather than erroring or duplicating.
- **R4.6** Declining the prompt MUST leave the pushed branch intact (PR can be opened
  later); the flow MUST be non-blocking to session teardown.

### R5 — Security & token handling

- **R5.1** Tokens MUST be **short-lived** (user token ≤ 8h) and **refreshable**; expired
  refresh tokens MUST trigger re-auth (device flow) rather than silent failure.
- **R5.2** Tokens MUST be **repo-scoped** to the single target repository and requested
  with **least-privilege** permissions (see [Authentication model](#authentication-model)).
- **R5.3** Tokens MUST NOT be written into the workspace, committed, or captured in the
  session tarball; credential material MUST be excluded from any workspace sync.
- **R5.4** Tokens MUST be **redacted** from logs and diagnostic bundles (extend the
  existing redaction denylist that already knows `GITHUB_TOKEN`).
- **R5.5** On session destroy, any in-session credential material MUST be
  invalidated/removed (helper de-registered; no lingering token on disk).

### R6 — Configuration & CLI surface

- **R6.1** GitHub targets on activate SHOULD be expressible as CLI flags (e.g.
  `--repo owner/repo`, `--branch`, `--base`) and MAY be defaulted from a `[github]` section
  in the client `config.toml` and/or the project `minimal.toml` `[session]` block.
- **R6.2** New session/GitHub state SHOULD be carried first via `SessionConfig.attrs`
  (already plumbed end-to-end and persisted) and promoted to typed fields once stable;
  new persisted fields MUST be `#[serde(default)]` for back-compat.
- **R6.3** New commands SHOULD live under the existing `Session` subcommand group (e.g.
  `min session push`, `min session pr`) and a small `github` group for auth
  (`min github login/status`).

### R7 — Observability & errors

- **R7.1** Auth, clone/branch, push, and PR steps MUST emit structured `tracing` spans and
  actionable, non-secret error messages (e.g. "App not installed on owner/repo", "token
  lacks contents:write", "base branch main not found").
- **R7.2** `min github status` MUST let a user self-diagnose: who they are, token validity,
  App installation state, and the session's target repo/branch.

## UX flows

**Activate (server-side clone):**

```
min github login                      # one-time device-flow auth
min activate --repo owner/repo --branch feat/x [--base main] --attach
# → session clones owner/repo, checks out feat/x (created from main if absent),
#   wires authenticated origin; user lands in the workspace on feat/x
```

**Activate (adopt local checkout):**

```
cd ~/code/repo                        # existing git checkout
min activate --branch feat/x --attach
# → tarball seeds the workspace; origin re-wired to authenticate as the user;
#   branch reconciled (checkout-or-create feat/x)
```

**Work & push:**

```
# inside the session
git commit -am "…"
min session push                      # or: git push origin feat/x  (explicit only)
```

**Exit → PR:**

```
exit                                  # min attach detects shell exit
# → "Open a PR for feat/x → main? [y/N]"  → on y: ensure pushed, create PR as the user
```

## Technical grounding & integration seams

- **Auth client:** new device-flow + token-refresh module on the `min` side; tokens in the
  client credential store. No server-held secrets in the single-user MVP.
- **Activate:** extend `ActivateArgs` (`crates/minimal/src/lib.rs:239`) and the
  `CreateSession`/`ConfigureLoadout` sequence; carry the GitHub target via
  `SessionConfig.attrs` (`crates/minimald-rpc/src/lib.rs:206`). Perform clone + branch
  server-side using the `crates/checkouts` git-CLI wrapper pattern.
- **Credential injection:** unblock the deferred secrets path
  (`crates/mfile/src/package_composable.rs:26`, `crates/graph/src/env_setup.rs:132`);
  implement the on-demand credential helper over the existing trusted transport; enforce
  via `crates/sessions/src/core/policy.rs`.
- **Push:** a `Session` subcommand (`crates/minimal/src/lib.rs:117`) plus in-session
  `git push` working through the credential helper.
- **PR on exit:** client-driven prompt around `min attach`/`min destroy`
  (`crates/minimal/src/lib.rs:1109,1322`); GitHub API call from `min`. (A future headless
  path could implement the deferred `on_destroy` lifecycle-hook executor —
  `crates/sessions/src/core/lifecyclehook.rs`, `crates/minimald/src/session_host.rs:245`.)
- **Egress:** ensure github.com reachable under restrictive policies
  (`crates/minimald/src/net/policy.rs`).

## Future work

- **FW1** Multi-repo sessions (NG1) — broader token scope, per-repo branch/PR handling.
- **FW2** Multi-tenant hosted operation (`minhosted`/`mincloud`, NG2) — a real
  session→GitHub authorization layer and server-held/short-lived installation tokens; the
  `MinHosted`/`MinCloud` placeholders in `docs/session-domain-diag.md` are the anchor.
  With no local `min` at a terminal, the device authorization grant is driven from the
  hosted side (the `user_code` is shown in the session/web UI for the user to approve) —
  same grant, different display surface.
- **FW3** Headless PR-on-exit via the deferred `on_destroy` lifecycle-hook executor.
- **FW4** GitHub Enterprise Server support (NG5).
- **FW5** Optional bot/installation-token transport mode for automation identities (NG3).

## Open questions

- **OQ1** Command namespacing: a dedicated `min github …` group vs. folding into
  `min session …`. (Recommendation: `min github login/status` for auth, `min session
  push/pr` for session actions.)
- **OQ2** Default PR as **draft** vs. ready-for-review.
- **OQ3** Whether to request `workflows:write` up front or lazily only when a diff touches
  `.github/workflows/`.
- **OQ4** Exit-detection UX: prompt on every `min attach` exit vs. only on an explicit
  `min session finish`.

## Appendix — GitHub token reference

| Property | User-to-server (chosen) | Installation (alt) |
|---|---|---|
| Obtain | OAuth **device flow** | App JWT → `POST /app/installations/{id}/access_tokens` |
| Lifetime | **8h** token + rotating **6-month** refresh token | **1h**, not refreshable (re-mint) |
| Attribution | **Real user** | `app[bot]` |
| Repo scoping | Intersection of user access ∩ App install | `repositories`/`repository_ids` at mint |
| Git usage | `https://x-access-token:<token>@github.com/owner/repo.git` | same |
| Permissions needed | `contents:write`, `pull_requests:write`, `metadata:read`, (`workflows:write` if CI files) | same |

### Sources

- Generating an installation access token for a GitHub App — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app>
- Create an installation access token for an app (REST) — <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>
- Authenticating as a GitHub App installation — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation>
- Generating a user access token for a GitHub App — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app>
- Authenticating on behalf of a user (device flow / attribution) — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user>
- Refreshing user access tokens — <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens>
- Choosing permissions for a GitHub App — <https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app>
