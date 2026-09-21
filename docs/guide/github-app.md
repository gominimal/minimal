---
description: Register the GitHub App `min auth login` signs in under — the permissions it may request, the settings it must carry, and why each one is load-bearing.
---

# The GitHub App behind `min auth login`

`min auth login` signs you in to GitHub under a published GitHub App, and the
token it holds is that App's permissions intersected with yours and with the
installations you hold. The App's registration is therefore the ceiling on
everything a box can ever reach with a brokered credential — which makes it
security-critical configuration, not an ops detail.

You do not need to register anything to use Minimal: the published App is
already wired in. This page is for anyone standing up their own — a fork, a
private deployment, a test registration — and for anyone reviewing what the
published one is allowed to do.

## Register a GitHub App, not an OAuth App

GitHub App user tokens expire and renew; OAuth App tokens do not. The custody
design depends on the first.

## Permissions

Request exactly these, and nothing else.

| Scope | Permission | Why |
|---|---|---|
| Repository | `metadata: read` | Every other repository permission implies it. |
| Repository | `contents: read + write` | Clone, fetch and push. |
| Repository | `pull_requests: read + write` | Open and update pull requests from inside a box. |
| Repository | `issues: read + write` | Read and triage issues from inside a box. |
| Organization | `members: read` | Org and team membership, which repository `metadata` does not cover. |

Two exclusions are properties, not omissions:

- **No `administration`**, repository or organization. No brokered credential
  ever holds it, and that holds by construction because the App never asks for
  it.
- **No `workflows`**. GitHub gates writes to Actions workflow files behind
  `workflows: write` even when `contents: write` is held, so excluding it means
  no brokered token can rewrite CI.

Widening this set is a security-review event: an over-broad grant silently
widens every token the App ever mints.

## Settings

**Enable the device flow.** `min auth login --device` is the reference sign-in
shape, and it is the only one that needs no client secret.

**Leave "User-to-server token expiration" enabled.** It is a per-App setting,
not a platform constant. The design holds 8-hour tokens and renews them on
GitHub's refresh token; a token response carrying no `expires_in` or
`refresh_token` is a configuration error, not something to store.

**Install the App** on the account or organization whose repositories the token
should reach. An uninstalled App yields a token that reaches nothing, because
the token is capped at the installations you hold.

## The client id, and the secret you probably do not need

A client id is public by construction — both sign-in flows put it on the wire —
so it is spelled in the source rather than configured. To sign in under your own
App instead, set `MINIMAL_GITHUB_APP_CLIENT_ID`.

The device flow needs no client secret. GitHub's web application flow does
require one at the code exchange, even with PKCE and a loopback redirect, so a
host running the browser flow sets `MINIMAL_GITHUB_APP_CLIENT_SECRET`. Nothing
in this repository carries a secret value.

## What you get, and what you do not

A locally minted member is **`full` breadth**: the signed-in account's
manifest-capped reach, until the token expires. There is no local narrowing
path yet, so a box spec declaring narrower `github:repo:*` scopes is refused at
expansion rather than honoured approximately. Declare `github:user-token`, which
is the honest spelling of what the member actually is.

## See also

- [Secrets by reference](secrets.md) — the other half of the credential plane,
  for upstreams that are not GitHub.
- [`min auth`](../reference/cli-min.md#auth) — the command reference.
