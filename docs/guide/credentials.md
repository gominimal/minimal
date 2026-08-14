---
description: Give an agent in a session an outbound credential to a real API without the credential ever entering the box.
---

# Giving an agent a credential

An agent in a [session](./dev-shell.md) that must call a credentialed API —
Anthropic's own API, an MCP server behind a token — has no safe way to hold
that credential directly: anything you pass into the box as an environment
variable or a patched file is visible to every process running there, and to
`env`, `printenv`, and `/proc` for the lifetime of the session.

A **credential lane** solves this differently: the box gets a scoped,
revocable token and a local endpoint to call, and a broker running on your
host resolves the real credential and attaches it to the outbound request.
The value itself never crosses into the box.

## What a lane is

A lane has two halves, declared in two different places:

- **The project** declares that it wants a lane, and how the credential
  should be injected into the request — a header name, an optional prefix, and
  any static headers to attach alongside it. It never says which upstream the
  lane reaches or where the secret comes from.
- **You** bind the lane name to an upstream URL, a secret source, and
  optionally the HTTP methods the grant covers, once, in your own user-scope
  configuration.

Splitting it this way is the whole point: a project can ask for a credential
by name, but it cannot tell your machine where to send it or what to send.
Only your binding does that.

## Declaring a lane in the project

In `minimal.toml`, under `[session.credentials.<name>]`:

```toml
[session.credentials.anthropic]
inject = { header = "x-api-key" }
```

`<name>` is the lane name an agent's tooling will reference (via the
environment variable described below). `inject.header` is the HTTP header the
credential is attached under on the request to the real upstream; an optional
`inject.prefix` is prepended to the value, useful for `Authorization: Bearer
<token>` shapes:

```toml
[session.credentials.github-mcp]
inject = { header = "Authorization", prefix = "Bearer " }
```

`endpoint_var` publishes the lane's endpoint under a second name of the
project's choosing, so an agent that reads its base URL from a fixed variable
finds it with no wiring at all:

```toml
[session.credentials.anthropic]
inject       = { header = "x-api-key" }
endpoint_var = "ANTHROPIC_BASE_URL"
```

`inject.also` carries static, non-secret headers the broker attaches to every
request on the lane:

```toml
[session.credentials.github-mcp]
inject = { header = "Authorization", prefix = "Bearer ", also = { "X-MCP-Readonly" = "true" } }
```

Attaching a constraint host-side is different in kind from asking the box to
send one: a box can omit a header it was told to send, but it cannot remove one
the broker adds — and a box's own copy of an `also` header is stripped before
the broker attaches its own. A read-only marker pinned this way survives an
agent that has stopped cooperating.

See the [`minimal.toml` reference](../reference/minimal-dot-toml.md#credentials)
for the full field list.

## Binding a lane {#binding-a-lane}

The project's declaration is inert until you bind the lane name to an actual
upstream and secret, in your own user-scope credentials file — outside the
project tree, never committed to git:

```
~/.config/minimal/credentials.toml
```

```toml
[anthropic]
upstream = "https://api.anthropic.com"
source   = { env = "ANTHROPIC_API_KEY" }

[github-mcp]
upstream = "https://api.githubcopilot.com/mcp/"
source   = { file = "~/.secrets/github-mcp-token" }

[gist-sink]
upstream = "https://api.github.com/gists"
source   = { file = "~/.secrets/github-mcp-token" }
methods  = ["POST"]
```

`upstream` must be `https://` — a plain `http://` upstream is rejected, since
it would put your secret on the wire in cleartext. `source` names where the
value resolves from on your machine: `{ env = "VAR" }` reads a variable from
your own shell environment at activation time; `{ file = "path" }` reads a
host file (a symlinked path component is refused, the same as a patch
source).

`methods` narrows the lane to a verb set. Without it a lane grants every
method the upstream honours under the bound path, which is coarser than you
usually mean: `gist-sink` above can create a gist and nothing else. Names are
matched case-sensitively and must be written uppercase; a lowercase entry is
rejected when the file is read, since it could never match a request line.
Omit the field and every method is allowed, and a request whose method the
binding does not cover is refused exactly as an unknown token is — the broker
never opens a connection to the upstream for it.

`methods` is on your binding, not the project's declaration, for the same
reason `upstream` is: narrowing a grant is the grantor's to choose.

A lane name that appears in a project's `minimal.toml` but has no matching
entry in your `credentials.toml` fails activation, naming the lane and the
binding file it expected.

## Approving a lane

Like [patches and hooks](../reference/user-policy.md), a project-declared
lane is gated by your [user policy](../reference/user-policy.md#credentials)
before it can be used, matched against `[credentials]` by the project's root
path — the same key `[hooks]` uses, because the question is whether you trust
*this project* with your credentials at all, not whether you trust it with
this one lane name.

A project matching nothing in your policy is undecided, not allowed: `min
session activate` prompts you before anything runs, showing the lane name,
the **bound** upstream, the injected header, any `inject.also` header names,
and the `endpoint_var` the endpoint would be published under — never the
credential's value. Choose to allow it once, allow it permanently, or deny
it, the same choices offered for any other gated contribution. Under
[`--no-prompt`](../reference/cli-min.md#global-flags) an undecided lane fails
activation with a ready-to-paste policy snippet instead of prompting.

A lane declared in one of your own [loadouts](../reference/loadouts.md)
auto-allows — it's your own configuration already. A lane a package declares
is denied outright; packages cannot hold credential lanes.

## What the box sees

Once a lane is approved, the session carries a handful of environment
variables instead of a credential:

| Variable | Value |
|---|---|
| `MINIMAL_CREDENTIAL_ENDPOINT_<LANE>` | The local broker endpoint for this lane, e.g. `http://100.64.255.254:<port>/anthropic`. |
| `MINIMAL_CREDENTIAL_URL_<LANE>` | The same endpoint with the token in the path: `http://100.64.255.254:<port>/t/<token>/anthropic`. |
| `MINIMAL_CREDENTIAL_UPSTREAM_<LANE>` | The upstream your binding bound, so the box need not assume how much of the path the binding already covers. |
| `MINIMAL_CREDENTIAL_LANES` | The lanes this box actually holds, space-separated in name order. |
| `MINIMAL_CREDENTIAL_TOKEN` | A bearer token scoping this box to those lanes. |

`<LANE>` is the lane name upcased with `-` replaced by `_` — `anthropic`
becomes `ANTHROPIC`, `github-mcp` becomes `GITHUB_MCP`. A lane that declares
`endpoint_var` publishes its endpoint under that name too, so an agent reading
`ANTHROPIC_BASE_URL` finds the lane without a line of per-project shell.

`MINIMAL_CREDENTIAL_LANES` is there so the box can tell a lane it was denied
from a lane it misspelled: either is simply absent from the environment, which
otherwise surfaces as a confusing `401` deep inside an agent rather than an
error at launch. So it is set to the empty string, not left out, when you were
granted nothing: empty means "the broker is there and you hold no lane", and
that is a different thing from a lane you misspelled.

The per-lane variables appear only when the box holds that lane and can reach
the broker — a `NoNet` box gets none of them, never an empty one, which would
read as a configured endpoint and fail far from the cause. `NoNet` is also the
one case where `MINIMAL_CREDENTIAL_LANES` itself is absent: there is no
credential plane to report on.

### Presenting the token

There are two ways to authenticate a request, and the lane accepts both (and
both at once, as long as they agree). Software with a header slot points at
`MINIMAL_CREDENTIAL_ENDPOINT_<LANE>` and sends `MINIMAL_CREDENTIAL_TOKEN` as
`X-Minimal-Credential-Token` on each request. Software with only a URL slot —
an agent whose extension config takes a bare URL and nothing else — uses
`MINIMAL_CREDENTIAL_URL_<LANE>`, whose `/t/<token>/` path prefix the broker
strips before it reads the lane, so lane selection and path scoping are
unchanged.

**Prefer the endpoint form wherever you have the choice.** The two grant
identical access, but `MINIMAL_CREDENTIAL_ENDPOINT_<LANE>` is safe to log,
print, or commit to a config file, whereas `MINIMAL_CREDENTIAL_URL_<LANE>`
*contains the token* and is a secret for as long as the session lives. Writing
it into a file in the project tree is the specific mistake to avoid: that tree
is a git worktree and anything that copies files back out of the box carries
the token with them. Treat the URL form like any other credential inside the
box, even though it is worthless outside the session.

A request through the lane, in either form, reaches the real upstream with the
real credential attached; a request to the upstream directly, without the
token, does not.

Nothing else appears in the box. The credential's value is never in `env`,
never in a patched file, and never written to the session's on-disk
composition — only the endpoint and a token that is meaningless outside this
session.

## Reviewing a session's lanes

`min session credentials <session>` lists every lane an active session holds:
the lane name, the header it injects into, its bound upstream, where it was
declared, and whether the broker still holds a live registration for it.
`--json` adds the lane's `inject.also` headers and its `endpoint_var`. It never
shows a value, at any verbosity or with `--json`.

The last column reads `live` when the broker holds the lane and a request on it
would be served, `dead` when the broker answered and holds nothing for it, and
`unknown` when no broker answered at all. `dead` is what you see after the
daemon or the VM restarts: the broker's registrations live only in its memory
and die with it, while the session itself survives. Nothing re-registers them —
create the session again to get live lanes back.

## Revoking access

A lane's token lives only as long as the session that requested it: destroying
the session (`min session destroy`) revokes it. There is also an absolute
expiry, so an abandoned session's access does not outlive the session
indefinitely even if the client that created it never runs the revoke.

## Why the project can't redirect your credential

The security property this design relies on is narrow and worth stating
plainly: **the binding, not the project, owns the destination.** A project's
`[session.credentials.<name>]` block has no field for an upstream URL — it
can only ask for a lane by name and describe how to inject the header. If a
project could also say where the lane goes, an already-allowed project could
quietly repoint a bound lane's *name* at an attacker-controlled host and
receive your real credential in plaintext, with no additional prompt, because
your policy allow-lists the project path, not the lane's destination. Because
the upstream comes only from your own binding file, the worst a malicious
project can do is ask for a lane name you've already bound, and get exactly
the upstream you bound it to.
