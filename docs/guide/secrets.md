---
description: Give a box an API key by reference — the value stays in your host keychain, the box holds a short-lived handle, and injecting the key is the proxy's job and never the box's.
---

# Secrets by reference

A box that needs an API key does not need the key. You keep the value in your
host's keychain, the project's spec refers to it by identifier, and the
[Box Egress Proxy](../reference/user-policy.md#secret-store-rules) injects it
into the box's requests to the one upstream you registered for it. What lands
in the box is a short-lived handle, so a tool inside it — an agent, a test
suite, a leaked log line, a compromised dependency — never sees the key.

The last leg of that — the injection — is not in force yet. Everything up to it
is: read [Today's limits](#todays-limits) before you plan work around this.

Three pieces, in three different places, on purpose:

| Piece | Who owns it | Where it lives |
|---|---|---|
| The value | you | your host's keychain, via [`min secret`](../reference/cli-min.md#secret-set-secret-list-secret-rm) |
| What it may reach, and how it goes on the wire | you | [`[[secret-store-rules]]`](../reference/user-policy.md#secret-store-rules) in `<config>/minimal/config.toml` |
| That the box wants it, and in which variable | the project | [`[[session.references]]`](../reference/minimal-dot-toml.md#session-references) in `minimal.toml` |

A project can ask for a value. It cannot say what the value may be sent to.

## Store the value

```console
$ min secret set anthropic-api-key
? value: ›
keychain `anthropic-api-key` stored
```

The prompt does not echo, and the command prints the identifier and never the
value. Piping works too (`pbpaste | min secret set anthropic-api-key`); a value
passed as an argument is refused, because an argument lands in your shell
history and every process on the host can read it.

The item is stored with an access entry for the proxy's process identity, so
the proxy reads it for each request without prompting and every other
application prompts.

## Register what it may reach

This is yours, in `<config>/minimal/config.toml`. A rule names the identifier,
the upstream authorities the value may be injected into, and the form it takes
on the wire:

```toml
[[secret-store-rules]]
store    = "keychain"
id       = "anthropic-api-key"
upstream = ["api.anthropic.com:443"]
inject   = { header = "x-api-key" }
action   = "allow"

[[secret-store-rules]]
store    = "keychain"
id       = "mcp-server-token"
upstream = ["mcp.example.com:443"]
inject   = { header = "authorization", prefix = "Bearer " }
action   = "ask"
```

Write the rule for the header the client already sends its credential in:
`x-api-key` for Claude Code's Anthropic key, `Authorization: Bearer` for an MCP
client. The client is given the handle in the variable it already reads and
sends it in the header it already sends — nothing about it is configured for
Minimal, and nothing about the handle needs rewriting on its way out.

`action = "ask"` asks you at the terminal before the value is injected, and
**denies** the reference when there is nobody to ask: no terminal, or
`--no-prompt` or `--no-input` saying you are not there — a scripted activation
never guesses. `deny` never injects. Some names a rule may not
register at all: a configured module's hosts (those carry the module's own
sealed value), Minimal's own hostnames, and headers like `Host` or `Cookie`
that would reframe the request rather than authenticate it. Such a rule is
refused when the configuration is read, so no box is ever created under it.

## Refer to it from the project

```toml
[session.network.egress]
allow_dns_hosts = ["api.anthropic.com"]

[session.network.bep]
steering = "proxy_env"

[[session.references]]
store  = "keychain"
id     = "anthropic-api-key"
env    = "ANTHROPIC_API_KEY"
source = "store"
```

The box's own egress has to admit the authority your rule registers: the spec
says which hosts the box may reach, your rule says what may be injected into
them, and both have to agree. A box that declares a reference is steered
through the proxy exactly as a box declaring a
[grant](../reference/minimal-dot-toml.md#session-network) is — it has to reach
the proxy for the injection to happen at all.

## Review it before creating the box

```console
$ min box spec
box spec: /repo/web
  interception root: sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
  steering: proxy_env (interception anchor in the box trust store)
  proxy environment:
    HTTPS_PROXY=http://127.0.0.1:7656
    HTTP_PROXY=http://127.0.0.1:7656
    NO_PROXY=.min.internal,host.min.internal,localhost,127.0.0.1
  grants: none declared
  references:
    - keychain reference `anthropic-api-key`: authorities api.anthropic.com:443
```

`min box spec` runs the same validation `min session activate` runs, so what it
refuses, activation refuses — with **exit 3**, naming every cause, before a box
exists:

- `matches no [secret-store-rules] rule` — you have not registered the
  identifier. The review shows the reference with `authorities none
  registered`.
- `missing: api.anthropic.com` — your rule registers an authority the box's own
  `allow_dns_hosts` does not admit.
- `action = "ask"`, with nobody to ask: no terminal, `--no-prompt`, or
  `--no-input`.
- `action = "deny"`.

## What the box gets

```console
$ min session exec web-4f21 'printenv ANTHROPIC_API_KEY'
minsealed1.eyJ2IjoxLCJib3hfaWQiOiJ3ZWItNGYyMSIsImhvc3QiOiJtYWMtMSIsIm1vZHVsZSI6…
```

A sealed envelope carrying a handle that names the store, the identifier, the
authorities and the injection form — and expires minutes later. It is bound to
this box and this host, so it is no use anywhere else, and it is not the key.
This much is what a box gets today.

What the proxy then does with the handle is decided per request: it reads your
keychain for the one request it injects the value into, and writes the value to
no file. Two consequences follow from deciding it per request:

- **A replacement takes effect at once.** `min secret set` over an existing
  identifier is injected by the next request that redeems a reference to it,
  and `min secret rm` refuses the next one. No restart of the box or the proxy.
- **Editing a rule bites a running box.** A handle whose rule has since
  narrowed its authorities, or changed its injection form, is refused at the
  proxy.

Both describe the proxy's decision, which is not yet reachable from a box: the
proxy your host runs is started holding neither your rules nor your keychain, so
it refuses every handle presented to it. Until it is handed them, a box's
request to the registered upstream carries the handle and gets no value —
see [Today's limits](#todays-limits).

## When a request is refused

[`min box audit <box>`](../reference/cli-min.md#box-audit) reads the proxy's own
records for that box: one line per decision, naming the upstream authority, the
identifier and the marker. A refused reference is marked
`store_handle_invalid`; a value the store no longer hands over names the
identifier that went missing. No record ever carries a credential, which is
what makes the trail safe to paste into a bug report — as
[`min bug`](../reference/cli-min.md#bug) does for you.

## Today's limits

- **No value is injected yet.** The proxy is started without your
  `[[secret-store-rules]]` and without access to your keychain, so it decides
  every handle a box presents against no rule and refuses it. What works today
  is all of the rest: storing the value, registering what it may reach, the
  refusals that name an unregistered identifier or a missing egress host, the
  review, and the handle in the box's own variable. A box cannot reach an
  upstream with a stored key in its requests until the running proxy is handed
  the rules and the store.
- The host store is the macOS Keychain. A Linux host holds no referenced value
  yet, and `min secret` says so rather than pretending to store one.
- The proxy has to be running for a reference to be redeemed: it is what holds
  the value, and the box never does.
- One value, one identifier, one rule. A box referring to two values declares
  two references, each in its own variable.
