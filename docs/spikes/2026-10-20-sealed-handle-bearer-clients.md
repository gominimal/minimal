---
id: 2257
title: "Sealed handle as a client's bearer (SP1)"
status: proved
date: 2026-10-18
budget_hours: 24
actual_hours: 1.5
related:
  - "issue #2257 (this spike, SP1 of the box egress proxy plan)"
  - "issue #1501 (BEP epic)"
  - "issue #2292 (T28: inject a stored key in the registered form), which waits on this spike"
  - "docs/specs/24-spec-box-egress-proxy/24-spec-box-egress-proxy.md (BEP-012, BEP-032, BEP-079, open question on client acceptance)"
tags:
  - bep
  - secrets
  - mcp
  - claude-code
---

# Question

Does each intended client send the sealed handle as its bearer, unmodified, in
the header the store rule names? Some clients check a token's shape before they
send it. Others send the credential in a header the rule does not name. Either
kind needs the harness adapter.

# Hypothesis

Claude Code with a sign-in token sends `Authorization: Bearer <value>` with no
check on the token's shape. MCP clients do the same.

# Method

A local stand-in played the proxy. It is `mitmproxy` 12.2.3 with the script
`standin.py`, and it offers HTTP/1.1 only, as the proxy does. It ends TLS under
its own CA and answers every request itself. It forwards nothing.

For each request the stand-in records the host, the path, the HTTP version
and the header names. It also checks each header whose name looks like a
credential. It records whether the value is the handle, `Bearer ` plus the
handle, or a value that contains the handle. For any other value it records
only the length and a short hash.

The clients used the variables a `proxy_env` box gets. `HTTPS_PROXY` and
`HTTP_PROXY` pointed at the stand-in. `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`
and `REQUESTS_CA_BUNDLE` named the stand-in's CA. Each run started from a new
environment with a throwaway home and config directory. No sign-in or setting
from the host reached the client.

The handle comes from `make-handle.py`. It is 484 characters: three base64url
segments joined by dots, the shape of a compact signed token. Its signature is
random.

Each MCP server had explicit headers, as a store rule sets them:

- `mcp.linear.app` and `mcp.cloudflare.com`: `Authorization: Bearer <handle>`.
- `mcp.sentry.dev`: `Authorization: Sentry-Bearer <handle>`.

The stand-in answers `initialize` and `tools/list` with a minimal valid reply.
So no client falls back to a browser sign-in.

The steering runs target `mcp.sp1.invalid`, a name that never resolves. A request to
it reaches the stand-in only if the client uses the proxy. These runs test
steering on its own.

`run.py` drives every case. The rows for each request are in `results/`.

The versions were Claude Code 2.1.302 and mcp-remote 0.15.1 on Node 26.0.0.
The Python MCP SDK was 2.3.0 on Python 3.14.6. The host was macOS 26.7 on arm64.

# Findings

| Client and setting | Header with the handle | Value as sent |
|---|---|---|
| Claude Code, `ANTHROPIC_API_KEY` | `x-api-key` | the handle, unchanged |
| Claude Code, `ANTHROPIC_AUTH_TOKEN` | `Authorization` | `Bearer <handle>`, unchanged |
| Claude Code, `CLAUDE_CODE_OAUTH_TOKEN` | `Authorization` | `Bearer <handle>`, unchanged |
| Claude Code as MCP client, Linear and Cloudflare | `Authorization` | `Bearer <handle>`, unchanged |
| Claude Code as MCP client, Sentry | `Authorization` | `Sentry-Bearer <handle>`, unchanged |
| mcp-remote, `NODE_USE_ENV_PROXY=1` | `Authorization` | `Bearer <handle>`, unchanged |
| Python MCP SDK, Linear, Sentry and the unresolvable name | `Authorization` | the set value, unchanged |

## 1. No client checks the token's shape

Every client sent the 484-character handle byte for byte. It did so in every
request that carried a credential. No client put the handle in a request
body. Every request used HTTP/1.1.

## 2. Claude Code picks its header from the variable

With `ANTHROPIC_API_KEY`, Claude Code sends the value in `x-api-key` with no
prefix. With `ANTHROPIC_AUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN`, it sends
`Authorization: Bearer <value>`.

The spec's `anthropic` preset (BEP-079) names `Authorization` with the prefix
`Bearer `. It fits only the two token variables. A box can set
`ANTHROPIC_API_KEY` to the handle. Then the handle travels in a header the
rule does not name. The proxy substitutes only in the rule's header. So the
handle goes upstream unchanged, and the upstream refuses the request.

## 3. Claude Code sends the credential to many paths on one authority

Every request went to `api.anthropic.com`. With an API key, 27 of 39 requests
carried it: settings, policy limits, bootstrap, model requests and event
logging. Substitution applies to all of them, so each is one audited
redemption. Some requests carried no credential, such as the MCP registry
and some event-logging batches. They passed with none.

## 4. Node's built-in fetch ignores `HTTPS_PROXY` by default

mcp-remote uses Node's built-in `fetch`. Without `NODE_USE_ENV_PROXY=1` it
ignored `HTTPS_PROXY` and resolved the name itself. The run failed with
`getaddrinfo ENOTFOUND mcp.sp1.invalid`, and no request reached the stand-in.
With the variable set, every request went through the stand-in.

Under `proxy_env` steering, a client like this connects to the real upstream
directly. It sends the handle there with no substitution. `dns` steering
does not have this gap. Claude Code and the Python SDK use `HTTPS_PROXY` with no
extra variable.

## 5. Explicit headers keep MCP clients off the browser sign-in

Claude Code and the Python SDK sent the set header on the first request. They
did not look for sign-in metadata. mcp-remote sent a `GET` first, and the
stand-in answered 405. mcp-remote then probed the `.well-known` sign-in
metadata paths. After that it sent the set header on every `POST`.

# Conclusion

The hypothesis holds. The intended clients send the handle unmodified, in the
set header, with no shape check. Because of that, the spec can settle the
open question on client acceptance, and the injection task can use the handle
as it is.

The measurements show gaps in the spec that do not concern the handle:

- The `anthropic` preset fits only the token variables. An API key in
  `ANTHROPIC_API_KEY` travels in `x-api-key` with no prefix.
- `proxy_env` steering misses Node clients that use the built-in `fetch`. The
  box must also set `NODE_USE_ENV_PROXY=1`.

# Action items

1. Settle the open question on client acceptance in the spec, and cite this
   document. Close the spike issue so the injection task can start.
2. Decide the `anthropic` preset. One option points it at `x-api-key` with no
   prefix, which fits `ANTHROPIC_API_KEY`, and adds a second preset for the
   token variables. Another option keeps it and says in its help which
   variable it fits.
3. Add `NODE_USE_ENV_PROXY=1` to the variables BEP-012 sets under `proxy_env`
   steering.

# Artifacts

- `make-handle.py` writes `handle.txt`, the opaque handle.
- `standin.py` is the stand-in script. Start it with
  `mitmdump --listen-port 18799 --set upstream_cert=false --set connection_strategy=lazy --set http2=false -s standin.py`.
- `run.py` drives each case with a clean environment. It expects the stand-in
  on port 18799, mcp-remote in `node_modules`, and the Python MCP SDK in
  `.venv`.
- `py_mcp_client.py` is the Python MCP SDK client.
- `results/*.jsonl` holds one row per request for each case.
