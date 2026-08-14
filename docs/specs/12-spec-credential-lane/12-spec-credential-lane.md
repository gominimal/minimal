---
id: spec-credential-lane
title: "Credential lane: outbound credentials a box never holds"
kind: spec
status: planned
tracking-issue:
supersedes:
---

# Credential lane: outbound credentials a box never holds

## Context

A box that must authenticate outward has no supported way to do it. Every
mechanism that exists today ends with the plaintext secret inside the sandbox:

- **Inherited vars.** `FOO = { inherit = true }` resolves on the client and
  travels to the daemon as `WireResolvedVar { name, value, carries_user_data }`
  (`crates/sessions/src/wire/primitives.rs:70-87`). The value reaches the box as
  execve envp — visible to `env`, to `printenv`, and to `/proc/<pid>/environ`.
- **Patches.** A patch copies a host file into the session home.
- **Task-path fs mappings.** A package's `env_file_mappings` entry is
  bind-mounted read-write from the host into a task sandbox
  (`crates/mctx/src/env.rs:582-615` → `crates/sandbox2/src/lib.rs:666-679`),
  with no policy gate anywhere on that path.

The resolved composition is then persisted: `DiskLoader::store_composition`
serialises `WireComposition` — vars and their values included — to
`<minimal_dir>/sessions/<short>/composition.json` with `std::fs::write` and
**no `set_permissions` call anywhere in that file**
(`crates/sessions/src/store.rs:992-1018`), so it lands at `0644` under a default
umask. `record.json` beside it has the same property
(`crates/sessions/src/store.rs:680-696`). Var values are additionally logged at
`debug` (`crates/minimald/src/session_host.rs:271-276`). An
`AWS_SECRET_ACCESS_KEY = { inherit = true }` is written verbatim to a
world-readable file.

The one place a secrets channel is named does nothing. `extract_fs_mappings`
drops `class = 'Credential` mappings with a `TODO(secrets)` and a warn
(`crates/minimald/src/sessions/composables.rs:113-182`), pinned by
`credential_class_fs_mappings_are_filtered_out`. That filter is **session-path
only**: `SetupForPackages::build` reads the same nickel attrs and ignores
`class` entirely (`crates/graph/src/env_setup.rs:34-109`), so the task path still
maps credentials in. Issue #1204 is that divergence biting a real user.

`carries_user_data`'s own doc comment already names "future secret-scrubbing
heuristics" as its intended consumer. This is that work.

This document is a pre-implementation design. It follows the prose shape of
[spec 11](../11-spec-lifecycle-hooks/11-spec-lifecycle-hooks.md) — the argument
first, because the placement decisions are the whole point — and adds a
**Units of work** section carrying `R{unit}.{seq}` IDs so it can be planned
against. The **Changed from the original design** callouts spec 11 uses belong
to its as-shipped reconciliation pass; this spec has nothing shipped yet.

## User stories

As a user I want to…

- Give an agent in a box the ability to call a credentialed API without the
  credential ever entering the box
- Review, before anything runs, exactly which upstreams a box may reach and
  with which credential — and never see the value in that review
- Revoke a box's access by destroying it
- Have a box that reaches an upstream it was not granted simply fail

As a project maintainer I want to…

- Declare that my project needs a named credential, without naming, holding, or
  being able to redirect the user's copy of it
- Have that declaration be inert until the user approves it

As an operator I want to…

- Bind a lane name to a host secret **and its permitted upstream** once, in my
  own configuration, and have every project that asks for that name use it
- Keep the binding out of the project tree, out of git, and out of the box

## Non-goals

- **A secrets store.** Values resolve from the host environment or a host file,
  behind a trait. KMS, Vault, and OS keychains are later implementations.
- **Package-declared credentials.** `class = 'Credential` stays dropped.
- **Touching `[[session.lifecycle_hooks]]`, the hook runner, or `proxy.rs`'s
  `Router`.** B5/B8 route host→box by `Host:` header; they are not the box's
  outbound path.
- **Protocol translation.** The broker forwards bytes; it does not rewrite
  bodies between API dialects.
- **Credential lanes for `min task run`.** The task path has no policy plane at
  all; lanes are session-scoped in this pass.
- **HTTP/2 or prior-knowledge upgrades** on the box→broker leg. HTTP/1.1 only;
  anything else is refused.

## Solution

### Placement: the broker lives where gvproxy lives

The broker holds plaintext. It must run on the **host**, outside any box and
outside the guest VM. The obvious placements do not survive the deployment
matrix:

| Deployment | Host-side | Guest-side |
|---|---|---|
| macOS (DM1) | `min`, `minvmd`, `gvproxy-min` | `minimald` |
| Linux native (DM2) | `min`, `minimald`, `gvproxy-min` | — |
| Linux + KVM (DM3/4) | `min`, `minvmd`, `gvproxy-min` | `minimald` |

There is **no minimal daemon host-side on all three**. `minimald` is not shipped
for darwin — the release staging table has no `minimald|darwin` row
(`scripts/stage-release.sh:144-156`) and the crate cannot build there
(unconditional `hakoniwa` dependency, `crates/minimald/Cargo.toml:41`). `minvmd`
does not run on native Linux. So "the broker lives in minimald" leaks host
secrets into the guest on macOS and Linux/KVM, and "the broker lives in minvmd"
has no owner on native Linux.

The only process host-side in every model is gvproxy — and its owner is exactly
the host-side daemon per model: `minvmd` spawns it on DM1/3/4
(`crates/minvmd/src/cmd/run.rs:267-324`), `minimald` spawns it on DM2
(`crates/minimald/src/net/mod.rs:289-322`), a split already encoded as
`SwitchTransport::{LocalSpawn, HostShuttle}` (`crates/minimald/src/net/mod.rs:53-72`).

**The broker is owned wherever gvproxy is owned.** Not a convenience: the host
alias NATs to `127.0.0.1` *of the machine running gvproxy*
(`crates/switch/src/lib.rs:293`), so binding the broker on that process's
loopback is what makes the address resolve. Placement and reachability are one
fact.

A new `credlane` library crate holds the broker; `minvmd` and `minimald` each own
its lifetime where they are host-side, `minimald` gating on `!in_microvm` — the
same predicate `start_host_proxies` uses to choose its bind address
(`crates/minimald/src/server.rs:696-777`).

### It is not a fifth binary

A new compiled binary **cannot ship without editing
`.github/workflows/release.yml`**, which is frozen and CODEOWNER-gated. Every
shipped binary is an explicit `cargo build` + `mv` + `upload-artifact` triple
there (`release.yml:153-184`, `:291-320`, `:384-456`); there is no discovery over
workspace bin targets, and `scripts/stage-release.sh` hard-fails on a component
whose artifact no workflow step produced (`stage-release.sh:220-230`).

The broker ships as a **subcommand of the daemon that already runs host-side** —
`minvmd broker` and `minimald broker` — with the logic in the shared crate. Zero
workflow edits, zero new install components, and it inherits the macOS
Developer-ID signing a new Mach-O would otherwise need.

This departs from the "sibling of `gvproxy-min`" shape deliberately.
`gvproxy-min` is a vendored upstream binary that is *downloaded*
(`scripts/fetch-gvproxy.sh`), not precedent for shipping a fifth first-party one.

### The address the box uses

`http://100.64.255.254:<port>` is **not** universally reachable, and this is the
correction that most changes the design. The alias is `broadcast - 1` of the
switch subnet (`crates/switch/src/lib.rs:218-224`), NAT'd to host loopback. It
resolves only where the caller's netns reaches the switch *and* gvproxy runs:

- **In a microVM (DM1/3/4), every mode.** The guest root netns is itself a switch
  client — `minimald` brings up `eth0` at `daemon_ip` with a default route via
  the gateway (`crates/minimald/src/guest.rs:934-967`), unconditionally on the
  vsock path (`crates/minimald/src/main.rs:917`) — so a default `HostNet` box
  reaches the alias, and it lands on the *host's* loopback, outside the VM. This
  is the case the design wants, and it works.
- **Native Linux, `own-ip` only.** The tap is built rootless by hakoniwa's
  RustSlirp *inside the sandbox's own netns*
  (`crates/sandbox2/src/lib.rs:501-533`) and its fd is relayed to the locally
  spawned gvproxy's `-listen` socket
  (`crates/minimald/src/net/gvproxy_network.rs:202-227`; fd handoff at
  `crates/minimald/src/session_host.rs:1923-1945`). gvproxy is spawned lazily on
  first attach and stopped when the last own-IP box detaches
  (`crates/minimald/src/net/mod.rs:289-322`). The host root netns holds no switch
  tap on **any** deployment model, so the alias resolves only from inside a box
  that is a switch client.
- **Native Linux, `HostNet` (the default).** Unreachable. `HostNet` "shares the
  host/VM network namespace… No isolation, no wiring"
  (`crates/sandbox2/src/network.rs:74-82`). The box's `127.0.0.1` *is* the host
  loopback, so the broker is reachable there at plain `127.0.0.1:<port>`.
- **`NoNet`.** Unreachable by any IP. A `NoNet` box gets no lane.

So the endpoint is **computed by the daemon and handed to the box**, never
hardcoded. On that native-Linux `HostNet` path the box is in the host network
namespace and can already reach every host loopback service; loopback is not an
isolation boundary there. The token, not the network, is what scopes access —
true everywhere, merely *visible* there.

### Declaration: the project asks, it does not point

A project declares that it wants a lane, under `[session.credentials]`:

```toml
[session.credentials.anthropic]
inject = { header = "x-api-key" }

[session.credentials.github-mcp]
inject = { header = "Authorization", prefix = "Bearer " }
```

It lives under `[session]`, not at the top level, for two mechanical reasons.
`build_composables` short-circuits on `has_material`, which consults only
`project_declared_packages`, `mfile.session`, and the graph stack
(`crates/minimald/src/sessions/composables.rs:434-441`) — a top-level section
would leave a credentials-only project with no composable at all, silently
dropping its lanes before the gate ever saw them. And `Session::is_empty()` uses
an exhaustive `let Self { … } = self` destructure precisely so a new primitive
fails to compile until accounted for (`crates/mfile/src/lib.rs:427-441`). Spec 11
records the same convention for hooks: "In a `minimal.toml` the section is
prefixed with `session.`".

**The project does not name the upstream.** The user's binding does:

```toml
# ~/.config/minimal/credentials.toml
[anthropic]
upstream = "https://api.anthropic.com"
source   = { env = "ANTHROPIC_API_KEY" }

[github-mcp]
upstream = "https://api.githubcopilot.com/mcp/"
source   = { file = "~/.secrets/github-mcp-token" }
```

This is the correction the first draft of this spec got wrong, and it is the
whole security argument. If the project supplied `upstream`, then an allow-listed
project could declare `[session.credentials.anthropic]` with
`upstream = "https://evil.example"`, and the broker would resolve the user's real
key and put it in the header on a request to the attacker's server — full
plaintext exfiltration of a long-lived key, no prompt, and the box never touches
the value, so every other property this design claims stays intact while the
credential is gone. The policy gate does not save it: the gate is keyed by
**project path**, exactly like `[hooks]`
(`crates/sessions/src/core/policy.rs:707-724`), so any project already inside an
`allow = ["~/work/**"]` glob clears it without a prompt.

The binding is therefore the authority on **both** halves — where the secret
comes from and where it may be sent. The project supplies only the lane name and
the injection shape. The worst a malicious project can do is ask for a name the
user has bound, and get that name's upstream.

`upstream` must be `https://`. Plain `http://` would put the user's secret on the
wire in cleartext; it is rejected at parse.

`Credential` and `CredentialInject` carry `#[serde(deny_unknown_fields)]`,
breaking mfile's flatten-`extra`-and-warn convention deliberately. Every other
section collects unknown keys into an `extra: HashMap<String, toml::Value>` and
`File` derives `Serialize` (`crates/mfile/src/lib.rs:742-787`) — so a catch-all
would *ingest and re-emit* a plaintext secret someone pasted as `value = "sk-…"`.
Refusing to parse it is what keeps "a secret never enters this struct"
mechanically true. The precedent is `HookScriptRepr`
(`crates/sessions/src/core/lifecyclehook.rs:200-217`).

### Lane names are a wire contract

A lane name is simultaneously a map key, a URL path segment, and an environment
variable suffix, so it is constrained at parse: `^[a-z0-9][a-z0-9-]*$`, mangled
to the env suffix by upcasing and replacing `-` with `_`. Two lanes that mangle
to the same suffix are a parse error, not a last-writer-wins.

### Resolvers

A `Resolver` trait turns a bound source into a value, on the host, on the client.
Two ship: `env` (read the named variable from the client's process environment)
and `file` (read a host path, rejecting a symlinked component the way hook script
paths already are). Keychain and Vault are later implementations.

Resolution runs **client-side**, because `min` is the only process host-side on
all three deployment models and because it is already where `inherit` resolves
(`crates/minimal/src/lib.rs:1466-1468`; the daemon composer is hard-wired to
`deferring_env()`, returning `Ok("")` for every name,
`crates/sessions/src/core/compose.rs:564-575`). The daemon never sees a value.

### The policy gate

`[credentials]` becomes the fourth gated domain in `user_policy.toml`, with the
same three keys and semantics as `[vars]`, `[patches]`, and `[hooks]`, matching
on the **project root path** exactly as `[hooks]` does
(`crates/sessions/src/core/policy.rs:707-724`): a lane from a user loadout
auto-allows; a lane from `Source::Package` is **denied outright**; a project lane
is matched deny → ignore → allow → `NeedsApproval`. Silence is not consent: an
unmatched project reaches the prompt, and under `--no-prompt` fails activation
with a paste-ready snippet, extending `UnapprovedSummary` rather than inventing a
second error shape (`crates/minimal/src/prompt.rs:708-774`).

Path is the right key rather than lane name because the question is "do you trust
this project with your credentials", and a name-keyed rule would let an untrusted
project inherit a decision made about a trusted one.

The prompt shows the lane name, the **bound** upstream, and the header — the same
reason `WirePendingHook` ships the whole hook body so the prompt can show what is
being approved (`crates/sessions/src/wire/primitives.rs:286-299`). Review happens
at the prompt, before anything runs; `min session credentials` (below) is the
after-the-fact view, not the gate.

The gate must be added to the daemon's all-decided fast path
(`crates/sessions/src/daemon/composer.rs:180-197`), currently
`vars.is_empty() && patches.is_empty() && lifecycle_hooks.is_empty()`. Its in-code
comment records that omitting hooks once let hook-only projects bypass the gate
entirely; a credentials-only project must not repeat it.

### Token lifecycle

The box is handed a bearer token — not the credential, but a capability naming
which lanes this box may use.

**The broker mints it.** The broker is host-side; `Manager::create_session` is
guest-side on DM1/3/4, so minting there would put the authority on the wrong side
of the VM boundary and require a guest→host registration channel that does not
exist as a first-class thing. Instead the sequence runs entirely host-side,
between two host processes:

1. The client gates the lanes and resolves each bound value (host-side).
2. The client registers `{lane set, bound upstreams, resolved values}` with the
   broker over the broker's control UDS, and receives a token and a handle.
3. The client sends the token to the daemon on **`FinalizeSession`** — not on
   the create RPC, which happens before the gate has decided which lanes exist
   at all, and so before there is anything to register.
4. The daemon injects the endpoint vars into the box.

- **Material.** 32 bytes from `rand::random()` — `rand` 0.10 is a ChaCha CSPRNG
  over `getrandom`, already a workspace dependency — hex-encoded. Not derived
  from the session id: `Uuid::now_v7()` embeds a 48-bit millisecond timestamp
  (`crates/sessions/src/store.rs:775`), the storage short form is 20 bits, and the
  id is already published to users and to `record.json`.
- **At rest, broker side.** Only a `blake3::Hash` of the token. `blake3` is
  already a direct `minimald` dependency and pulls `constant_time_eq`; its `Hash`
  equality is the only constant-time-ish comparison reachable without a new
  dependency. Nothing in the tree calls `ct_eq` and `subtle` is not a workspace
  dep, so a hand-rolled `==` on bytes is what to avoid.
- **At rest, daemon side: nowhere.** The token is held in memory keyed by session
  id and is **never** written to `record.json`, `composition.json`, or any
  sidecar. This is a requirement, not a preference: `build_record` copies every
  `SessionConfig` field onto the `Record`
  (`crates/minimald/src/sessions.rs:69-82`) and `write_record` uses
  `File::create` with no `set_permissions`
  (`crates/sessions/src/store.rs:680-696`), so a token riding `SessionConfig`
  as-is lands at `0644` — the identical property used above to disqualify
  `composition.json`. It travels as a wire-only field on the create request,
  excluded from `build_record`.
- **Scope.** A set of lane names. One box reaching an MCP server and another
  reaching a sink cannot reach each other's upstream.
- **Keyed by an opaque registration handle, and indexed by session id.** The
  handle is the primary key, so two sessions holding the same lane name with
  different credentials never reach each other's. But registration happens at
  *gate* time, after `CreateSession`, so the session id **is** known — and
  indexing by it is what lets a later, separate `min session destroy`
  invocation revoke at all. The activating process holds the handle and exits;
  without the index, revocation would require persisting the handle to disk.
- **TTL.** An absolute expiry, so an abandoned session leaves no live token.
- **Revoke.** From the **client**, over the control UDS, on `min session
  destroy`. Revocation cannot be driven from `ManagerMessage::DeleteSession`
  (`crates/minimald/src/sessions.rs:509-578`) or `SessionMessage::Abort`
  (`crates/minimald/src/session.rs:904-911`) the way an earlier draft of this
  spec had it: those run in `minimald`, which is *guest-side* on DM1/3/4, and the
  broker's control socket is a host filesystem path. That is the same boundary
  error that disqualified guest-side minting.

  The consequence is stated rather than hidden: teardowns the client does not
  drive — a connection-close reap, an aborted create, a killed CLI — do not
  revoke, and are bounded only by the TTL. Shortening the TTL is the lever;
  a guest→host revocation channel is the follow-up (see Known gaps).

The internal CA is **not** the authentication mechanism, despite existing.
`CertAuthority` is real (`crates/minimald/src/net/proxy.rs:345-510`) and
`min login` mints client certs from it — but it sits behind the non-default
`networking-proxy` feature, is regenerated on every daemon start, and
authenticates on CA-signed-cert *presence* rather than CN or SAN
(`proxy.rs:431-439`, `:494-497`). It answers "is a Minimal client", never "is
session X". It cannot scope a credential.

### Delivering the endpoint to the box

**One environment variable per lane**, because the box's software needs a
distinct base URL per lane anyway (`ANTHROPIC_BASE_URL` for one, an MCP server
URL for the other):

| Variable | Value |
|---|---|
| `MINIMAL_CREDENTIAL_ENDPOINT_<LANE>` | `http://<host>:<port>/<lane>` |
| `MINIMAL_CREDENTIAL_TOKEN` | the session's token |

They are layered **above** the composition in `layer_session_env`
(`crates/minimald/src/session_host.rs:1523-1544`), not into `session_baseline_env`
where `MINIMAL_SESSION_NAME` lives. That baseline is the *lowest* layer and
nothing reserves the `MINIMAL_` prefix against the user var lane, so a loadout
declaring `MINIMAL_CREDENTIAL_ENDPOINT_ANTHROPIC = "http://attacker"` would
silently shadow the real one. Layering above, as hook metadata already does
(`crates/minimald/src/hooks.rs:130-131`), makes shadowing impossible.

They never ride `Composition`: anything there is copied into `WireComposition`
and written to `composition.json` (`crates/sessions/src/wire/request.rs:92-108`)
and logged at `debug`.

The token is visible to `env` inside the box. That is unavoidable — every
variable arrives as execve envp and there is no confidential-env mechanism in
this tree — and acceptable precisely because it is a scoped, revocable
capability. What leaks from a compromised box is a handle that dies with the box,
not a key that outlives it.

### The broker's request path

There is **no HTTP server library in any crate's `[dependencies]`** — no hyper,
axum, or tower; they appear only transitively, under tonic and reqwest.
`proxy.rs` hand-parses HTTP/1.1 over a raw `tokio::net::TcpStream`, buffering
only the request head (`MAX_HEAD = 8 KiB`, `HEAD_READ_TIMEOUT = 30 s`,
`crates/minimald/src/net/proxy.rs:44-52`) and then splicing with
`tokio::io::copy_bidirectional` (`:262`). The broker uses that shape, with four
corrections the shape does not supply.

**It terminates and re-originates; it does not tunnel.** The box's leg is
plaintext HTTP/1.1 to loopback. The upstream leg is TLS, originated by the
broker. A rustls stream already splices against `copy_bidirectional` in this file
(`proxy.rs:577` → `:262`), so the streaming property survives verbatim — but that
is *server*-side termination. Client-side origination (a `rustls::ClientConfig`,
a root store, SNI) has **no in-tree precedent**: `grep ClientConfig crates/minimald`
finds nothing, and the workspace `rustls` pin carries
`default-features = false` with no root store
(`Cargo.toml:132-133`). The upstream certificate is verified against the OS trust
store via `rustls-platform-verifier`, added to `[workspace.dependencies]` for
this work and already present in `Cargo.lock` transitively under reqwest, so it
costs no genuinely new crate. Verification failure is a refusal, never a
downgrade. `minvmd` carries none of `rustls`, `tokio-rustls`, `blake3`, or `rand`
today; depending on `credlane` brings them in.

**Lane selection is by leading path segment**, taken from the URL the box was
handed. The broker percent-decodes the remainder, rejects any `.` or `..` segment
in any encoded form, and appends it to the bound `upstream`'s path such that the
result always remains under it. Without that rule, a request for
`/github-mcp/../../v1/admin` would let the box choose an upstream by the back
door — the thing the design forbids.

**The distinction that carries the security argument** is between a box-supplied
*selector* and a box-supplied *upstream*. The selector is permitted and validated
against the token's scope; the upstream is never honoured and comes only from the
binding. `Host:` is rewritten to the upstream's authority.

**Injection is per request, and there is only ever one.** Head-parse-once then
splice injects on request 1 only, and every mainstream HTTP client pools
connections — MCP Streamable HTTP issues `initialize` then
`notifications/initialized` on the same socket — so request 2 would go upstream
bare and 401. The agent's second call would fail. The broker therefore rewrites
the head (strip per below, inject, drop the hop-by-hop set — `Keep-Alive`,
`Proxy-Connection`, `Upgrade`, `TE`, `Trailer`, and every token named in the
inbound `Connection`) and **adds `Connection: close`**. Stripping
`Connection: keep-alive` would be a no-op: HTTP/1.1 is persistent by default. One
upstream connection is opened per client connection and is never pooled across
tokens or lanes. The cost is a fresh TCP+TLS handshake per call, and it is
accepted here in exchange for a guarantee that holds on every request rather than
the first; request-side framing to keep a connection warm is the optimisation to
revisit, not the thing to ship first.

`read_head` cannot be copied as-is: it returns one buffer that may already contain
body bytes and gives the caller no head/body offset (`proxy.rs:303-325` tests for
the marker with `buf.windows(4).any(…)` and never locates it), which works for
`proxy.rs` only because it replays verbatim. A broker that rewrites the head must
write the rewritten head plus the already-buffered body bytes, so the split offset
is part of the contract.

Two more refusals are load-bearing:

- **Inbound header stripping.** The lane's configured header is removed from the
  request before injection — case-insensitively, on every occurrence, not just
  the first — so a box can neither shadow the injected credential nor observe it
  by echoing it back.
- **A distinct token header, removed before forwarding.** The box presents its
  token in `X-Minimal-Credential-Token`, never `Authorization` — the spec's own
  `github-mcp` lane injects into `Authorization`, so reusing it would make the
  token header and the stripped header the same header. The broker removes it
  from the rewritten head, so the box's capability never reaches the upstream.
  Order is: authenticate, remove the token header, strip the lane's header,
  inject.

Unknown lane, out-of-scope lane, malformed selector, and missing or expired token
all produce one identical refusal, so refusals do not enumerate what exists.

The broker cannot identify the caller by source address — gvproxy NATs the
connection to host loopback — so the token is the only identity.

### Rendering it for review

`min box spec` does not exist. There is no `box` noun and no `spec` verb in the
CLI (`crates/minimal/src/lib.rs:49-176`). The closest real surface, and the right
model, is `min session hooks`, which shows "what will actually run, not what was
asked for", answered from the persisted composition snapshot so it survives a
restart (`crates/minimal/src/lib.rs:2573-2625`).

`min session credentials <SESSION> [--json]` is the sibling verb, served by a
`GetSessionCredentials` RPC modelled on `GetSessionHooks`
(`crates/minimald-rpc/src/lib.rs:641-666`). It prints lane name, bound upstream,
injected header, declaring source, and **live/absent state from the broker** —
not a bare snapshot replay, because broker state is in memory and a lane can be
dead while the snapshot still lists it (see Known gaps). There is no value column
at any width and no `--json` field carrying a value; the descriptor that reaches
the composition never contains one.

### The task path

Tasks must not map credentials in from the host. Today they do:
`SetupForPackages::build` keeps `path` and `read_only` and discards `class`
(`crates/graph/src/env_setup.rs:58-71`), so a package's Credential-class mapping
becomes a read-write bind mount of a host file into every task sandbox — no gate,
no provenance, no record.

The fix is to make the task path do what the session path already does: drop
Credential-class entries in both mapping loops, using the tolerant accessor form
(never `.unwrap()`, since a missing `class` must not panic) and warning which
package and path. `CREDENTIAL_CLASS_TAG` moves into `graph` and `composables.rs`
references it, so the two filters share one definition.

Two honest limits:

- **This does not fully close #1204.** The same package's `~/.claude` *State* dir
  mapping still tilde-expands against the guest daemon's `HOME=/` — the
  conversion uses `home_dir().unwrap()` of the ambient process
  (`crates/mfile/src/lib.rs:252-291`) — and dir mappings are validated *before*
  file mappings, so the `EROFS` reappears as
  `create mapped dir I/O error at path /.claude`, which is issue #794. Closing
  #1204 outright additionally requires fixing that expansion.
- **`claude-code` from a task becomes unauthenticated.** That is intended: the
  package asked for plaintext in the box and the answer is now no. Sessions are
  unaffected — they never received it.

## Units of work

> Requirement IDs use the format **R{unit}.{seq}**. Do not renumber after
> approval.

### Unit 1: schema and validation

**Affected:** `crates/mfile/src/lib.rs`, `error.rs`, `fuzz/mfile_from_toml.dict`

- **R1.1**: `Credential { inject: CredentialInject }` and
  `CredentialInject { header: String, #[serde(default)] prefix: String }` are
  defined in `sessions::core::primitives`, not `mfile` — `mfile` depends on
  `sessions` (`crates/mfile/Cargo.toml`), so the types must live where
  `VarValue` and `LifecycleHook` already do or Unit 4 cannot use them. Both carry
  `#[serde(deny_unknown_fields)]` with no `extra`. `mfile::Session` gains
  `#[serde(default)] pub credentials: BTreeMap<String, Credential>` and
  `Session::is_empty`'s exhaustive destructure gains the field.
- **R1.1a**: Lane names are unique per composition. Two sources (a project and a
  loadout, or two loadouts) declaring the same name is a `Conflict`, checked
  post-gate alongside `check_var_mismatches`
  (`crates/sessions/src/core/compose.rs:239-320`) — otherwise two lanes collapse
  onto one env var and the box silently gets whichever merged last.
- **R1.2**: Lane names match `^[a-z0-9][a-z0-9-]*$`. Two lanes whose env-suffix
  mangling (upcase, `-`→`_`) collides are a parse error.
- **R1.3**: `header` must be a non-empty ASCII header token; `prefix` must
  contain no CR or LF. Violations are `Error::InvalidCredential`.
- **R1.4**: The user binding file parses `{ upstream, source }` per lane;
  `upstream` must be `https://`. Plain `http://` is rejected.
- **R1.5**: The fuzz dictionary gains the new tokens; `File::from_toml_bytes`
  must return `Err`, never panic.

### Unit 2: broker process, sockets, and host-side lifetime

**Affected:** `crates/credlane/` (new), `crates/minvmd/`, `crates/minimald/`,
`Cargo.toml`, `scripts/reap-vms.sh`

- **R2.1**: Endpoint derivation per mode: `SwitchSubnet::host_alias()` inside a
  microVM (any mode); `SwitchSubnet::host_alias()` for a native-Linux `own-ip`
  box; `127.0.0.1` for a native-Linux `HostNet` box; `None` for `NoNet`. The
  literal `100.64.255.254` appears in no non-test source.
- **R2.2**: **Two** sockets, distinguished: a box-facing **TCP** listener on the
  owning process's loopback, on a port colliding with neither 7654 nor 7655; and
  a client-facing **control UDS** for registration, at a path both `min` and the
  owning daemon derive from the same shared function, with parent dir `0700` and
  socket `0600`, stale-socket removal refusing to unlink a non-socket.
- **R2.2a**: The control UDS must not resolve under any path bind-mounted into a
  sandbox. `sandbox2` mounts `state_dir` at `/state` and `base_dir/run` at `/run`
  (`crates/sandbox2/src/lib.rs:539-540`) — the latter already carrying the in-box
  `minenv_sock` — so a control socket placed in either is openable by the box,
  which on native-Linux `HostNet` also shares the host netns. A test asserts the
  derived control path is outside both.
- **R2.3**: `minvmd broker` owns the lifetime on DM1/3/4; `minimald broker` on
  DM2 gated `!in_microvm`. Supervision follows `HostGvproxy`'s pidfd
  SIGTERM→SIGKILL or `SwitchClient`'s `kill_on_drop`, not a third pattern.
- **R2.4**: The broker is added to `scripts/reap-vms.sh`'s checkout-scoped rows.

### Unit 3: token mint, scope, and revocation

- **R3.1**: 32 bytes from `rand::random()`, hex-encoded; broker stores only
  `blake3::Hash`, compared as one.
- **R3.2**: A token carries a lane set and an absolute expiry.
- **R3.3**: The **broker** mints, on registration (R5.2), returning a token and
  an opaque registration handle. The daemon holds the token in memory and writes
  it to no file: it is a wire-only field on the create request, excluded from
  `build_record` (`crates/minimald/src/sessions.rs:67-82`, which today copies
  every `SessionConfig` field onto the `Record`).
- **R3.4**: The client revokes over the control UDS: by handle on an activation
  failure it is still holding, and **by session id** from `min session destroy`,
  which is a separate invocation with no handle. Daemon-side teardown paths do
  not revoke — `minimald` is guest-side on DM1/3/4 and cannot reach a host
  filesystem socket — and are bounded by the R3.2 expiry. Tests assert that a
  revoked handle's token is refused, and that destroying a session refuses its
  token afterwards.
- **R3.5**: Unknown lane, out-of-scope lane, malformed selector, and
  missing/expired token produce one identical refusal, and the credential is not
  read from its resolver in any of those cases.

### Unit 4: policy gate and composition plumbing

**Affected:** `crates/sessions/src/core/{policy,compose,hooks}.rs`,
`client/handler.rs`, `daemon/composer.rs`, `wire/*`, `crates/minimal/src/prompt.rs`

- **R4.1**: `UserPolicy` gains `CredentialsPolicy`; `into_parts` widens to a
  4-tuple (the intended compile-break).
- **R4.2**: `PolicyHooks` gains `on_credential_unapproved` defaulting to
  `HookResult::Abort`; `handle_response` gains a fourth gate after hooks.
  `Source::Package` denied outright; `Source::UserLoadout` auto-allows.
- **R4.3**: The daemon's all-decided fast path counts credentials, and
  `has_material` accounts for them (satisfied by R1.1's placement under
  `[session]`, and asserted by test).
- **R4.4**: The wire types gain serde-defaulted credentials fields. A verdict the
  client never mentions is **dropped**, so an old client yields zero lanes.
- **R4.5**: The descriptor reaching `Composition` carries lane name, bound
  upstream, and header only. No type on that path has a value-bearing field.
- **R4.6**: `UnapprovedSummary` gains a credentials list and a
  `[credentials] allow` block; `merge_policy_into_document` upserts three more
  arrays.

### Unit 5: binding, resolvers, registration

- **R5.1**: The user binding lives in user scope; `Resolver` has `env` and `file`
  implementations; `file` refuses a symlinked component.
- **R5.2**: The client resolves values host-side and registers
  `{session, lane set, values, bound upstreams}` with the broker over the control
  UDS, receiving a token. Values never reach the daemon.
- **R5.3**: A declared-but-unbound lane fails activation naming the lane and the
  binding file. A gate-denied lane is absent.
- **R5.4**: A project-declared lane whose name is bound is used with the
  **binding's** upstream. The project has no upstream field to disagree with.

### Unit 6: the request path

- **R6.0**: The upstream connector is a trait with a TLS implementation and a
  plaintext one. Production binds the TLS implementation and R1.4 forbids a
  plaintext `upstream`; the plaintext implementation exists so the behavioural
  tests can drive a hand-rolled `TcpListener` backend, which is otherwise
  incompatible with a mandatory-TLS upstream.
- **R6.1**: Read one bounded head (byte cap and timeout, both stated); rewrite it
  (strip per R6.2, inject, drop hop-by-hop, force `Connection: close`); open a
  fresh upstream connection per client connection, never pooled across tokens or
  lanes; originate TLS and verify the upstream certificate; write the rewritten
  head plus already-buffered body bytes at the stated split offset; then
  `copy_bidirectional`. Responses are never parsed.
- **R6.2**: The lane's configured header is stripped case-insensitively on every
  occurrence before injection, and `X-Minimal-Credential-Token` is removed from
  the rewritten head so the box's capability never reaches the upstream. Order is
  authenticate → remove token header → strip lane header → inject.
- **R6.3**: Lane selection is the leading path segment. The remainder is
  percent-decoded, `.`/`..` in any encoded form rejected, and appended under the
  bound `upstream`'s path. `Host:` is rewritten to the upstream authority. A
  box-supplied upstream is never honoured.

**Proof:** behavioural tests against a hand-rolled `TcpListener` backend (the
`proxy.rs` test pattern): header stripped and replaced; a client issuing two
requests on one socket never gets the second forwarded bare (assert the forwarded
head carries `Connection: close`); SSE chunks arrive incrementally rather than at
end-of-response; `..` traversal in the selector remainder is refused; a request
for a lane outside the token's scope is refused identically to an unknown lane.

### Unit 7: review surface

- **R7.1**: `min session credentials <SESSION> [--json]` renders lane, bound
  upstream, injected header, declaring source, and live/absent broker state.
  Never a value.
- **R7.2**: The policy prompt shows lane, bound upstream, and header before
  approval.

### Unit 8: tasks stop mapping credentials

- **R8.1**: `SetupForPackages::build` drops `class = 'Credential` in both mapping
  loops, warning package and path, with tolerant accessors.
- **R8.2**: `CREDENTIAL_CLASS_TAG` moves to `graph`; `composables.rs` references
  it.
- **R8.3**: `SetupForPackages` records what was dropped.

**Proof:** `env_setup::tests::fs_mappings` inverts — it currently asserts a
Credential mapping *survives* — plus a dir-mapping twin and a `class`-absent case
pinning the fail-open decision.
`credential_class_fs_mappings_are_filtered_out` stays green.

### Unit 9: docs

- **R9.1**: `### [session.credentials.*]` in the schema reference; a
  `[credentials]` category in the policy reference (three sections become four,
  nine rule arrays become twelve); a guide page on giving an agent an outbound
  credential; a `min session credentials` entry in the CLI reference.

## Testing

Schema and validation are unit-tested in `mfile`: round-trip, unknown-key
rejection, the lane-name grammar, env-suffix collision, the `https://`
requirement, and each header/prefix refusal. The fuzz target must not panic on a
credentials-bearing input.

Policy is unit-tested against the `hooks` gate's tests as the model: allow, deny,
ignore, undecided-reaches-prompt, package-denied, loadout-auto-allowed, and the
`--no-prompt` snippet's exact text. A daemon-side test asserts a project whose
only declaration is `[session.credentials]` produces a composable and faces the
gate — `has_material`'s short-circuit is the regression to pin, and it is not
reachable from `crates/sessions/tests/client_flow*.rs`, which never exercise
`build_composables`.

Broker behaviour is tested against a hand-rolled `tokio::net::TcpListener`
backend, the pattern `proxy.rs`'s own tests use; there is no HTTP mocking library
in the workspace and this spec does not add one. Behavioural assertions: expiry
(`#[tokio::test(start_paused = true)]`); a token scoped to lane A refused for
lane B with the same response as an unknown lane; the injected header stripped
and replaced on every occurrence; a second request on one socket never forwarded
bare; a response body arriving incrementally, proving SSE is not buffered; `..`
traversal refused; upstream certificate verification failure refused rather than
downgraded.

End-to-end, the only way anything is asserted true *inside* a box is
`min session exec <sid> '<command>'` from `scripts/session-e2e.sh`, which is how
the acceptance assertions are written: the upstream reached **through** the lane
returns a successful `initialize` while the same upstream reached **directly**
returns `401`; and inside the box no credential value appears in `env`, nor in
`composition.json` or `record.json` on disk. The through-the-lane assertion must
issue **two** requests on one connection, or it cannot see the defect that
`Connection: close` exists to prevent. On VM lanes the daemon logs to a guest
tmpfs, so log-reading assertions are native-lane only.

## Threat model

| Threat | Mitigation | Notes |
|---|---|---|
| A project retargets a bound lane at an attacker-controlled host | The project has no `upstream` field; the binding is the sole authority on destination | The reason the schema splits this way; the gate is path-keyed, so an already-allowed project would otherwise clear it silently |
| A project points a lane at a host file it should not read | The project cannot name a source either | Both halves of the binding are the user's |
| The secret crosses the network in cleartext | `upstream` must be `https://`; the broker originates TLS and verifies the upstream certificate, refusing on failure | Rejected at parse, not at request time |
| A box reaches a credentialed upstream it was not granted | The token authorises a lane set; selection is a validated path segment checked against that set; the upstream comes only from the binding | Box-supplied *selector* is permitted and validated; box-supplied *upstream* is never honoured |
| A box escapes the granted path scope via traversal | The selector remainder is percent-decoded, `.`/`..` rejected in any encoded form, and constrained to remain under the bound upstream's path | Otherwise `/lane/../../v1/admin` is an upstream choice by the back door |
| A box shadows or observes the injected credential | The lane's header is stripped case-insensitively on every occurrence before injection; the token travels in a distinct header | Reusing `Authorization` would collide with the `github-mcp` lane's own injection |
| Requests after the first on a pooled connection go upstream unauthenticated | The rewritten head forces `Connection: close`; one upstream connection per client connection, never pooled across tokens or lanes | The primary workload — MCP Streamable HTTP — pools by default, so this is a correctness property before it is a security one |
| The credential is read out of the box's environment | The credential is never in the box; only a scoped, revocable token is | Every var reaches a box as execve envp; there is no confidential-env mechanism in this tree |
| A loadout shadows the endpoint or token to redirect a lane | Lane vars are layered *above* the composition, as hook metadata is | Nothing reserves the `MINIMAL_` prefix against the user var lane |
| The token is persisted to disk | It rides neither `Composition` nor `Record`; it is a wire-only field held in daemon memory | `record.json` and `composition.json` are both `0644`; the first draft of this spec disqualified one and then chose the other |
| A token outlives its box | Revoked at `DeleteSession` *and* `Abort`, plus an absolute expiry | `Abort` bypasses `delete_session` entirely |
| A token is guessed or replayed | 32 CSPRNG bytes, stored and compared as a `blake3::Hash` | The broker cannot identify a caller by source address — gvproxy NATs the connection — so the token is the only identity |
| Refusals enumerate what exists | Unknown lane, out-of-scope lane, malformed selector, and missing/expired token are one identical response | |
| Another local process reaches the broker | The token is required regardless of transport | On native-Linux `HostNet` the box shares the host netns and can already reach every loopback service; loopback is not a boundary there and the design does not pretend it is |
| A box opens the broker's control UDS and registers its own lane, or reads a resolved value | The control socket is placed outside every path bind-mounted into a sandbox (R2.2a) and is `0600` | `/state` and `/run` *are* mounted in (`crates/sandbox2/src/lib.rs:539-540`), and `/run` already carries `minenv_sock`. Registration itself carries no token — filesystem placement and mode are the *entire* control, which is why R2.2a is a requirement with a test and not a note |
| The broker forwards the box's capability token to the upstream | `X-Minimal-Credential-Token` is removed from the rewritten head (R6.2) | Without this every upstream is handed a live credential-lane token |

The lane narrows what a compromised box yields from a long-lived key to a
short-lived, scoped, revocable handle. It does not stop a box that legitimately
holds a lane from *using* it: an agent that can call the API can call it for
anything the API allows. Approval remains the user's judgement about the project,
exactly as for hooks.

## Known gaps

- **Only the client can revoke.** `minimald` is guest-side on DM1/3/4 and cannot
  reach the broker's control socket, so daemon-driven teardowns (connection-close
  reap, aborted create, killed CLI) leave a token live until its TTL. A
  guest→host revocation channel — plausibly the broker exposing an authenticated
  control verb on the switch-facing listener the guest daemon can already reach —
  is the follow-up.
- **Broker state is in memory and dies with its supervisor, but sessions
  survive.** A restarted VM or daemon leaves every live lane dead; `min session
  credentials` reports it (R7.1) but nothing re-registers automatically, and a
  re-attach after a restart has no token. A re-registration path is the obvious
  follow-up and is deliberately not designed here.
- **Package-declared credentials.** `class = 'Credential` stays dropped on both
  paths. Teaching the extractor to emit a lane — so a package can say "I need an
  Anthropic credential" without saying where plaintext lands — is the natural
  follow-up and the reason `SetupForPackages` records what it dropped (R8.3).
- **Rotation.** No renewal; `AttachEnv` is captured only at the launching attach
  (`crates/minimald/src/session_host.rs:1425-1450`), so a re-attach cannot refresh
  a running shell's environment. Rotating the *upstream* secret is picked up on
  the next resolution, untested here.
- **`Connection: close` costs a handshake per call.** Request-side framing with a
  warm upstream connection is the optimisation; it needs `Content-Length` /
  `Transfer-Encoding` awareness on the request side only, and is not in this pass.
- **#1204 is not closed by Unit 8 alone** — the `~`-expansion against the ambient
  `HOME` (`crates/mfile/src/lib.rs:254`) still strands the State-class dir
  mapping; that is #794.
- **Tasks get no lanes.** The task path consults no policy plane.
- **`min dash` cannot gate** — the TUI bails on a `Pending` response, so a
  project whose lanes are undecided cannot be started from the dash until a rule
  exists.
- **`NoNet` boxes get no lane**, and nothing tells the user why beyond absence.
- **`composition.json` is `0644`.** The lane descriptor publishes bound upstream
  URLs and header names to any local reader. Hardening the sidecar is a behaviour
  change for existing sessions and is not bundled here.
- **The token crosses plaintext HTTP** inside the switch. Anything already on the
  box's network path can read it; mTLS from the box would need a per-session
  identity the internal CA does not provide.
- **`own-ip` is hidden** behind a comment claiming no install ships a switch
  binary, while `stage-release.sh` stages `gvproxy-min` for all three platforms.
  One is stale; the native-Linux reachability story depends on which.
