# What "provider" means in the source today

The starting point for the refactor BPA-013 asks for, read from `gominimal/minimal`
at `c664f786`. Nothing here is a Box Provider in this spec's sense: there is no
`BoxProvider` type, no provider API, and no `min provider` or `min host` command.
The word is used for two unrelated things, and a third mechanism does the job a
provider would do without being called one.

## 1. A backend selector

`--provider` is a global CLI flag with two values, documented in source as
*"Which daemon backend (\"provider\") hosts sessions"* — the scare quotes are
theirs.

| | |
|---|---|
| `crates/minimal/src/cli.rs` | `enum Provider { LocalMinimald, LocalMinvmd }`, and `--provider` as a `global = true` arg |
| Values | `local-minimald` (minimald on the host, the Linux default) and `local-minvmd` (minimald inside the microVM) |
| Platform | No effect on macOS, where minvmd is the only backend |

Two values, not three, and both local. BPA-013's targets are `local-minvmd`,
`local` and `local-box` — three providers, no instance suffix. The `0..N` the
shipped state directory carries moves to **hosts**, so `local-minvmd0`'s VMs
become hosts of `local-minvmd`; BCLI-046 carries that mapping with a one-release
alias.

## 2. A state-directory naming convention

| | |
|---|---|
| `crates/paths/src/lib.rs` | `enum ProviderKind { Minimald, Minvmd }` with `tag()` → `"minimald"` / `"minvmd"` |
| | `provider_instance_name(kind, instance)` → `format!("local-{tag}{instance}")` |
| | `provider_instance_dir(...)` → `<state_dir>/providers/local-<tag><instance>` |
| | `provider_instance_dir_named(...)` nests a named VM under that |
| `crates/minvmd/src/state.rs` | `provider_dir()` → `<state>/providers/local-minvmd0[/<vm>/]` |
| `crates/minvmd/src/sock.rs` | the SSH socket at `<provider dir>/ssh.sock` |

So `local-minvmd0` already exists as a string, and the `local-<tag><instance>`
shape already exists as a function. It names a directory holding sockets and
locks; it is not an addressable entity and nothing enumerates it.

## 3. Socket probing, which does a provider's job

`crates/minimal-tui/src/rpc.rs` is the closest thing to BPA-005's inventory. Its
`Provider` is *"a reachable daemon the TUI lists sessions from"* — a sidebar
label, an SSH socket path, and a client. `probe_candidates()` builds an ordered
probe list: the host daemon's socket, plus one per VM including every named VM's
own directory, deduplicated by path.

This matters to the refactor more than the other two. The dash already
aggregates across several local daemons, already tolerates one being
unreachable (the group stays in the sidebar with its sessions cleared), and
already dedupes two labels resolving to one socket. That behaviour is what
BPA-005 and BPA-015 would be reimplemented over, so it is the first consumer the
refactor has to keep working.

## What the client talks to a daemon over

`crates/minimald-rpc` — *"Wire contract for minimald's oneshot SSH RPCs"* —
holds the subsystem names, payload types and the `OneshotSshRpc` trait, with no
transport dependency so clients and tests encode through the same types. Under
this spec that channel becomes provider-internal for the operations the API defines:
it is how the client reaches one host, below the Box Provider API rather than beside
it. It stays in the client for `local` and `local-minvmd`, because there is one
minvmd per VM and one minimald per native host and nothing spans either set — §3's
probe loop above is already the shape the composed provider needs, and `min` is the
only party that knows the whole set. For `local-box` the parent minimald answers
whole, over the socket projected into the box. Stopping a daemon stays a client
action either way — `min host stop` has no call in the API, by its §1.

## Not present

- No `BoxProvider` or `box_provider` anywhere (0 occurrences across 347 Rust files)
- No Box Provider List, in config or in code
- No `min provider` or `min host` command; shipped top-level commands are
  `ls stop session loadout task net run dirs bug diag mesh proxy login init add
  update version spin dash completions`
- No `box` noun — `session` (`list activate attach exec run destroy rename
  policy`) and `task` are the surface, which the local-first box spec changes
- No remote provider of any kind. `crates/remote-proto` and
  `crates/remote-client` are the Remote Execution Service, a build-caching
  concern unrelated to box providers

## Staleness

This is a snapshot for orientation, not a binding part of the spec. The
local-first box spec and its CLI sibling change the command surface, and the
refactor changes all of §1 to §3. Re-read the source rather than trusting this
once either has landed.
