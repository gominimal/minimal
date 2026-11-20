---
title: min CLI
description: "Reference for the min session CLI: create, attach to, and manage sandboxed development sessions, plus the git-remote-min helper."
---

# `min` - session CLI

`min` is the Minimal session CLI. It talks to the `minimald` daemon (see
[minimald](./cli-minimald.md)) to create, attach to, and manage sandboxed
development sessions. Most commands start the daemon automatically when it
is not running, with `bug`, `host stop`, and `version` being the exceptions. On
macOS the daemon starts inside the [`minvmd`](./cli-minvmd.md) microVM host
daemon. On Linux the provider decides where it starts, as
[Choosing the provider on Linux](#choosing-the-provider-on-linux) describes.
Running bare `min` with no subcommand routes you into a session when stdin
and stdout are both a terminal: it follows the smart-resolution rules of
`min session attach` with no argument (cwd match → attach, only session →
attach, ambiguity → picker), and when no sessions exist it creates one from
the current directory and attaches. Without a terminal it instead prints a
read-only state report on stderr and exits successfully. Use `min --help` to print this
help.

Commands are spelled `min <noun> <verb>`, and every noun accepts its singular
and plural form (`session`/`sessions`, `loadout`/`loadouts`). A handful of
bare verbs (`ls`,
`init`, `add`, `update`) survive at the top level as deliberate ergonomic
exceptions, called out as such below; see
[the CLI convention](./cli.md#command-naming-convention) for the rule and the
full list of exceptions.

## Global flags

These apply to every subcommand.

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use the given directory as the repository root, instead of the current working directory |
| `--minimal-dir <PATH>` | | Override the base directory for minimal's state; the session store, provider instances, and other on-disk state live under `<minimal_dir>/`. Defaults to `$XDG_STATE_HOME/minimal` on Linux (or `$HOME/.local/state/minimal`); macOS also uses `$HOME/.local/state/minimal` |
| `--config-dir <PATH>` | | Override the user config directory; everything under `<config_dir>/minimal/` (`config.toml`, `loadouts/`, ...) resolves relative to it. Defaults to `$XDG_CONFIG_HOME` on Linux (or `$HOME/.config`); macOS also uses `$HOME/.config` |
| `--provider <PROVIDER>` | | Daemon backend that hosts sessions: `local` (`minimald` natively on the host) or `local-minvmd` (`minimald` inside the `minvmd` microVM). Without the flag, Linux uses `MIN_PROVIDER`, then the `provider` key of `config.toml`, then `local-minvmd` where `/dev/kvm` opens for you and `local` where it does not. No effect on macOS, where `minvmd` is the only backend |
| `--no-input` | | Skip interactive prompts that need a terminal (such as the session picker); ambiguous choices error with a list of candidates instead. Implied when stdin/stdout is not a terminal |

### Choosing the provider on Linux

A command without `--provider` chooses the provider in this order:

1. The `MIN_PROVIDER` environment variable, set to `local` or
   `local-minvmd`.
2. The `provider` key of your `config.toml` (run `min dirs` to find the
   file). It is a top-level key, so it goes before the first table:

   ```toml
   provider = "local"
   ```

3. `local-minvmd`, when `/dev/kvm` opens for reading and writing for you
   and answers the KVM API version request.
4. `local`, otherwise.

`--provider` wins over all of them. A host where `/dev/kvm` is there but does
not open for you stays on `local` until you join the `kvm` group.
`min finalize-install` offers that step. It takes effect at your next login.

Each provider keeps its own boxes. Boxes you started on the native provider
before `local-minvmd` became your default stay there: `min --provider local
ls` lists them. To keep the native provider as your default, set
`MIN_PROVIDER=local` or put `provider = "local"` in `config.toml`.

A command can reach `local-minvmd` only because `/dev/kvm` opens. If the
native provider then still has boxes or a running daemon, the command prints
a note on stderr after it ends. The note names both ways back above, and it
stops once `--provider`, `MIN_PROVIDER` or the `provider` key names the
provider.

A VM that fails to start under this default gives an error with one more
line. That line says `min` used the VM because `/dev/kvm` opens, and that
`MIN_PROVIDER=local` keeps the native provider.

## Errors in JSON output

A command that runs with `-o json` or `-o jsonl` and fails writes one JSON
object on stderr, on one line, in place of the plain-text error. Nothing
else goes to stderr for that failure. The command still exits non-zero.

```json
{"schema":"min/v1/error","code":"not_found","message":"no box matches 'web'","hint":"..."}
```

| Field | Description |
|-------|-------------|
| `schema` | Always `min/v1/error` |
| `code` | The kind of failure, from the table below. Branch on this field in a script |
| `message` | The same error text that the command prints without `-o` |
| `hint` | One line that names the next step, or an empty string when there is none |

| `code` | Exit code | When the command gives it |
|--------|-----------|---------------------------|
| `ambiguous` | 2 | A box name or id prefix matches more than one box |
| `not_found` | 4 | No box matches the box name or id, the box is on a VM that is stopped, or `min type show` names no box type. When `min box show --network -o json` finds no box, the exit code is 1 |
| `host_unreachable` | 7 | A host that the command must ask does not answer |
| `insufficient_resources` | 8 | The VM host has no network address left for another box |
| `github_sign_in_required` | 3 | The box spec needs a GitHub sign-in, and you are not signed in. Run `min auth login` |
| `gatehouse_unenrolled_node` | 5 | The box spec asks for a grant that this host cannot give, because the host is not enrolled |
| `audit_self_unsupported_unenrolled` | 1 | `min box audit self` inside a box on a host that is not enrolled. On the host, run `min box audit <box>` |
| `timeout` | 124 | A box ran past its own timeout, or `min box exec --timeout` ended the command |
| `wait_timeout` | 124 | `min box wait --timeout` ran out before the box ended |
| `policy_unavailable` | 1 | The command found the box but did not read its network policy |
| `output_failed` | 1 | The command did not write its JSON output to stdout, for example on a full disk |
| `unspecified` | 1, or the exit code of the failure | Any other failure. The exit code is the one the command gives without `-o` |

A command line that `min` cannot parse, such as an unknown flag, exits 2
before the command runs. The error is plain text, not a JSON object. When
the reader of stdout closes it early, the command exits 141 and writes no
object.

## Commands

### `ls`

```
min ls [--raw] [--json]
```

Lists sessions. `--raw` prints raw session IDs one per line for piping
into scripts; `--json` prints the full session list as pretty-printed
JSON. When the daemon reports a shared resource pool, the table is headed
by a `RESOURCE POOL:` line (CPU cores, memory, and the number of sessions
sharing them); `--raw` omits it.

The table has the columns `SESSION ID`, `NAME`, `ADDRESS`, `STATUS`,
`EGRESS`, `TITLE`, `LAST ACTIVITY` and `PROJECT PATH`. `ADDRESS` is the
host loopback address where the box's ports answer. A box with an address of
its own shows that address. A box at the shared fallback shows `127.0.0.1`.
The column shows `-` when the daemon does not report an address. An older
daemon does not report it.

`EGRESS` is the box's egress posture:

| `EGRESS` | `egress_posture` in `--json` | Meaning |
|---|---|---|
| `deny-all (default)` | `deny_all_default` | The box does not declare egress, and the default denies every external address |
| `allow-all (default)` | `allow_all_default` | The box does not declare egress, and the default allows every address: the operator opt-out, or a box without an address of its own |
| `deny-all` | `deny_all` | The box declares egress that admits nothing |
| `declared rules` | `declared_rules` | The box declares egress rules of its own. `min box show <box> --network` prints them |
| `no network` | `no_network` | A `--network none` box. It has no network, so no egress posture applies |

A host-address box on a host that cannot decide egress per box adds
`; per-box enforcement none` to the posture. The column shows `-` when the
daemon does not report a posture.

With `--json`, each session entry has the address under `loopback_address`
and the posture under `egress_posture`. The entry omits a key when the daemon
does not report that value.

Another box at the same shared loopback address can hold a port this box
declares, and this box does not forward it. The list prints one stderr line
per such port after the table:
`warning: <session>: port <p> is held by <box>; not forwarded`.
With `--json` the entry lists those ports under `shared_port_collisions`,
each with `port` and `held_by`, and the key is absent when there are none.

`min ls` stays bare at the top level. It is a deliberate exception to the
`min <noun> <verb>` convention, because it is the highest-traffic command in
the CLI and scripts read its `--raw` output. It is not an alias of
`min session list`.

### `session list` (alias: `min session ls`)

```
min session list [--all] [-o json]
```

Lists the session boxes of the current project, in any state. It is
`min box list` limited to session boxes, with the same columns and the same
flags. It does not take `--raw` or `--json`. Use `min ls` for those.

| Flag | Short | Description |
|------|-------|-------------|
| `--all` | | List the session boxes of every project |
| `--output json` | `-o` | Write the boxes as one JSON array, and nothing else |

### `dash`

```text
min dash
```

Opens a full-screen TUI for browsing, inspecting, and managing sessions
across every running provider on the host (native minimald and the minvmd
microVM). The left pane lists sessions grouped by provider; the right pane
stacks the focused session's Info, networking Policy, and a read-only live
Preview of its terminal screen (no attach, no PTY resize). Requires a
terminal.

Keys: `↑`/`↓` (or `k`/`j`) move, `/` fuzzy-filters by name, ID, and
project path, `enter` attaches to the focused session (suspend TUI → ssh →
resume on `ctrl-]` then `d` detach) or collapses a provider group, `d` destroys
(with confirmation — also cancels an in-flight create/upload), `r`
renames, `n` creates a session through the full activate flow (project
upload, loadout compose, finalize), `q` quits. The cursor's last position
is restored on the next launch from `<state>/dash-state.json`; TUI
diagnostics go to `<state>/dash.log`.

### `session start`

```
min session start [OPTIONS] [ENTRY]
```

Creates a box from a session entry in the project's `minimal.toml`, and
attaches this terminal to it. `ENTRY` names a `[sessions.<name>]` entry, or a
`[boxes.<name>]` entry with `type = "session"`.

| Argument or flag | Description |
|------------------|-------------|
| `ENTRY` | The session entry to start. Optional |
| `--name <NAME>` | Name the box. With `--new`, the box is named `<NAME>-<n>` |
| `--new` | Create another box from the entry, named `<name>-<n>`, even when a running box holds the entry's name |
| `--detach` | Create the box, print its id and return. This terminal is not attached to the box |
| `--network <none\|host_ip\|own_ip>` | Override of the entry's `network.mode`: the box gets this network mode. Without the flag, the box takes the entry's `network.mode`, else `host_ip`. The old hyphenated spellings `no-net`, `host-net`, and `own-ip` still work for one release, with a one-line hint naming the current spelling |
| `--ingress <EXT:INT[/PROTO]>` | Override of the entry's `network.ingress`: each use adds one port mapping, `EXT:INT[/PROTO]` (PROTO = tcp or udp, default tcp). Requires `--network own_ip` |
| `--allow-subnets <CIDR>` | Destination subnet the box may reach, in CIDR form (e.g. `10.0.0.0/8`). Repeatable. Adds to the `allow_subnets` that `minimal.toml` declares. Inside a declaration, an unset flag grants nothing once the daemon resolves the policy: write allow-all out as `0.0.0.0/0` and `::/0`. Boxes have no IPv6 path yet, so `::/0` is the forward-compatible spelling and grants nothing today. The opt-out below keeps the old allow-all meaning of an unset flag. An own-address (`--network own_ip`) or host-address (`--network host_ip`) box accepts the rule flags, and only an own-address box enforces them. A host that decides egress per box refuses to create a host-address box that carries them. Any other host runs that box with the rules unenforced. A `--network none` box rejects the whole egress declaration |
| `--allow-dns-hosts <HOST>` | Destination DNS hostname the box may resolve and reach (e.g. `github.com`). Repeatable. Adds to the `allow_dns_hosts` that `minimal.toml` declares. Inside a declaration, an unset flag grants nothing once the daemon resolves the policy. The opt-out below keeps the old allow-all meaning of an unset flag |
| `--allow-protocols <PROTO>` | Outbound transport protocol the box may use: `tcp`, `udp`, or `icmp`. Repeatable. Unset lets every protocol through: the flag filters the reach the two allow lists grant. Replaces the `allow_protocols` that `minimal.toml` declares |
| `--deny-subnets <CIDR>` | Destination subnet the box may not reach, in CIDR form — subtracted from what the allow flags admit. Repeatable; unset means nothing is denied. Adds to the `deny_subnets` that `minimal.toml` declares, so it never drops a range the file denies. A declaration with only deny flags admits nothing: there is no allow list to subtract from. Add `--allow-subnets 0.0.0.0/0 --allow-subnets ::/0` to deny a range out of allow-all |
| `--deny-all-egress` | Declare deny-all egress: the box reaches no external address. Drops every `allow_subnets` and `allow_dns_hosts` value that `minimal.toml` declares. The file's `allow_protocols` and `deny_subnets` stay. With no `allow_protocols` from the file or `--allow-protocols`, it writes the deny-all `egress` section, every allow list present and empty. Combines with `--deny-subnets` and `--allow-protocols`, which only narrow, and conflicts with `--allow-subnets` and `--allow-dns-hosts`. A box declared by flag reads in the record exactly like one whose `minimal.toml` carries the section. On a host-address box the host's classifier decides a declared deny-all per box. An own-address box gets deny-all by default when it does not declare egress by flag or in its `minimal.toml` (see below) |
| `--dynamic-ingress <allow\|ask\|deny>` | Override of the entry's `network.dynamic_ingress`. It sets the stance that decides the box's own requests to publish a port (`min net expose`, or a listen inside `--dynamic-range`). `allow` publishes them. `ask` asks the attached person about a `min net expose`. With nobody attached, `ask` refuses the request at once. `ask` never publishes a listen. `deny` refuses every one, the same as leaving the flag unset. Setting it declares ingress even with no `--ingress` mapping. Requires `--network own_ip`. On a VM-backed host the create registers the stance and range with the VM host daemon. That daemon admits each publish the box requests against that grant. It admits an `ask` publish only on a yes the host records. Every macOS host is VM-backed |
| `--dynamic-range <LO-HI>` | Override of the port range in the entry's `network.ingress`: the inclusive host port range, such as `8000-8443`, inside which `--dynamic-ingress allow` publishes. A port outside it gets the out-of-range refusal. Requires `--dynamic-ingress`. Setting it declares ingress even with no `--ingress` mapping. The flag refuses a range that starts below 1024, a privileged port |
| `--credentialed-upstream` | Declare a credentialed upstream for the box, so the box can reach the Box Egress Proxy. Without the flag, the box has one only when `minimal.toml` grants it a secret through the proxy |
| `--quic443 <auto\|block\|allow>` | Override of the entry's `network.quic443`: whether the box can send UDP to port 443, the traffic of HTTP/3. `block` always blocks it, `allow` always allows it, and `auto` blocks it only when the box has a credentialed upstream |
| `--vpn-network-names <NAME>` | Adds a name to the box's `network.vpn_network_names`. Repeatable. The box keeps the names, but `minimald` does not connect the box to a VPN yet |
| `--loadout <NAME>` | Apply the named loadout. Repeatable. With any `--loadout`, the config file's `default_loadouts` are not applied |
| `--no-loadouts` | Apply no loadouts, and not the config file's `default_loadouts` either. Cannot be combined with `--loadout` |
| `--no-hooks` | Run none of the box's [lifecycle hooks](./loadouts.md#lifecycle_hooks---scripts-at-session-transition-points), from the loadouts or from `minimal.toml`. The box keeps hooks off, so the choice also holds when the box is attached or detached, and when it ends |

Each override flag changes only the key it names. The other
`network.egress` keys of the entry stay as the entry declares them. With no
`--network`, the box takes the entry's `network.mode`, else `host_ip`. A
session box takes the entry's `network.ingress`, a list such as
`[{ port = 8080 }]` or `[{ external_port = 8080, internal_port = 80, proto = "tcp" }]`.
Each `--ingress` adds one mapping after the entry's mappings.
Ingress needs an `own_ip` box, so a start refuses `network.ingress` on any
other mode. The box keeps the
result: `min box show <box> --network` prints the network policy in force
for the box.

`min box start [ENTRY]` takes the same flags. For a task entry, it takes
every flag in the table except `--ingress` and `--loadout`. A task entry refuses
`--ingress` and `--loadout` with exit code 2.

`min task run <task>` and `min box run <entry>` take the same flags as a
task entry's start: `--network`, the egress flags, `--dynamic-ingress`,
`--dynamic-range`, `--credentialed-upstream`, `--quic443`,
`--vpn-network-names`, `--no-loadouts` and `--no-hooks`. Put them before the task's first argument.

Without `ENTRY`, the command starts the session entry named `default`. When
no session entry has that name, it starts the project's only session entry. A
project with no session entry and no entry named `default` gets a `default`
session entry with no settings of its own. A project with no `minimal.toml`
gets that entry too.

The command refuses these starts before it creates a box:

| Refusal | Exit code |
|---------|-----------|
| `ENTRY` names no entry in `minimal.toml` | 4 |
| `ENTRY` names an entry that is not a session entry | 4 |
| `ENTRY` names a session entry other than `default`. The command cannot start one by name yet | 2 |
| Without `ENTRY`: several session entries, and none of them is named `default` | 2 |
| Without `ENTRY`: no session entry, and an entry of another type is named `default` | 2 |
| An entry in `minimal.toml` has a type that is not built in, or a `[boxes.<name>]` entry has no `type`. The command refuses only when `ENTRY` names that entry, or when the start must count the entries to pick one | 2 |
| No terminal, and no `--detach` | 2 |
| `--no-loadouts` and `--loadout` together | 2 |
| A running box holds the box's name. Pass `--new` or `--name` to create the box | 2 |

An invalid `minimal.toml` ends the command with exit code 3.

#### Egress flags

Together the four `--allow-*`/`--deny-*` rule flags form the box's `egress`
declaration. Naming one of them stores it on the box, and
`min box show <box> --network` shows what the box ended up with. The flags apply to the
`network.egress` keys that `minimal.toml` declares for the box: a list flag
adds its values to the file's list, and `--allow-protocols` replaces it.
`--deny-all-egress` can only narrow, so it cannot combine with
`--allow-subnets` or `--allow-dns-hosts`.

An unset `--allow-subnets` or `--allow-dns-hosts` inside a declaration
grants nothing, whatever the box's network mode. This changes
what a declaration with no allow list does. `--allow-dns-hosts github.com`
alone reaches `github.com` and no address directly. `--deny-subnets` alone
reaches nothing. Both used to reach every address the deny left, and the
operator opt-out named below restores that earlier meaning. An
own-address box (`--network own_ip`) gets the deny-all default when it does
not declare egress by these flags or in the project's `minimal.toml`. It
then reaches no external address. It can still resolve names in the box zone,
`host.min.internal` included. `min session start` prints one line saying so:

```
This box can reach no external address: a --network own_ip box with no egress rules gets the deny-all default. To allow outbound traffic, activate a new session with --allow-subnets or --allow-dns-hosts, for example --allow-dns-hosts github.com.
```

To give such a box reach, declare it with the allow flags, such as
`--allow-dns-hosts github.com` or `--allow-subnets 0.0.0.0/0`. To keep the earlier allow-all default for
every undeclared box on a host, the operator opts out. A native Linux host
opts out with `minimald run --egress-deny-all-opt-out`, or with
`MINIMALD_EGRESS_DENY_ALL_OPT_OUT=1` in the environment that starts
`minimald`. `min` starts the daemon without the flag when it is not running,
so export the variable to keep the opt-out after such a restart (see
[minimald](./cli-minimald.md)). A VM-backed host opts out with
`MINVMD_EGRESS_DENY_ALL_OPT_OUT=1` in the environment that starts `minvmd`
(see [minvmd](./cli-minvmd.md)). A host-address box with no section
keeps allow-all either way.

The opt-out also keeps the earlier meaning of an unset allow flag inside a
declaration. On an opted-out host, `--allow-dns-hosts github.com` alone keeps
allow-all addresses: the box reaches every address directly, and the names
bound nothing. The start does not warn about it. Add `--allow-subnets` to
bound the addresses there.

Known issue: own-address boxes take their addresses from 100.64.0.0/16,
a block inside 100.64.0.0/10. Some VPNs, such as Tailscale, use addresses in
100.64.0.0/10. While such a VPN is up, a box's connections to addresses the
VPN routes in 100.64.0.0/16 can fail. No setting changes the range a box uses.

### `session attach`

```
min session attach [SESSION]
```

Attaches to an existing session, identified by UUID, unique id prefix, or
session name. An exact session name wins over an id prefix. A prefix that
matches more than one session fails with an error that names the candidates.
When `SESSION` is omitted, `min session attach` resolves a session from the
current working directory (or the only existing session) and opens an
interactive picker if the choice is ambiguous (`--no-input` errors instead).

`min session attach` exits 0 when you detach or the session's shell exits.
It prints a one-line notice and exits 254 when the daemon ends the attach.
That happens when someone destroys the session, another connection attaches
to it, or the daemon shuts down. It exits 255 when the connection fails, or
when the daemon disconnects a terminal that stopped keeping up with output.

`min session attach`, `min box attach` and bare `min` exit 1 when the daemon
refuses the attach. The reason stays on screen. One example is a session
that still receives its workspace upload. Another is an `own_ip` box that
cannot get its address back. The reason then names the command that checks
the setup, such as `min finalize-install --show`.

### `session logs`

```
min session logs [-f|--follow] [--raw] <BOX>
```

Shows what a session box's terminal printed, from its start. It is
`min box logs` for a session box. `BOX` is the box's id, the start of its id,
or its name, as `min session list` prints them.

| Flag | Short | Description |
|------|-------|-------------|
| `--follow` | `-f` | Show the output so far, then keep showing new output, until the box is removed or the command is interrupted |
| `--raw` | | Write the output byte for byte, with its terminal control codes. Without `--raw`, the command removes those codes when stdout is not a terminal |

### `session stop`

```
min session stop [--force | --exec <EXEC_ID>] <BOX>
```

Stops a running session box and keeps it. It is `min box stop` for a session
box, with the same flags.

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Kill every process in the box at once, with no grace period |
| `--exec <EXEC_ID>` | | Stop only one command, by the exec id that `min box exec` printed for it. The box keeps running. Cannot be combined with `--force` |

### `session rm`

```
min session rm [--force] <BOX>
```

Removes a stopped or exited session box. It is `min box rm` for a session
box. The command refuses a running box unless you give `--force`.

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Stop a running box at once, then remove it |

### `task run`

```
min task run [OPTIONS] <TASK> [ARGS]...
```

Runs a task that the project's `minimal.toml` declares, in a box of its own
named `<TASK>-<n>`. The command exits with the task's exit code. The task
runs without a terminal. A piped or redirected stdin goes to the task. The
task's stdout is the command's stdout, and the command prints its own lines
on stderr. `ARGS` go to the task's declared `args`. Put the command's flags
before the first task argument. A task argument with the name of a flag goes
after `--`.

When the task ends, the box stays with its exit code. `min box show
<TASK>-<n>` shows it, and `min box rm <TASK>-<n>` removes it. Ctrl-C stops
the box as `min box stop` does, and the command exits 130. For a task
declared with `interactive = true`, Ctrl-C removes the box.

| Flag | Short | Description |
|------|-------|-------------|
| `--detach` | | Start the box, print its id and return. The task gets no input |
| `--network <none\|host_ip\|own_ip>` | | The network mode of the task box. Without the flag, the box takes the task's `network.mode`, else `host_ip` |

The command also takes these flags of
[`session start`](#session-start): `--allow-subnets`, `--allow-dns-hosts`,
`--allow-protocols`, `--deny-subnets`, `--deny-all-egress`,
`--dynamic-ingress`, `--dynamic-range`, `--credentialed-upstream`,
`--quic443`, `--vpn-network-names`, `--no-loadouts` and `--no-hooks`. To run
a task of another project, give `--repo-dir <DIR>` (short `-C`).

### `task list`

```
min task list [--all] [-o json]
```

Lists the task boxes of the current project, in any state. It is
`min box list` for task boxes, with the same columns and flags. A task that
ended shows its exit code, such as `exited (exit 3)`, until `min box prune`
removes it.

| Flag | Short | Description |
|------|-------|-------------|
| `--all` | | List the task boxes of every project |
| `--output json` | `-o` | Write the boxes as one JSON array, and nothing else |

### `task logs`

```
min task logs [-f|--follow] [--raw] <BOX>
```

Shows what a task printed, from its start. It is `min box logs` for a task
box.

| Flag | Short | Description |
|------|-------|-------------|
| `--follow` | `-f` | Show the output so far, then keep showing new output, until the box is removed or the command is interrupted |
| `--raw` | | Write the output byte for byte, with its terminal control codes. Without `--raw`, the command removes those codes from the output of a box with a terminal when stdout is not a terminal |

### `task stop`

```
min task stop [--force | --exec <EXEC_ID>] <BOX>
```

Stops a running task box and keeps it. It is `min box stop` for a task box,
with the same flags.

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Kill every process in the box at once, with no grace period |
| `--exec <EXEC_ID>` | | Stop only one command, by the exec id that `min box exec` printed for it. Cannot be combined with `--force` |

### `task rm`

```
min task rm [--force] <BOX>
```

Removes a stopped or exited task box. It is `min box rm` for a task box. The
command refuses a running box unless you give `--force`.

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Stop a running box at once, then remove it |

### `box list`

```
min box list [--all] [-o json]
```

Lists the boxes of the current project, in any state. Each row shows the
box's id, name, type, parent, project and state, how a stopped or exited box
ended, and the provider and host the box runs on.

| Flag | Short | Description |
|------|-------|-------------|
| `--all` | | List the boxes of every project |
| `--output json` | `-o` | Write the boxes as one JSON array, one object for each box, and nothing else |

### `box start`

```
min box start [OPTIONS] [ENTRY]
```

Creates a box from an entry of the project's `minimal.toml`. A box with a
terminal attaches this terminal to it, unless you give `--detach`. Any other
box starts with no input, and the command prints its id and returns. Without
`ENTRY`, the command starts the entry named `default`, of any type, else the
project's only entry.

| Flag | Short | Description |
|------|-------|-------------|
| `--name <NAME>` | | Name the box. With `--new`, the box is named `<NAME>-<n>` |
| `--new` | | Create another box from the entry, named `<name>-<n>`, even when a running box holds the entry's name |
| `--detach` | | Create the box, print its id and return. This terminal is not attached to the box |

The command takes the override flags of
[`session start`](#session-start), from `--network` to `--no-hooks`. A task
entry refuses `--ingress` and `--loadout` with exit code 2.

### `box run`

```
min box run [OPTIONS] <ENTRY> [ARGS]...
```

Creates a box from an entry of the project, runs it without a terminal, and
exits with the box's exit code. The command's stdin, stdout and stderr are
the box's. The box is always a new box, named `<ENTRY>-<n>`. `ARGS` go to the
entry's declared `args`. Put the command's flags before the first argument.
An argument with the name of a flag goes after `--`.

| Flag | Short | Description |
|------|-------|-------------|
| `--detach` | | Start the box, print its id and return. The box gets no input |
| `--path <PATH>` | | The project directory. Without the flag, the directory that `--repo-dir` (short `-C`) gives, else the current directory |
| `--network <none\|host_ip\|own_ip>` | | The network mode of the box. Without the flag, the box takes the entry's `network.mode`, else `host_ip` |

The command also takes the flags of `min task run` that
[`session start`](#session-start) lists: `--allow-subnets`,
`--allow-dns-hosts`, `--allow-protocols`, `--deny-subnets`,
`--deny-all-egress`, `--dynamic-ingress`, `--dynamic-range`,
`--credentialed-upstream`, `--quic443`, `--vpn-network-names`,
`--no-loadouts` and `--no-hooks`.

### `box attach`

```
min box attach [BOX]
min box attach --exec <EXEC_ID> <BOX>
```

Attaches this terminal to a box's terminal. `BOX` is the box's id, the start
of its id, its name, or `provider/host/name`, as `min box list` prints them.
Without `BOX`, the command attaches to this project's running box that has a
terminal, else to its only stopped or exited one, which starts again.
`min session attach` is the same command for session boxes.

| Flag | Short | Description |
|------|-------|-------------|
| `--exec <EXEC_ID>` | | Attach to a command that `min box exec -t` started in the box, by the exec id it printed. Needs `BOX` |

### `box resume`

```
min box resume <BOX>
```

Starts a stopped or exited box that has a terminal again, from the spec it
was created with, and attaches this terminal to it. The command refuses a box
that is not stopped or exited. Attach to a running box with
`min box attach`.

### `box restart`

```
min box restart <BOX>
```

Stops a box that runs until it is stopped, if it runs, and starts it again
from the settings it was created with. The box keeps its id, its name and its
files. A box that runs to completion cannot restart. Run its entry again with
`min box run`.

### `box stop`

```
min box stop [--force | --exec <EXEC_ID>] <BOX>
```

Stops a running box and keeps it. Its record, its events and its files stay
until `min box rm` removes them.

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Kill every process in the box at once, with no grace period |
| `--exec <EXEC_ID>` | | Stop only one command, by the exec id that `min box exec` printed for it. The box and its other commands keep running. Cannot be combined with `--force` |

### `box logs`

```
min box logs [-f|--follow] [--raw] <BOX>
min box logs --exec <EXEC_ID> <BOX>
```

Shows what a box printed, from its start. A stopped or exited box keeps its
output until `min box rm` removes it.

| Flag | Short | Description |
|------|-------|-------------|
| `--follow` | `-f` | Show the output so far, then keep showing new output, until the box is removed or the command is interrupted |
| `--raw` | | Write the output byte for byte, with its terminal control codes. Without `--raw`, the command removes those codes from the output of a box with a terminal when stdout is not a terminal |
| `--exec <EXEC_ID>` | | Show what one command printed, by the exec id that `min box exec` printed for it. The command can be running or ended. Cannot be combined with `--follow` or `--raw` |

### `box events`

```
min box events [-f|--follow] [-o jsonl] <BOX>
min box events --parent <BOX> [-f|--follow] [-o jsonl]
```

Shows the events that the daemon recorded for a box, oldest first: its
creation, each start and stop, and each exec and its exit. A stopped or
exited box keeps its events until `min box rm` removes it.

| Flag | Short | Description |
|------|-------|-------------|
| `--parent <BOX>` | | Show the events of every child box of this box together, in time order. Each event names its box |
| `--output jsonl` | `-o` | Write each event as one JSON object on its own line |
| `--follow` | `-f` | Show the events so far, then keep showing new events, until the box is removed or the command is interrupted |

### `box cp`

```
min box cp <BOX:PATH> <LOCAL>
```

Copies a file out of a box to this machine. `BOX` is the box's id, the start
of its id, or its name. A relative `PATH` is in the box's home directory, and
`/workbench/<PATH>` is in the box's copy of the project. When `LOCAL` is a
directory that exists, the file goes into it under its own name. A stopped or
exited box keeps its files, so a copy from it works too.

### `box prune`

```
min box prune [--older-than <AGE>] [--parent <BOX>] [-y|--yes] [--dry-run]
```

Removes every stopped or exited box: its record, its events and its files.
The command never removes a running box. Off a terminal, the command needs
`--yes`.

| Flag | Short | Description |
|------|-------|-------------|
| `--older-than <AGE>` | | Remove only the boxes that stopped or exited at least this long ago: a whole number of days, hours, minutes or seconds, such as `7d`, `12h`, `30m` or `90s` |
| `--parent <BOX>` | | Remove only the child boxes of this box |
| `--yes` | `-y` | Remove the boxes and do not ask first |
| `--dry-run` | | List the boxes that the command removes and the disk each one holds, and remove nothing |

### `box exec`

```
min box exec [-t|--tty|--detach] [--timeout <DURATION>] <BOX> -- <COMMAND>...
```

Runs a command in a running box, and exits with the command's exit code.
`BOX` is the box's id, the start of its id, or its name, as `min box list`
prints them. The command goes after `--`. It runs as these words, with no
shell, so a word keeps its spaces and its metacharacters stay literal. To use
a shell's pipes, globs and `$VAR`, run the shell as the command:

```
min box exec web -- sh -c 'echo $PWD'
```

| Flag | Short | Description |
|------|-------|-------------|
| `--tty` | `-t` | Give the command a terminal and connect this terminal to it. The command's exec id is printed on stderr, so stdout has only the command's output. Refused when stdin is not a terminal |
| `--detach` | | Start the command and return at once. Only the command's exec id is printed, on stdout. Cannot be combined with `--tty` |
| `--timeout <DURATION>` | | Stop the command when it runs for longer than this: a number of seconds, or a number followed by `s`, `m` or `h`, such as `30s`, `5m` or `1h`. The command then ends with exit code 124 |

`min box show <BOX>` lists the box's running commands with their exec ids.
`min box logs <BOX> --exec <ID>` shows what one of them printed.

### `box rm`

```
min box rm [--force] <BOX>
```

Removes a stopped or exited box: its record, its events and its files. The
command refuses a running box. `--force` stops a running box at once and then
removes it.

### `box rename`

```
min box rename <BOX> <NEW_NAME>
```

Gives a box a new name. The box keeps its id, its state and its files. The
command refuses a name that a running box on the same host holds.

### `box show`

```
min box show [-o <json|yaml>] <BOX>
min box show --network [-o json] <BOX>
```

Shows one box: its id, name, type, parent, project and state, how it ended,
the identity it runs under, and its provider and host. It also lists the
box's running commands, each with its exec id, its argv, and whether it has
a terminal (`tty`), is connected without one (`attached`) or runs on its own
(`detached`).

| Flag | Short | Description |
|------|-------|-------------|
| `--network` | | Show the box's effective network policy in place of the box: the ingress and egress rules in force, the ports the box published while it runs, and the VPN networks the box keeps |
| `--output <json\|yaml>` | `-o` | Write the box and its running commands in this format instead of text. With `--network`, only `json` is available |

`--network` prints the rules the box runs under. A box with no egress rules
of its own shows the default it gets, such as `deny-all (default)`. The ports
the box published while it runs follow, under
`live ingress (published at runtime)`. The VPN networks the box keeps
follow last, under `vpn networks (not connected yet)`. They are the
entry's `network.vpn_network_names`, then each `--vpn-network-names`
value. `minimald` does not connect the box to a VPN yet. With `-o json`,
`--network` writes one JSON document, `min/v1/session-policy`, in place
of the text. The document lists the names in `vpn_network_names`. The
command refuses `-o yaml` with `--network`, with exit code 2.

### `box wait`

```
min box wait [--timeout <DURATION>] [-o json] <BOX>
min box wait --exec <EXEC_ID> [--timeout <DURATION>] <BOX>
```

Waits until the box ends, and exits with the box's exit code. A box that a
signal stopped gives 128 plus the signal, such as 143 for SIGTERM. A box
that ran past its own timeout gives 124. When the box ends, the command
copies the files the box declares as exports into the project. If it skips
an export of a box that exited with 0, it exits with 125.

| Flag | Short | Description |
|------|-------|-------------|
| `--timeout <DURATION>` | | Stop waiting after this long: a number of seconds, or a number followed by `s`, `m` or `h`. The box keeps running, and the command exits with code 124 |
| `--exec <EXEC_ID>` | | Wait for one command, by the exec id that `min box exec` printed for it, and exit with that command's exit code |
| `--output json` | `-o` | When the box ends, write how it ended as one JSON object on stdout. Not available with `--exec` |

With `-o json`, the command writes one `min/v1/wait` object on one line when
the box ends. Its `boxes` array has one entry for the box, with these fields:

| Field | Value |
|-------|-------|
| `box_id` | The box's id |
| `name` | The box's name, or `null` |
| `state` | `exited` or `stopped` |
| `reason` | How the box ended, as its record keeps it, such as `exit`, `stopped` or `timeout` |
| `exit_code` | The exit code the box's record keeps, or `null` |
| `signal` | The signal that ended the box, or `null` |
| `code` | The exit code of `min box wait` for this box |

A wait that `--timeout` ends before the box ends writes no object. Under
`-o json`, a failure is one `min/v1/error` object on stderr.

### `box spec`

```
min box spec [OPTIONS] <ENTRY>
min box spec [-o <toml|json|yaml>] <BOX>
min box spec [--network <none|host_ip|own_ip>]
```

With an argument, the command reads it as an entry of the project's
`minimal.toml`. When the project has no entry of that name, it reads the
argument as a box address: an id, the start of an id, or a name, as
`min box list` prints them. It never reads the argument as a directory. To
use another project, give `--repo-dir <DIR>` (short `-C`).

`min box spec <ENTRY>` shows the spec that `min box start <ENTRY>` sends to
the host, before any box exists. A comment or a `sources` field names the
layer that set each value. A secret shows only as its reference, never as its
value. The output also names the loadouts that `min box start` applies. When
the entry declares a broker secret, the Box Egress Proxy rows follow.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <toml\|json\|yaml>` | `-o` | The format of the spec. The default is `toml` |
| `--network`, `--ingress`, `--allow-subnets`, `--allow-dns-hosts`, `--allow-protocols`, `--deny-subnets`, `--deny-all-egress` | | Overrides of the entry's `[network]` keys, as on [`session start`](#session-start) |
| `--loadout <NAME>` | | Apply the named loadout, as on [`session start`](#session-start). Repeatable |

A task entry refuses `--ingress` and `--loadout` with exit code 2, as
`min box start` does.

`min box spec <BOX>` shows the spec that the box was created with, as its
host stores it. It takes `-o` and no override flag. An override flag with a
box gives exit code 2.

The spec of a box lists its
[lifecycle hooks](./loadouts.md#lifecycle_hooks---scripts-at-session-transition-points),
each with the loadout or project that declared it. A box started with
`--no-hooks` lists none. To read a box and not an entry of the same name,
give the box's id.

`min box spec` with no argument shows how the box of the project reaches
GitHub through the local Box Egress Proxy. The rows are the proxy's root
certificate fingerprint, each secret with its hosts, the steering mode, and
the UDP 443 stance. This form takes `--network` and no other override flag.
Another override flag gives exit code 2.

| Flag | Short | Description |
|------|-------|-------------|
| `--network <none\|host_ip\|own_ip>` | | The network mode of the box to show, with the same values and the same default (`host_ip`) as `min session start --network` |

The command refuses a box spec, with exit 3, where `min session start` with
the same `--network` value refuses it for the same reason. For example, on a
VM-backed host, `min box spec --network own_ip` accepts `steering = "both"`.
With no `--network` flag, it refuses that spec because a `host_ip` box has no
box DNS resolver, and `min session start` with no flag refuses it too.

### `type list` (alias: `ls`) and `type show`

```
min type list [-o json|yaml|toml]
min type show <NAME> [-o json|yaml|toml]
```

`min type list` lists the box types that the project can use. These are the
built-in types and each type of the project's `[box_types]` in
`minimal.toml`. Each row shows the type's source, `builtin` or `project`, the
type it extends, and the built-in type at the end of its chain.

`min type show <NAME>` shows one type. It shows the type that it extends,
and the chain of types from the built-in type to this type. It lists each
default and each constraint with the type that sets it and the source of
that type.

The commands read the `minimal.toml` in `--repo-dir`. Without `--repo-dir`,
they read the first one in the current directory or a parent directory.
Outside a project, they show the built-in types only.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <json\|yaml\|toml>` | `-o` | Write `min/v1/type` objects in this format, in place of text. `min type list` writes a JSON array, a YAML sequence, or a TOML `[[types]]` table for each type |

| Exit code | Meaning |
|---|---|
| 3 | The project's `minimal.toml` does not load, is not valid TOML, or has a type in `[box_types]` that does not resolve |
| 4 | `min type show` names a type that does not exist |

### `net forward`

```
min net forward <SESSION> <LOCAL>:<PORT>
```

Forwards a port from a session's box to the laptop: binds
`localhost:<LOCAL>` and relays every accepted connection over the session's
SSH channel to `127.0.0.1:<PORT>` inside the box, so a service running in
the session answers on the laptop with nothing else installed or configured
on the remote side. `min net forward web 8080:3000` puts the box's port 3000
on `localhost:8080`. A `<LOCAL>` of `0` binds a free port the OS picks, and
the forward prints the port it bound. `<PORT>` must be 1-65535.

Each accepted connection gets its own SSH channel, and the daemon dials
`127.0.0.1:<PORT>` on the box's side of the session: inside the box's own
network namespace when it has one (`--network none`, `--network own_ip`), or
the namespace it shares with the daemon when it does not (`--network
host_ip`). Either way the port reached is the one the box's service binds,
so the command works for every network mode a session can have.

The forward follows the session, not the box's process: a session record
that outlives its box is the normal state after [`host stop`](#host-stop), which keeps
records, and a forward that refused such a session would be stranded against
every session that survived a daemon restart. Where the dial has to run
inside the box — an isolated session's own network namespace — the daemon
brings a box that isn't running up for the dial. A
`--network host_ip` box shares the daemon's namespace, so its dial needs no
box up: a session nothing has started answers with a refused connection
until something starts the box.

The forward stays in the foreground and ends on `Ctrl-C`, when the box
is removed, or when the daemon goes away; the listener and every open relay
close with it. `min host stop` does not remove a box: it ends a forward only because the
daemon's exit does, and it keeps every box record, so a later
`min net forward` reaches those sessions again.

What the tree proves today is the host-address mode (`--network host_ip`)
end to end: the `net_forward_*` tests drive a real daemon and relay bytes
through a live laptop-side listener. The in-box dial that the isolated modes
(`--network none`, `--network own_ip`) take — a `socat` relay injected into
the box's namespaces — is exercised by the daemon's harness test with a
host-side stand-in relay rather than a real box; a root-integration proof of
that leg (`just test-root-integration`) is still owed to the root lane.

### `finalize-install`

```
min finalize-install [--show [--script | --json]] [--undo]
```

The installer runs without privilege. Anything on this host that needs root
is left for this command, which runs it in one `sudo` call. Until it runs,
the hostname proxy serves box names. The host line that
`min session start` prints says how the box name opens. While the proxy
serves the names, the line is
`names: <box>.min.internal opens through the HTTP proxy at 127.0.0.1:<port>`.
Once this host resolves the zone natively, the line has one of two forms. The
first form is for a box with its own reserved local address:

```text
names: <box>.min.internal opens at its name on this machine; the HTTP proxy at 127.0.0.1:<port> opens it too
```

The second form is for a box at the `127.0.0.1` fallback:

```text
names: <box>.min.internal resolves on this machine; open it through the HTTP proxy at 127.0.0.1:<port>
```

The `BOX NAMES` row of `min ls` states the same words. While any item is not
done, the line ends with `; finish setup: min finalize-install`. When the proxy failed
to bind, the cause replaces the resolution and the box stays named:
`names: <box>.min.internal: the hostname proxy is not serving: <cause>`, with
the same clause after it when it applies. A session
start never prints or runs the privileged step.

On macOS, a box opens at its name directly once `min finalize-install` has
run. A port that the box publishes, by `--ingress` at activate or by
`min net expose` inside the box, opens at `http://<box>.min.internal:<port>`
in the default profile of Safari, Chrome or Firefox. A browser profile that
resolves names through DNS over HTTPS does not resolve box names. The box then
stands at its own reserved local address, the address that its name resolves
to. Before `min finalize-install` runs, the box stands at `127.0.0.1`, and
the same URL opens through the hostname proxy at the `127.0.0.1:<port>` that
the host line names. The hostname proxy keeps serving
after the step, and it refuses a port that the box did not publish, the same
as a direct connection.

An activation refuses a declared `--ingress` host port that something on this
machine already holds, and leaves no box behind. The refusal names the port
and its holder, and suggests the next port up:

```
Port 8080 is already in use on this machine by box web.
Choose another host port in --ingress (for example --ingress 8081:8080) or in [network] ingress in minimal.toml.
```

When the holder is not a box, the first line ends with
`by another program on this machine.` Before `min finalize-install` runs,
every box shares `127.0.0.1`, so two boxes cannot declare the same host port.

The script holds only what this host is missing from:

- the AppArmor profile that allows user namespaces for the sandbox
- names: the resolver link and the box-name service, plus the reserved local
  range on macOS
- the classifier tree that enforces a host-address box's egress declaration.
  The step keeps a root-owned copy of itself under `/usr/local/lib/minimal`.
  A systemd boot unit re-installs the tree after a reboot. On every start the
  daemon connects to a systemd socket unit at `/run/minimald-place.sock`, and
  the service it starts places the daemon in its leaf. An un-enrolled
  host does not need a source identity for it. The classifier translates
  nothing until an association adds the reserved addresses
- membership of the `kvm` group, for the Linux VM provider. A command that
  does not name a provider also gets it where `/dev/kvm` does not open for you

On macOS the step installs the box-name service's program in an app bundle,
`/Library/PrivilegedHelperTools/Minimal.app`, that root owns. The service and
the job that reserves the local range both run that program. A release signs
the bundle, so System Settings lists the two jobs under the bundle's name,
Minimal, in General, then Login Items & Extensions. A host that ran the step
from an earlier release has a bare `minzoned` program in the same directory
and a script for the local range. The next `min finalize-install` replaces
both with the bundle.

`min finalize-install` prints the summary of what is missing. It writes the
script to a temporary file that only you can read (mode `0600`) and runs it
with `sudo sh`, so `sudo` asks for your password once. It then removes the
file and exits with the script's status. A completed run that installed
anything other than the `kvm` group membership ends with
`Running boxes pick this up on their next start.`. A run that added you to
the `kvm` group ends with
`KVM group membership starts at your next login: log out and back in, or restart the daemon from a new login.`
When both apply, both lines print, the login line last. When the step that
enforces deny-all egress installs while a daemon is running, on a host with
systemd, the script also prints `note: a Minimal daemon is running. If a box you start next still says this machine cannot enforce its egress yet, restart the daemon. Run min host stop local0 --provider local, which stops each running box and then the daemon. Then run min ls --provider local, which starts the daemon again.`
When `min finalize-install` runs with `--minimal-dir`, both commands in the
note carry the same `--minimal-dir`, made absolute.
A daemon of this release reads the machine again once the step places it, so
the restart is for a daemon started by an earlier release. Without systemd no
unit places a restarted daemon, so the script does not advise a restart.
On a host that needs nothing it prints
`Every part of the install is finished on this machine; there is nothing to run.`
and exits 0. It lists a fact that no script can change, such as cgroup2
mounted without `nsdelegate`, under `can't do on this machine:`. The other
items still run. When a host fact blocks every missing item, it runs
nothing and exits non-zero.

Without a terminal, it tries `sudo -n`. If `sudo -n` cannot run the script
without a prompt, it prints the summary and
`f=$(mktemp) && min finalize-install --show --script > "$f" && sudo sh "$f"`,
runs nothing, and exits 1.

The script is plain POSIX `sh` and stops at the first statement that fails.
Its header says what it configures and that it must run as root. A comment
introduces each step.

| Flag | Description |
|---|---|
| `--show` | Print the summary of what this host is missing, with no privilege prompt, and run nothing. Exits 0 whatever the items' states. |
| `--show --script` | Print the script to stdout and the summary to stderr, with no privilege prompt. Run it later with `sudo sh <file>`. Exits 0 whatever the items' states. |
| `--show --json` | Print the summary as one JSON document under the schema `min/v1/finalize-install`. Each item has a stable id and a state: `done`, `missing`, `waiting`, or `cannot`. Exits non-zero while any item is not `done`. |
| `--undo` | Remove everything the step installed on this host. It accepts only `--show --script`, which prints the removal script instead. |

The names step points at the port the daemon's zone answerer listens on, so
it needs a running daemon that has bound its answerer. It does not start one.
With no daemon reachable, it lists the names item as `waiting on a daemon`
under the summary and runs the remaining items.

The box-name service runs as one user for the whole machine. If another user
already installed it, the command refuses before running anything, names
that user, and exits 1. `--show` still prints.

`--undo` works without a daemon, and it succeeds on a host that holds none of
the install. It removes the user-namespace profile, the classifier tree with
its units and step copy, and the group membership the step added. A profile
or a classifier tree installed another way stays, with a note. It also removes the box-name
service and its program copy, the resolver hook, and on macOS the local range
unit. On macOS the program copy is the app bundle, and `--undo` also removes
the bare program and the range script that an earlier release installed.
On macOS the local range addresses come off the loopback too, and `--undo`
removes the resolver file's directory when it holds nothing else. While a VM
is running, the addresses stay and a note says so: stop every VM, then run
`--undo` again. The check counts any `minvmd` process on the host, so end one
that `min host stop` leaves behind too.
`install.sh --uninstall` points at `min finalize-install --undo` while any of
these host files remain.

When the installer finishes on a terminal and the host lacks a step, it shows
the summary and asks `Finish setup now? This runs one sudo command. [Y/n]`.
The default is yes. It does not ask on a host that needs nothing. If you
decline, or there is no terminal, it prints
``run `min finalize-install` when you're ready``.

### `host stop`

```
min host stop [-f|--force] <HOST>
```

Stops each running box on a local host, then the host's daemon, and its VM
on a VM host. `HOST` is the host's name as `min host list` prints it, such as
`local0` or `local-minvmd0`. The boxes stay: their records, events and files
remain until `min box rm` removes them. `--force` force-stops each box, and
stops the daemon without waiting for it to shut down cleanly. On a VM host,
`--force` stops the VM from this machine, and data not yet written to disk
inside the VM can be lost.

### `auth login` (alias: `min login`)

```
min auth login [--device]
min login [--device]
```

Signs in to GitHub and keeps the sign-in in the host keychain. It opens
GitHub in your browser. With `--device`, or in a build with no browser
sign-in, it prints a code to enter at github.com. The token stays in the host
keychain and is never written to a file.

The browser sign-in ends on a page that states the outcome. After a sign-in,
`min auth login` names the accounts that have an installation of the Minimal
GitHub App. With no installation, it gives the install URL,
`https://github.com/apps/gominimal/installations/new`, where you choose the
repositories your boxes can reach. The browser page links there too. The
browser sign-in then waits up to 5 minutes for the installation, and Ctrl-C
stops the wait. The sign-in is already saved. If the wait ends without an
installation, `min auth login` gives the install URL again.

`min login` is the same command as `min auth login`. It takes the same flags
and prints the same prompts.

### `loadout list` (alias: `ls`)

```
min loadout list [--dir <DIR>]
```

Lists loadouts from the user's config directory, in both layouts —
`<name>.toml` and `<name>/loadout.toml`. `--dir` overrides the
loadouts directory (default: `<config>/minimal/loadouts`, e.g.
`~/.config/minimal/loadouts` on Linux).

A loadout that fails to load is reported on stderr and makes the command exit
non-zero, leaving the table of valid loadouts intact. That covers a malformed
file and a name defined in both layouts at once, which is
[an error rather than a precedence rule](./loadouts.md#where-loadouts-live).

### `dirs`

```
min dirs
```

Prints important directories and file paths for debugging.

### `bug`

```
min bug [-o <OUTPUT>] [--upload [--context <TEXT>] [--security] [--endpoint <URL>]]
```

Collects a diagnostic bundle (logs, state, config) to send to the minimal
dev team. Writes `minimal-diag-<timestamp>.tar.zst` to the current
directory; `-o/--output` overrides the path. The archive contains host
system facts, log tails, redacted config, and state listings, plus a
`manifest.json` recording any collector that failed or timed out; a
broken install still yields a valid archive that explains what is
missing.

Because sessions are interactive, the bundle also records the terminal
`bug` itself ran on (`host/terminal.json`): whether stdin, stdout, and
stderr are ttys — the same condition `attach` gates on, so a run under a
pipe or CI is distinguishable from a real terminal — and, for each that
is, its device and its `TIOCGWINSZ` geometry (rows, columns, and the
`xpixel`/`ypixel` size emulators report), which is what makes a garbled
TUI or wrong wrapping diagnosable.

The bundle is scoped to a project, so it can be attributed to one. Every
other collector describes a machine, and a machine hosts many projects:
two bundles taken on one host from two checkouts otherwise read
identically. `manifest.json` therefore opens with the project's name,
root, and which config file defines it (`minimal.toml` or
`.minimal/minimal.toml`), repeated in `project/project.json` along with
the directory `bug` was actually run from. Run outside a project, the
manifest records that as a finding with its reason rather than falling
silent.

Only the project's identity is recorded there — its name, its root, its
config file's relative path, and where `bug` ran from. No configuration
*values*; the redacted config is collected separately, under the
allowlist policy below.

Diagnosing a wedged system must not change it: `bug` mutates no state and
never starts a daemon; it works even when none are running.

Secret-shaped values (env vars, tokens) are redacted before they enter
the archive: only a small allowlist of env names (`RUST_LOG`, `HOME`,
`SHELL`, `TERM`, `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`, `COLORTERM`,
`PATH`, and the `XDG_*` / `MINIMAL_*` / `MINVMD_*` / `MINIMALD_*`
prefixes) have values captured verbatim (a sensitive-shaped
name always loses to the allowlist), and every other env var is reported
by name only. Session and project file contents are never included, only
name/size listings. Review the archive before sharing.

`--upload` sends the bundle to the diag portal after `bug` writes it to
disk. A failed upload leaves the archive in place. The upload sends
nothing to identify you: it sends the bundle and the `--context` text.
`--context` is a sentence on what went wrong. The portal shows it beside
the report and gives it to the agent that reads the bundle. `--endpoint`
names another portal. It must be HTTPS, or plain HTTP to a loopback
host. The portal takes bundles up to 64 MiB.

After an upload, `bug` prints:

```
Report:  https://agents.minimal.farm/diag/<id>
The bundle is stored for the minimal team for 7 days. It is not diagnosed until someone signs in at the report URL and starts the diagnosis.
Expires: <date>
Delete:  min diag delete <id> <token>
```

The portal keeps the bundle for 7 days and then deletes it. The portal
starts a diagnosis only when someone signs in on the report page and
starts it there. The report URL does not contain the delete token, so
you can share the URL. To remove the bundle sooner, run the `Delete:`
line. See [`diag`](#diag).

`--security` sends the bundle as a security report, for a suspected
vulnerability. It needs `--upload`. Only portal owners can read the
report. Its description is never public, it is never filed to public
GitHub, and the results go to a private channel. `bug` prints these
lines instead:

```
Received privately as a security report. Only the minimal team's portal owners can read it.
Receipt: https://agents.minimal.farm/diag/<id>
That page only confirms receipt. It shows nothing else and will not change.
Expires: <date>
Delete:  min diag delete <id> <token>
```

### `diag`

```
min diag collect [<bug options>]
min diag upload <PATH> [--context <TEXT>] [--security] [--endpoint <URL>]
min diag delete <ID> <TOKEN> [--endpoint <URL>]
```

`diag collect` is [`bug`](#bug) under another name and takes the same
options.

`diag upload` sends a bundle that you collected earlier. Use it for a
bundle someone gave you, or for one you collected while the portal was
unreachable. It prints the same lines as `bug --upload`, and takes
`--security` the same way.

`diag delete` deletes an uploaded bundle before it expires. Give it the
id and the delete token that the upload printed. The portal deletes the
bundle and any diagnosis made from it, and the command prints
`Deleted <id>`. It fails with a plain error when the portal has no such
bundle, or when the token does not match the bundle. A bundle is missing
when nobody uploaded it, it expired, or someone already deleted it.
`--endpoint` follows the same HTTPS rule as the upload.

### `init`, `add`, `update`

```
min init [-y|--yes]
min add <--session|--runtime|--build|--task <TASK>> <PACKAGES>...
min update
```

Project-configuration conveniences mirroring the corresponding `mip`
commands: initialize minimal configuration from your source tree, add a
tool or dependency, and refresh local checkouts of upstream packages and
the embedded standard library. See the [mip reference](./cli-mip.md) for
details.

`min update` is not a self-update. It re-pins the project's `[upstream]` link
(and any sideloads) in `minimal.toml` to the current head of each tracking
branch — rewriting `locked_commit` and leaving the file modified in your
working tree — then refreshes the local checkouts to match. The standard
library is embedded in the `min` binary and is only refreshed or verified
locally — its commit is not re-pinned. The next `min session start`
materializes the new closure, which can take several minutes on the first
start. When no pin has moved it reports that and leaves `minimal.toml`
unchanged. To update the `min` binary itself, reinstall it with the
installer.

These three are deliberate exceptions to the `min <noun> <verb>` convention:
they are passthroughs to the `mip` commands of the same name, and keeping the
spelling identical across the two CLIs is worth more than the hierarchy.

### `version`

```
min version
```

Prints CLI and daemon version information.

### `completions` (alias: `completion`)

```
min completions print <SHELL>
min completions install [<SHELL>...]
```

`print` writes a shell tab-completion script to stdout. Supported shells
include `bash`, `zsh`, `elvish`, `fish`, `powershell`. Usage:
`source <(min completions print bash)`.

`install` writes that script into the shell's completion directory instead,
for the three shells with a conventional per-user completion path. With no
`SHELL` argument it installs for all three.

| Shell | Path |
|-------|------|
| `bash` | `$XDG_DATA_HOME/bash-completion/completions/min` (default `~/.local/share/...`) |
| `zsh` | `$XDG_DATA_HOME/zsh/completions/_min` (default `~/.local/share/...`) |
| `fish` | `$XDG_CONFIG_HOME/fish/completions/min.fish` (default `~/.config/...`) |

Each file is written atomically — a temporary sibling, then a rename — so a
half-written completion file never reaches a shell.

`install` prints every path it wrote to stdout, one per line. That is a
contract rather than a convenience: `scripts/install.sh` feeds exactly those
paths into its install record so `uninstall` can remove them, and derives no
paths of its own. The bookkeeping therefore has one implementation, reachable
by everyone rather than only by users who installed via `curl | sh`.

A completion directory that exists but is not writable — these are shared,
user-owned locations that can pre-exist root-owned — produces a warning on
stderr, not a failure: the other shells still install and the exit status is
still 0. For `zsh`, a stale `compinit` dump is dropped after a (re)install,
since it can otherwise keep trusting its cached contents after the completion
file underneath has changed.

What it emits is a short *registration* shim, not a completion table: it teaches
the shell to ask `min` itself what to offer. That indirection is what makes
session arguments completable — `min session attach <TAB>` lists live session
names, and `min session attach 019<TAB>` lists session IDs, neither of which
exists at the time a static script would be written. The `SESSION` argument of
`session attach` completes this way, and so does the box argument of every
`min box` verb that takes one, such as `box exec`, `box show`, `box rm` and
`box rename`.

Session completion is best-effort by design. It never starts a daemon — with
none running there is nothing to list, and booting a VM on a keystroke would be
a poor trade — and it gives up rather than make you wait if the daemon does not
answer promptly. In both cases the shell simply offers nothing.

To see the candidates without a shell in the loop, or to check completion
against a non-default backend:

```
min complete-session-str [<prefix>]              # value<TAB>description per line
min --provider local-minvmd complete-session-str # honours global args
```

The in-process completer cannot see global args (clap hands a value completer
only the word being typed), so it always resolves the default backend; this
hidden command is the way to check any other.

## `git push min://` - the git remote helper

Installs of `min` lay down a `bin/git-remote-min` symlink pointing at the
`min` binary. The binary dispatches on `argv[0]`: when invoked with the
basename `git-remote-min` (which is how git invokes remote helpers for
`min://` URLs), it speaks the
[gitremote-helpers](https://git-scm.com/docs/gitremote-helpers) line
protocol on stdio instead of the normal CLI.

This lets you add a session's workspace as a git remote and push to or
fetch from it directly:

```
git remote add session min://<session>
git push session
```

When the workspace's worktree is clean, a push to its checked-out branch also
checks out the new tip. That rewrites files under any process running in the
session. When the worktree holds uncommitted changes, the branch ref still
moves, and the push warns that it skipped the checkout. A push to any other
branch moves only that branch's ref. A push into a worktree with a detached
HEAD moves only the refs and warns that it skipped the checkout. HEAD stays
detached. The first push into an empty workspace checks out the branch that
the fresh repository's HEAD already names, if the push includes it.
Otherwise it checks out the first pushed branch.

Only the `connect` capability is implemented: on `connect`, the helper
opens an exec channel to `minimald` over its Unix domain socket (the same
transport the rest of the CLI uses) and bridges git's pack-protocol
conversation across it; no external `ssh` or `socat` involved. Only the
two pack services (`git-upload-pack`, `git-receive-pack`) are accepted.
If the daemon is not running, the helper starts it, using default global
flags (git invokes helpers without any of `min`'s own flags).
