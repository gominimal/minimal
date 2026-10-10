---
title: min CLI
description: "Reference for the min session CLI: create, attach to, and manage sandboxed development sessions, plus the git-remote-min helper."
---

# `min` - session CLI

`min` is the Minimal session CLI. It talks to the `minimald` daemon (see
[minimald](./cli-minimald.md)) to create, attach to, and manage sandboxed
development sessions. Most commands start the daemon automatically when it
isn't running, with `bug`, `stop`, and `version` being the exceptions. The 
daemon starts natively on Linux (and under `--provider local-minvmd`) or 
inside the [`minvmd`](./cli-minvmd.md) microVM host daemon on macOS. 
Running bare `min` with no subcommand routes you into a session when stdin
and stdout are both a terminal: it follows the smart-resolution rules of
`min session attach` with no argument (cwd match → attach, only session →
attach, ambiguity → picker), and when no sessions exist it creates one from
the current directory and attaches. Without a terminal it instead prints a
read-only state report on stderr and exits successfully. Use `min --help` to print this
help.

Commands are spelled `min <noun> <verb>`, and every noun accepts its singular
and plural form (`session`/`sessions`, `loadout`/`loadouts`). A handful of
bare verbs (`ls`, `stop`,
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
| `--provider <PROVIDER>` | | Daemon backend that hosts sessions: `local-minimald` (Linux default, `minimald` natively on the host) or `local-minvmd` (`minimald` inside the `minvmd` microVM). No effect on macOS, where `minvmd` is the only backend |
| `--no-input` | | Skip interactive prompts that need a terminal (such as the session picker); ambiguous choices error with a list of candidates instead. Implied when stdin/stdout is not a terminal |

## Commands

### `session list` (aliases: `min ls`, `min session ls`)

```
min session list [--raw] [--json]
```

Lists sessions. `--raw` prints raw session IDs one per line for piping
into scripts; `--json` prints the full session list as pretty-printed
JSON. When the daemon reports a shared resource pool, the table is headed
by a `RESOURCE POOL:` line (CPU cores, memory, and the number of sessions
sharing them); `--raw` omits it.

Another box at the same shared loopback address can hold a port this box
declares, and this box does not forward it. The list prints one stderr line
per such port after the table:
`warning: <session>: port <p> is held by <box>; not forwarded`.
With `--json` the entry lists those ports under `shared_port_collisions`,
each with `port` and `held_by`, and the key is absent when there are none.

`min ls` is the same command kept bare at the top level — a deliberate
exception to the `min <noun> <verb>` convention, since it is the
highest-traffic command in the CLI; `min session ls` is the noun-level alias.
All three spellings take the same flags and produce identical output.

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

### `session activate`

```
min session activate [OPTIONS] [PATH]
```

Activates (creates) a new session for the project at `PATH` (defaults to
the current directory).

| Flag | Short | Description |
|------|-------|-------------|
| `--name <NAME>` | `-n` | Optional session name |
| `--sync <MODE>` | | How to load project files into the session: `tarball` (default: stream a tarball of your project and unpack it) or `none` (do not populate the worktree. The session starts from a default project configuration and does not apply the project's `minimal.toml`) |
| `--network <none\|host_ip\|own_ip>` | | Network mode for the session: `none` gives it no network (every socket it opens to a destination outside itself fails), `host_ip` shares the host's network namespace (the default), and `own_ip` gives it an IP of its own on the host's switch so `--ingress` can publish ports. The old hyphenated spellings `no-net`, `host-net`, and `own-ip` still work for one release, with a one-line hint naming the current spelling. On a VM-backed host an `own_ip` box registers with the VM host daemon before the daemon creates the box. An activation that cannot reach the VM host daemon exits 7. One that daemon refuses because it has no free addresses exits 8 |
| `--ingress <EXT:INT[/PROTO]>` | | Static ingress port mapping `EXT:INT[/PROTO]` (PROTO = tcp or udp, default tcp). Repeatable. Requires `--network own_ip` |
| `--dynamic-ingress <allow\|ask\|deny>` | | Sets the stance that decides the box's own requests to publish a port (`min net expose`, or a listen inside `--dynamic-range`). `allow` publishes them, `ask` asks the attached person, and `deny` refuses every one, the same as leaving the flag unset. Setting it declares ingress even with no `--ingress` mapping. Requires `--network own_ip`. A VM-backed host refuses `allow` and `ask` before it creates the box, until the host side can admit a publish the box requests ([gominimal/minimal#1897](https://github.com/gominimal/minimal/issues/1897)). Every macOS host is VM-backed |
| `--dynamic-range <LO-HI>` | | Inclusive host port range, such as `8000-8443`, inside which `--dynamic-ingress allow` publishes. A port outside it gets the out-of-range refusal. Requires `--dynamic-ingress`. Setting it declares ingress even with no `--ingress` mapping. The flag refuses a range that starts below 1024, a privileged port |
| `--loadout <NAME>` | | Apply the named loadout from `<config>/minimal/loadouts/<NAME>.toml` or `<config>/minimal/loadouts/<NAME>/loadout.toml`. Repeatable; if given, config-file `default_loadouts` are ignored |
| `--no-loadouts` | | Apply no loadouts at all (also skips the config's `default_loadouts`). Conflicts with `--loadout` |
| `--no-hooks` | | Run none of the session's [lifecycle hooks](./loadouts.md#lifecycle_hooks---scripts-at-session-transition-points), from either the loadouts or the project's `minimal.toml`. Recorded on the session, so it applies to the later attach, detach, and destroy transitions too |
| `--no-prompt` | | Fail instead of prompting when the daemon surfaces items user policy can't auto-decide; implied when stdin/stderr isn't a TTY |
| `--attach` | | Automatically attach after creation |
| `--allow-subnets <CIDR>` | | Destination subnet the box may reach, in CIDR form (e.g. `10.0.0.0/8`). Repeatable. On an own-address box, an unset flag grants nothing once the daemon resolves the policy: write allow-all out as `0.0.0.0/0` and `::/0`. The opt-out below keeps the old allow-all meaning of an unset flag. Valid on an own-address (`--network own_ip`) or host-address (`--network host_ip`) box; a `--network none` box rejects the whole egress declaration |
| `--allow-dns-hosts <HOST>` | | Destination DNS hostname the box may resolve and reach (e.g. `github.com`). Repeatable. On an own-address box, an unset flag grants nothing once the daemon resolves the policy. The opt-out below keeps the old allow-all meaning of an unset flag |
| `--allow-protocols <PROTO>` | | Outbound transport protocol the box may use: `tcp`, `udp`, or `icmp`. Repeatable. Unset lets every protocol through: the flag filters the reach the two allow lists grant |
| `--deny-subnets <CIDR>` | | Destination subnet the box may not reach, in CIDR form — subtracted from what the allow flags admit. Repeatable; unset means nothing is denied. On an own-address box a declaration with only deny flags admits nothing: there is no allow list to subtract from. Add `--allow-subnets 0.0.0.0/0` to deny a range out of allow-all |
| `--deny-all-egress` | | Declare deny-all egress: the box reaches no external address. Writes the deny-all `egress` section, every allow list present and empty. A box declared by flag reads in the record exactly like one whose `minimal.toml` carries the section. On a host-address box the host's classifier decides a declared deny-all per box. An own-address box without egress flags already gets deny-all by default (see below). Conflicts with every `--allow-*`/`--deny-*` rule flag |

Together the four `--allow-*`/`--deny-*` rule flags form the box's `egress`
declaration. Naming one of them stores it on the session, and `min session
policy` shows what the session ended up with. `--deny-all-egress` declares
the whole section in one flag and cannot combine with them.

An unset `--allow-subnets` or `--allow-dns-hosts` grants nothing on an
own-address box, inside a declaration as much as without one. This changes
what a declaration with no allow list does. `--allow-dns-hosts github.com`
alone reaches `github.com` and no address directly. `--deny-subnets` alone
reaches nothing. Both used to reach every address the deny left, and the
operator opt-out named below restores that earlier meaning. An
own-address box (`--network own_ip`) without these flags, and without an
`egress` section in its `minimal.toml`, gets the deny-all default: it
reaches no external address. It can still resolve names in the box zone,
`host.min.internal` included. Activate prints one line saying so:

```
egress: deny-all (default for an own-ip box with no egress section); declare reach with the --allow-subnets, --allow-dns-hosts and --allow-protocols flags
```

To give such a box reach, declare it with the allow flags, such as
`--allow-dns-hosts github.com` or `--allow-subnets 0.0.0.0/0`, or with an
`egress` section in `minimal.toml`. To keep the earlier allow-all default for
every undeclared box on a host, the operator opts out. A native Linux host
opts out with `minimald run --egress-deny-all-opt-out`, or with
`MINIMALD_EGRESS_DENY_ALL_OPT_OUT=1` in the environment that starts
`minimald`. `min` starts the daemon without the flag when it is not running,
so export the variable to keep the opt-out after such a restart (see
[minimald](./cli-minimald.md)). A VM-backed host opts out with
`MINVMD_EGRESS_DENY_ALL_OPT_OUT=1` in the environment that starts `minvmd`
(see [minvmd](./cli-minvmd.md)). A host-address box with no section
keeps allow-all either way.

Activating a path that already has a session is allowed, but warns: `min` names
the existing session and creates a second one anyway. With two sessions on one
path, resolving that directory to a session is ambiguous, so a bare `min` there
can no longer pick one and `session attach` falls back to its picker (erroring
when `--no-input` is set or stdin/stdout is not a terminal). Attach to the
existing session instead when you mean to
rejoin it.

When `PATH` has no `minimal.toml`, activation still succeeds and the session
comes up with a default environment. On an interactive terminal `min` first
offers to scaffold a `minimal.toml`; accepting writes one into `PATH`, while
declining leaves your directory untouched. When prompts are skipped
(`--no-input`, or a non-terminal stdin) `min` prints a notice and continues
without writing anything to `PATH` — the daemon fabricates a default config
inside the session's own workspace instead. `--loadout` is resolved before any
of this, so an unknown loadout name errors even in a directory with no config.

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

### `session exec`

```
min session exec <SESSION> <COMMAND>...
```

Runs a command in an existing session, non-interactively, relaying its
stdout, stderr and exit code.
When a daemon shutdown stops the command, `min` prints
`minimald is shutting down; the command was stopped` on stderr and exits with
the command's own status.

How `COMMAND` is read depends on how many arguments you give it:

- **One argument is a shell command**, run by the session's shell with its
  pipes, globs and `$VAR` intact — the `ssh host '<cmd>'` form.

  ```
  min session exec web 'echo $PWD'
  ```

- **Several arguments are an argv**, carried as data. No shell reassembles
  them, so a word keeps its spaces and its metacharacters stay literal.

  ```
  min session exec web sh -c 'echo A B C'
  ```

The argv form matters because ssh has no argv on the wire — it joins its
trailing arguments with single spaces and the far side reshells the result.
Passing words through one by one would let the session's shell re-split them,
which is how `sh -c 'echo A B C'` once lost its first word to `sh`'s `$0`.

Nothing about a command's *text* routes it: a command is the session's however
it happens to start, so the session's own `min` binary is reachable here. The
daemon's own operations are named explicitly instead — see `session run`.

#### Backgrounding a command

`session exec` returns when `COMMAND` itself exits, and relays output up to
that point. A process the command backgrounds keeps running in the session,
but what it writes *after* the command has exited is not yours to rely on: a
short drain catches whatever was already in flight, and past that its output
is read and discarded. Nothing it writes is ever lost to a broken pipe — the
process is not killed — but you will not see it.

```
min session exec web 'sleep 20 & echo STARTED'   # returns immediately
```

So background a long-running process with its output redirected somewhere you
can retrieve it, rather than expecting it on the wire:

```
min session exec web 'nohup ./server >server.log 2>&1 &'
min session exec web 'tail -n 50 server.log'
```

`nohup ... >/dev/null 2>&1 &` is the fully detached form: it hands the process
its own stdout and stderr and drops the ones it inherited, so nothing about it
depends on the exec channel at all. The same applies to `session run` and
`task run`, which relay over the same channel.

If the client goes away while the command is still running, the exec ends its
whole process group: SIGTERM, a grace period, then SIGKILL. A `nohup`'d job
stays in that group, so it ends too. Start a job that must outlive the client
with `setsid`, which puts it in a session and group of its own:

```
min session exec web 'setsid nohup ./server >/dev/null 2>&1 &'
```

A command that exits by itself ends nothing: its background jobs keep running.

### `session run`

```
min session run <SESSION> <TASK>
```

Runs a task declared in the session project's `minimal.toml`, in that session,
relaying its output and exit code.

This is the session-scoped counterpart to
[`min task run <task>`](../guide/tasks.md), which composes a task session of
its own. Use `session run` when you want the task to run against a session you
already have.

Because the task is named as a task rather than inferred from a command string,
a task may share a name with a daemon subcommand or with a program on the
session's `PATH`.

### `session destroy`

```
min session destroy [--all] [-f|--force] [SESSION]
```

Destroys a session and ends its processes. `--all` destroys all sessions.
`-f/--force` skips the confirmation.

Before it destroys one session, the command asks for confirmation if the
session holds uncommitted changes or commits that no remote has. It also asks
if the daemon cannot report that state. The command destroys a clean session without
a prompt. Without a terminal, or under `--no-input`, nobody can answer, so the
command refuses unless you pass `-f`. `--all` without a terminal also refuses
unless you pass `-f`.

### `session rename`

```
min session rename <SESSION> <NEW_NAME>
```

Renames an existing session.

### `session policy`

```
min session policy <SESSION> [-o json]
```

Prints the effective networking rules for `SESSION` (a UUID, unique id
prefix, or session name). Resolved from the daemon, which answers from the policy stored at
activation; each rule line shows what the session ended up with, not just
what was typed.

The egress block resolves every dimension of the box's `egress` declaration
to its rule or its default:

```
egress
  subnets  10.0.0.0/8
  dns hosts  allow-all
  protocols  tcp, udp
  deny subnets  169.254.169.254/32
```

`subnets`, `dns hosts`, and `protocols` each read `allow-all` when the
matching flag was not given. `deny subnets` reads `(none)` when the
declaration denies nothing. A deny-all declaration, the `egress` section
with every allow list present and empty, prints as the one row `deny-all`.
A box without an `egress` section prints the default the daemon resolved
the absence to, by name and marked as what it is. `deny-all (default)`
marks an own-address box, which gets the deny-all default.
`allow-all (default)` marks a box on a host that opted out of that default,
or one that shares its host's network namespace. The `(default)` mark distinguishes a verdict
the box declared from the same verdict the default gave it.

A box activated with `--credentialed-upstream` prints one more row in
the egress block:

```
egress
  deny-all (default)
  credentialed upstream  box egress proxy listener
```

The row names the lane the declaration opened. The gate admits the box's
frames to the box egress proxy's listener, and the proxy checks their
credential. The rows above never decide that destination. The listener is
the lane's whole reach. The gate still refuses everything else the box
sends to the proxy's address. A box without the lane omits the row, so
the missing row means the box runs without a lane.

The gate that admits the lane sits only in front of own-address boxes. A
box in any other mode still prints the row it declared, marked as not in
effect, with the box's mode named:

```
egress
  allow-all (default)
  credentialed upstream  box egress proxy listener (not in effect: host_ip box)
```

The ingress block lists the published port mappings the session's
`--ingress` flags declared (or `deny-all` when the box leaves ingress
undeclared). The `dynamic ports` row joins them when the box declared a
`--dynamic-range`.
The `dynamic ingress` row always prints, with the stance that decides the
box's own publish requests. A box that set no `--dynamic-ingress`
reads `deny (default)`, the deny the absence evaluates to, marked the way
the egress block marks a default. A box that declared `deny` reads plain
`deny`:

```
ingress
  tcp  :8080 → :80
  dynamic ports  8000–8443
  dynamic ingress  allow
```

A host-address (`--network host_ip`) session prints no ingress block at all:
it shares its host's network namespace, so minimald applies no per-session
ingress to it and there is no rule to state.

The `live ingress` block lists the ports the box published at runtime with
`min net expose`. Each row shows the address the forward binds on and the
in-box port it delivers to:

```
live ingress (published at runtime)
  tcp  127.0.64.21:3000 → :3000
```

A listed runtime publish is reachable. The daemon admits the port at the
box's relay gate when it binds the forward. If nothing in the box listens on
the port yet, the box itself refuses a connection to it.
A row from an older daemon whose gate did not admit runtime publishes reads
`(pending; not yet reachable)`. A row from a daemon older than the `pending`
field reads `(unknown; daemon predates this field)`. The CLI never shows
either row as reachable.

The daemon publishes a port the box listens on only after it writes the
decision to its audit log. When the daemon cannot write the log, the port
stays unpublished, and the command prints one line per port after the live
rows:

```
warning: port 3000 is permitted but not published: the audit log /path/to/audit/decisions.log cannot be written
```

The line clears once the log takes records again and the port publishes.
In `-o json` output the same ports appear as `unaudited_listen_ports`, a
list the document leaves out when it is empty.

`-o json` (`--output json`) prints one `min/v1/session-policy` document on
stdout instead of text. Each block the text output prints becomes a key:
`network`, `egress`, `ingress`, and `live_ingress`. The `egress` object
carries the verdict the gate enforces as `effective` and its origin as
`source`. `effective` reads `deny-all`, `allow-all`, or `rules` when the
declaration's own lists say the verdict. `source` reads `default` for the
rollout's resolution of an absent section, `declared` for the box's own.
A declared section appears under `rules`, its lists as the record holds
them. The fields match the text output's `(default)` mark, so a client
never recomputes the default rule to tell a declaration from a default.
Each `live_ingress` row is the daemon's mapping object, with its `pending`
state (`true`, `false`, or `null` for a daemon older than the field). The
document leaves out the blocks the text output leaves out. A host-address
session has no `ingress` key, and a `--network none` box has only `schema`
and `network`, plus `credentialed_upstream` when it declared a lane. The `ingress` block has a `kind` tag, `deny_all` or
`declared`, so a client reads one field to branch. Both kinds carry
`dynamic_ingress`, the resolved stance: `allow`, `ask`, or `deny`, never
`null`. Both also carry `dynamic_ingress_source`. It reads `declared` when
the box set `--dynamic-ingress`, and `default` when the stance is the deny
an absent setting gives. Both keys are new in the `min/v1/session-policy`
shape. A client written against the earlier document ignores them. A
client that reads them finds a value in every `ingress` object. The
document also carries `credentialed_upstream`, an object, when the box
declared a lane, in any network mode. Its `effective` field is `true`
for an own-address box and `false` for any other, the text row's
`(not in effect: …)` mark. The document leaves the key out when the box
did not declare a lane, so a missing key means the box runs without one.

Boxes handed one shared loopback address can declare the same port. The
box that published it first holds it, and a later box does not forward it.
Activation prints a `warning:` line on stderr for each such port, naming
the box that holds it. The text output marks the declared row
`(held by <box>)`, and the document lists the rows under
`shared_port_collisions`, each with `port` and the holding box as `held_by`.
The key is absent when another box holds none of the box's ports.

With `-o json`, a failed run writes one `min/v1/error` object on stderr and
exits non-zero, with no plain-text error line. The `code` field names the
failure: `not_found` for a missing session, `daemon_unreachable`, or
`policy_unavailable`. The code is `output_failed` when the CLI cannot write
its own document to stdout, such as on a full disk. Any other failure has
the code `unspecified`. The `message` field holds the text mode's error
chain, and `hint` says what to do next. An `unspecified` object has no
`hint`. When the
reader closes stdout early, the run writes nothing and exits 141,
the shell's SIGPIPE convention.

### `session hooks`

```
min session hooks <SESSION> [--json]
```

Lists the [lifecycle hooks](./loadouts.md#lifecycle_hooks---scripts-at-session-transition-points)
composed into `SESSION` (a UUID, unique id prefix, or session name), one row per script, with
the transition it runs on, whether it is inline or external, its timeout, and
the loadout or project that declared it.

This shows what will actually run, not what was asked for: the daemon answers
from the session's composition, which holds only the hooks that survived your
[user policy](./user-policy.md). A session activated with `--no-hooks`, or one
whose project you never allow-listed, lists nothing.

Rows are in setup order — the project first, then loadouts in the order they
were applied; teardown runs the reverse. Inline bodies are collapsed to their
first line; `--json` emits the full records.

Answered from the persisted composition, so it works after a daemon restart
and for a session nobody is attached to.

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
that outlives its box is the normal state after [`stop`](#stop), which keeps
records, and a forward that refused such a session would be stranded against
every session that survived a daemon restart. Where the dial has to run
inside the box — an isolated session's own network namespace — the daemon
brings a box that isn't running up for the dial, exactly as
[`session exec`](#session-exec) brings one up for a command. A
`--network host_ip` box shares the daemon's namespace, so its dial needs no
box up: a session nothing has started answers with a refused connection
until something starts the box.

The forward stays in the foreground and ends on `Ctrl-C`, when the session
is destroyed, or when the daemon goes away; the listener and every open relay
close with it. `stop` is not a destroy: it ends a forward only because the
daemon's exit does, and it keeps every session record, so a later
`min net forward` reaches those sessions again.

What the tree proves today is the host-address mode (`--network host_ip`)
end to end: the `net_forward_*` tests drive a real daemon and relay bytes
through a live laptop-side listener. The in-box dial that the isolated modes
(`--network none`, `--network own_ip`) take — a `socat` relay injected into
the box's namespaces — is exercised by the daemon's harness test with a
host-side stand-in relay rather than a real box; a root-integration proof of
that leg (`just test-root-integration`) is still owed to the root lane.

### `net setup`

```
min net setup [--print] [--undo]
```

Host DNS is opt-in. Until you run this command, the hostname proxy serves box
names. The name-surface line that `min session activate` and `min ls` print
ends with a pointer here. A session start never prints or runs the
privileged step.

`min net setup` sets this host up to resolve and reach boxes by name, for
this host's current state. It prints what is missing to stderr. It then
writes a setup script to a private temporary file and runs it with
`sudo sh`, so `sudo` asks for your password once. It removes the file
afterwards and exits with the script's status. On a host that is already set
up, it runs nothing and says so.

The script is plain POSIX `sh` and stops at the first statement that fails.
Its header says what it configures and that it must run as root. A comment
introduces each step. The steps install the resolver hook and the Minimal
box-name service, plus the local range on macOS.

| Flag | Description |
|---|---|
| `--print` | Print the script to stdout instead of running it, with no privilege prompt. Run it later with `sudo sh <file>`. |
| `--undo` | Remove everything the setup step installs on this host. With `--print`, print the removal script instead. |

Setup points at the port the daemon's zone answerer listens on, so it needs a
running daemon that has bound its answerer. It does not start one. With no
daemon reachable, it prints an error and exits 1. Start a session first to
bring the daemon up. On a host where no script can make box names
resolve, it prints why and exits 1.

The box-name service runs as one user for the whole machine. If another user
already installed it, setup refuses before running anything, names that user,
and exits 1. `--print` still prints the script.

`--undo` works without a daemon, and it succeeds on a host that holds none of
the setup. It removes the box-name service and its program copy, the resolver
hook, and on macOS the local range unit. The local range addresses on macOS
stay on the loopback until the next boot. `install.sh --uninstall` points at
`min net setup --undo` while any of these host files remain.

### `stop`

```
min stop [-f|--force]
```

Shuts down the `minimald` daemon. `--force` shuts down even if active
sessions exist. This stops the daemon backend that hosts sessions, and the
sessions themselves survive it (contrast
[`session destroy`](#session-destroy), which removes one session and leaves the
daemon running).

`stop` stays bare at the top level — a deliberate exception to the
`min <noun> <verb>` convention: it acts on the daemon, not on any session.

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
min bug [-o <OUTPUT>] [--upload [--context <TEXT>] [--endpoint <URL>]]
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

### `diag`

```
min diag collect [<bug options>]
min diag upload <PATH> [--context <TEXT>] [--endpoint <URL>]
min diag delete <ID> <TOKEN> [--endpoint <URL>]
```

`diag collect` is [`bug`](#bug) under another name and takes the same
options.

`diag upload` sends a bundle that you collected earlier. Use it for a
bundle someone gave you, or for one you collected while the portal was
unreachable. It prints the same lines as `bug --upload`.

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
locally — its commit is not re-pinned. The next `min session activate`
materializes the new closure, which can take several minutes on the first
activate. When no pin has moved it reports that and leaves `minimal.toml`
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
exists at the time a static script would be written. Every argument documented
as "UUID, unique id prefix, or session name" completes this way: `session attach`,
`session exec`, `session run`, `session destroy`, `session rename`, and
`session policy`.

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

Only the `connect` capability is implemented: on `connect`, the helper
opens an exec channel to `minimald` over its Unix domain socket (the same
transport the rest of the CLI uses) and bridges git's pack-protocol
conversation across it; no external `ssh` or `socat` involved. Only the
two pack services (`git-upload-pack`, `git-receive-pack`) are accepted.
If the daemon is not running, the helper starts it, using default global
flags (git invokes helpers without any of `min`'s own flags).
