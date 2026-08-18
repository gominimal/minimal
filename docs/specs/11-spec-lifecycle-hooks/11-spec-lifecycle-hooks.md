---
id: spec-lifecycle-hooks
title: "Lifecycle hooks: user- and project-defined scripts at session transitions"
kind: spec
status: shipped
tracking-issue:
supersedes:
---

# Lifecycle hooks: user- and project-defined scripts at session transitions

## Context

Lifecycle hooks are a feature of session composables (loadouts, projects) that
lets a user define arbitrary code to execute at a session's state transitions.
Hooks execute inside the session's sandbox.

This document is the as-shipped design. It began as a pre-implementation spec
and has been reconciled against the implementation: where building it revealed
the original design to be wrong or impossible, the text describes what shipped
and says why it differs. Those points are marked **Changed from the original
design**, and are the parts worth reading if you have seen the earlier draft.

## User stories

As a user I want to be able to…

- Perform arbitrary actions to set up my development environment when it is
  created
- Perform arbitrary actions to set up my development environment when I
  connect to it
- Perform arbitrary actions to tear down my development environment when I
  disconnect from it
- Perform arbitrary actions to tear down my development environment when I
  destroy it
- Disable lifecycle hooks entirely on a session-by-session basis
- List all lifecycle hooks associated with my session and determine where they
  were defined

As a project maintainer I want to be able to…

- Do everything a user might want for environment set-up and tear-down,
  consistently between developers
- Have project-level hooks take precedence over user-level ones (first to set
  up, last to tear down)

As a lifecycle hook author I want to be able to…

- Have access to all packages, variables, and files composed into the sandbox
- Have access to additional metadata provided by minimal with additional
  context
- Define hooks in a shell, or in another interpreter of my choosing
- Define hooks inline in a loadout or project (`minimal.toml`) file
- Have write access to the sandbox filesystem
- Have `on_attach` output reach the terminal I am attached to

## Solution

### Declaration

Hooks are declared in loadouts and in projects (`minimal.toml`). Each may
declare any number. A lifecycle hook consists of an optional string
description and a set of optional hook scripts, one per transition. A hook
must define at least one script to be valid; an empty one is a fatal error at
deserialization.

A hook script is either an inline script body or a path to a script file.
Both are strings, so a `type` field labels which. Loadout script paths resolve
against a directory in the user's loadouts directory named after the loadout;
project script paths resolve against the project root. Paths may not traverse
symlinks and may not contain `..`.

Each hook script takes an optional `timeout`, defaulting to 60 seconds.

#### Transitions

| Transition | Fires when |
|---|---|
| `on_activate` | the session is created |
| `on_destroy` | the session is destroyed |
| `on_attach` | a client attaches |
| `on_detach` | a client detaches |

```toml
[[lifecycle_hooks]]
on_activate = { type = "external", value = "activate.sh" }
on_destroy  = { type = "external", value = "teardown.sh" }
on_attach   = { type = "external", value = "attach.sh" }
on_detach   = { type = "external", value = "detach.sh" }

[[lifecycle_hooks]]
description = "warm the tree-sitter grammar cache"
on_activate = { type = "inline", value = "hx --grammar fetch >/dev/null 2>&1 || true", timeout = 120 }
```

In a `minimal.toml` the section is prefixed with `session.`.

`on_failure` was an earlier spelling that never executed. It is rejected by
name at parse time with an error pointing at `on_destroy`, rather than being
silently dropped — the hook deserializer otherwise ignores unrecognized keys,
which would lose the script without saying so. A composition snapshot that
still carries one loads, discards it, and logs a warning.

### Interpreter

**Changed from the original design.** The original specified bash. Hook
bodies run under POSIX `sh` unless they open with a shebang, in which case
they run under what it names.

The contract is `sh`, not any one shell's extensions, so a hook that works in
one session keeps working in a session whose `sh` is leaner. A hook wanting
more says so the way every hook author already knows:

```toml
on_activate = { type = "inline", value = "#!/usr/bin/env fish\nset -gx ...\n" }
```

The shebang is parsed exactly as `execve(2)` parses one — the interpreter is
the first word, everything after it is a **single** argument. That is what
makes `#!/usr/bin/env -S python3 -u` work: `env` receives `-S python3 -u`
whole and splits it itself. Splitting per-word here would hand `env` a `-S`
with only `python3` attached.

Two consequences of reading the shebang ourselves rather than letting a kernel
do it (see *Execution*):

- The interpreter must accept a program on standard input. Every shell and
  scripting language in common use does; one that insists on a file argument
  (`awk -f`) cannot be driven this way.
- A relative interpreter path would resolve against the *daemon's* working
  directory, not the session's. Name an absolute path, or a bare command for
  `env` to find on the session's `PATH`.

There is no quoting in a shebang line on any system, so an interpreter path
cannot contain spaces.

### External scripts

A script path resolves against an anchor determined by where the hook was
declared: a loadout named `dev` anchors at a `dev` directory beside
`dev.toml`; a project anchors at the project root. The anchor cannot be
decided when the file is parsed, because the same hook type is deserialized
from both kinds of file — it is decided from the hook's recorded source.

Validation runs on the client, before the session is created, so a mistyped
path fails locally and immediately rather than partway through an activation.
A script must resolve to a regular file underneath its anchor, must not climb
out of it, and must not traverse a symlink at any component. Symlinks are
rejected rather than followed, so canonicalizing the path is not sufficient —
each component is checked as it is walked.

Transport depends on origin:

- **Inline** scripts need none; their bodies travel inside the composition.
- **Project** scripts travel with the project tree, which activation uploads
  into the session workspace, and the daemon resolves them there.
- **Loadout** scripts are uploaded during activation, in a stream alongside
  the patch upload.

That upload is a separate archive stream rather than extra entries in the
patch stream. Patch destinations are arbitrary paths under the session home,
so any prefix reserved inside the patch archive is one a user could
legitimately claim; and the daemon copies the entire staged patch tree into
the home directory at finalize, where hook scripts do not belong. The stream
reuses the existing archive builder and the existing atomic unpack-and-swap,
landing scripts in a `hooks` directory beside `patches` in the session
workspace.

The daemon's finalize gate waits for that upload only for hooks that actually
arrive by it. A project's external script is **not** counted: it comes with
the project tree, so gating on a marker that is never sent would mean no
project could declare an external hook script at all.

### Client-side pre-flight

**Changed from the original design.** The original routed these checks
through `mip check`. `mip` is legacy, so the checks run on the client at
activation instead — the same "fail on this machine, before a session exists"
property, without a command nobody runs.

Before the daemon is contacted, activation validates:

- every **loadout** external script, as part of staging it;
- every **project** external script, against the project root — validated but
  not staged, since the project tree carries it;
- every **inline** script is non-empty, which can only ever be a typo: it
  declares a transition and then does nothing at it.

Without this a bad project hook surfaces only when it runs, which for
`on_destroy` is at teardown, long after the mistake.

### Composition and ordering

The hooks the client composes from loadouts and the hooks the daemon composes
from the project meet in one composition. The daemon composes the project
first and appends the client's contribution, so the composed list is ordered
project-first, loadouts-after. That ordering is a guaranteed property,
documented and covered by tests in both directions.

Setup hooks run in that order; teardown hooks run in reverse. Project
maintainers get the precedence the design calls for: project hooks set up
first and tear down last. Among loadouts, hooks run in selection order.

### Execution

Hooks run as processes inside the session's sandbox, joining the session
process's namespaces — not a freshly built sandbox. A new sandbox would share
the rootfs and the persistent home and workspace mounts but get its own
`/tmp`, its own `/dev`, and its own network namespace; on an own-IP session
that fresh netns has no tap relayed to the switch, so a hook that fetches
anything would fail there and succeed on a host-net session.

**Changed from the original design.** The original wrote inline scripts into
the sandbox as executable files. Scripts are instead **piped to the
interpreter on standard input**. The staged-scripts directory is on the daemon
filesystem and is not mounted into the sandbox, so a path would not resolve
there; reading the bytes daemon-side collapses inline and external onto one
code path; and it avoids materialising user-controlled executables inside the
session. It also settles standard input: the script occupies it, so a hook
cannot read the user's keystrokes out of an attached terminal. The cost is
that no kernel sees the shebang, so minimal parses it (see *Interpreter*).

`on_attach` runs on the same pseudo-terminal as the user's shell; its output
reaches the attached client the way the shell's does. The other three have no
terminal, and their output is captured and logged.

Every hook receives the session's composed environment plus:

| Variable | Value |
|---|---|
| `MINIMAL_SESSION_ID` | The session's id |
| `MINIMAL_SESSION_NAME` | Its display name |
| `MINIMAL_HOOK_EVENT` | The transition: `on_activate`, `on_destroy`, `on_attach`, `on_detach` |
| `MINIMAL_HOOK_SOURCE_KIND` | `loadout` or `project`, for branching |
| `MINIMAL_HOOK_SOURCE_NAME` | The loadout's name, or the project's path **as the client refers to it** |
| `MINIMAL_HOOK_INDEX` / `MINIMAL_HOOK_COUNT` | Position within this transition's run, 1-based |

### Trigger points

**`on_activate`** runs when a session is finalized, after its patches are
materialized into the sandbox home and before the session is marked
attachable. The sandbox has not been built at that point — the daemon builds
it lazily on first attach — so finalization builds it. That is the same
cache-backed package resolution the first attach would perform, so the attach
that follows is not slower for it. Setup work, and its failures, land at
`min session activate`. The finalize response carries one entry per hook that
ran, so the client can report it: an activate hook is headless, and without
that the only trace is the daemon log.

**`on_attach`** runs when a channel is bound to a session host, after the
binding is installed so its output reaches the client. This covers the attach
that creates the host and every later re-attach.

**`on_destroy`** runs when a session is destroyed, before its host is stopped,
since the sandbox must still exist for a hook to run in it. A session whose
actor is not running has one started for the purpose — teardown is the actor's
job, and taking the shortcut of deleting the record directly skips the hooks
silently for every session whose actor has been reaped, which after a daemon
restart is all of them.

**`on_detach`** — **changed from the original design in three ways.**

*It is headless.* The original had detach hooks run on the user's terminal.
That is not achievable on the dominant path: leaving a session by exiting its
shell means the shell's exit is precisely what ended the sandbox, so by the
time a detach is observable there is no terminal and no namespace left to run
in. Detach hooks run headlessly like activate and destroy, and the actor mints
a host for them when none is live. `on_attach` still runs on the terminal.

*Exiting the shell and keeping the session is a detach.* The original said a
binding that ends because the shell exited "flows into destruction instead."
That path offers Keep or Delete; Keep leaves the session alive, which is a
detach by any reading. Delete flows into destruction and runs `on_destroy`.

*Daemon shutdown does not fire it.* The original said it should. Asking for
detach hooks reaches the sessions manager, which brings a session's actor up
from disk on demand and would mint a sandbox to run them in — the opposite of
what shutdown is doing. The session is being suspended, not left.

A binding displaced by a second connection does not fire detach either: that
is a replacement, not a departure. It is also unsafe to try — the attach that
displaces it awaits the old binding's teardown from inside the host's own
message loop, so a detach hook there deadlocks against the host it needs.

### Failure handling

Every hook runs under a timeout. Without one, a hook that hangs would wedge an
attach or make a session impossible to destroy. The timeout bounds the write
of the script to the interpreter as well as the wait for it, since an
interpreter that never reads its input would otherwise block before the
timeout applied.

A hook killed by its timeout takes the interpreter with it. Anything the
interpreter itself backgrounded survives, bounded instead by the session,
whose PID namespace takes it when the shell exits.

An activate hook that fails or times out **fails the activation**. The session
does not become attachable, and the error names the hook's source and what it
printed. A development environment whose setup script failed is not the
environment the user asked for.

Attach, detach, and destroy hooks never block their transition. A failing
attach hook warns and the attach proceeds; a failing detach or destroy hook is
logged and teardown proceeds. A session must always be destroyable.

**Added since the original design.** Each teardown transition runs all of its
hooks under a single shared time budget — `on_detach` and `on_destroy` get a
budget each, not one between them. A per-script cap bounds nothing in
aggregate, because nothing limits how many hooks a composition may carry: N
hooks at the cap would hold a destroy open for N × the cap, which is the exact
failure the cap exists to prevent. A hook that runs into the end of the budget
is cut short and says so; one the budget leaves no room for is reported as not
run. The log distinguishes both from a hook that exhausted its own `timeout`.
The launch of a sandbox for a teardown hook is bounded the same way.

### Disabling and listing

Hooks are disabled per session with `min session activate --no-hooks`. The
flag is persisted on the session record, not only applied to the composition,
because attach, detach, and destroy fire from processes that never saw the
original command. The client also omits hooks from what it composes and
uploads, so such a session has no scripts staged for it at all.

`min session hooks <session>` lists every hook composed into a session: the
transition, the description, whether it is inline or external, and the loadout
or project that declared it. It is served from the daemon's persisted
composition snapshot, so it works after a daemon restart and without an
attached session, and it reads that snapshot from the store rather than
through the session's actor — a report has no business starting the thing it
reports on.

### User policy

A project's hooks are arbitrary code from someone else, so a project must be
allow-listed by path in `user_policy.toml` before any hook it declares will
run. A loadout's hooks are the user's own file and are not gated. Packages
cannot declare hooks; any that appear are denied outright.

Silence is not consent: a project matching no rule is undecided, reaches the
prompt, and under `--no-prompt` fails the activation with a snippet naming the
project.

The path matched is the project **as the client refers to it**, not the
daemon's per-session copy of the tree. A per-session path would be different
on every activation, making a permanent allow rule unmatchable and
`--no-prompt` unusable.

Policy patterns are globs, so the prompt escapes the path before storing it.
Stored raw, a path containing glob metacharacters would either match its
siblings — approving code execution nobody was asked about — or match nothing
at all, leaving a rule that silently never fires.

## Testing

Schema and path validation are unit-tested in the crate owning the types:
TOML round-trips for all four transitions, rejection of hooks with no scripts,
and each path rule.

Composition tests cover the ordering guarantee in both directions and confirm
that a session activated with hooks disabled composes none.

Daemon tests cover the activate, detach, and destroy trigger points against a
mock sandbox: that hooks dispatch at the right moment, that a failing activate
hook prevents a session from becoming attachable, that teardown hooks run for
a session whose actor is idle, and that the teardown budget bounds a run in
aggregate. The upload path is covered like the patch upload it mirrors.

`on_attach` has no daemon-level test. It is the one transition that runs in
the user's shell, so it resolves the sandbox's session leader from `/proc`,
and the mock launcher's program is a childless shell with no leader to find.
Faking one would prove the call happens but not the property the transition
exists for.

The session end-to-end harness is the only layer that exercises the real
namespace injection, and it covers: all four transitions in one session
lifecycle; shebang dispatch to a non-default interpreter; an external script
through the upload and staging path; loadout-declared hooks; the three
refusals (un-allow-listed project, failing activate, `--no-hooks`); and
survival across a daemon restart. `on_attach` is asserted from the attached
terminal's transcript, driven through a real pty.

On VM lanes the daemon runs inside the guest and logs to a guest tmpfs, so the
assertions that read a hook's captured output are native-lane only. What runs
everywhere: that a failing teardown hook still tears the session down, and
that `on_detach` ran — read back through the session rather than from a log.

## Threat model

| Threat | Mitigation | Notes |
|---|---|---|
| A malicious project provides a hook that exfiltrates sensitive data | The project must be allow-listed in the user policy before any hook runs | Shared responsibility between minimal and users |
| A malicious project infiltrates user data into a session for a hook to exfiltrate | Files and variables carrying user data must themselves be allow-listed before entering the session | Shared responsibility between minimal and users |
| A malicious project denies service with a very large timeout and an infinite loop | Hard cap of 300 seconds on any hook's declared timeout, plus a per-transition teardown budget bounding all of a transition's hooks together | |
| A malicious project steals compute by running it in a hook | Allow-listing, plus the timeout cap and teardown budget | |
| A hook script path escapes its anchor to read a file outside the session | Path validation refuses `..` and absolute paths at construction, refuses a symlink at any component when staged, and re-checks containment on the daemon before reading | The daemon check is defence in depth: it is currently unreachable, and tested directly for that reason |

Lifecycle hooks fundamentally provide arbitrary code execution. Beyond the
above, the best that can be done is to make the user aware that a project
wants to run code, and to let them decline until they have reviewed it.

## Known gaps

- A project's external hook script is not uploaded when the project tree is
  not (`--sync none`). The client-side pre-flight catches a *missing* script,
  but a present one that never reaches the daemon fails when the hook runs.
- The persisted composition snapshot is not version-gated on read: a snapshot
  claiming a version newer than this daemon understands is parsed rather than
  refused.
- A composition snapshot written before the provenance fix carries the daemon's
  per-session workspace path as the project's identity. Script resolution
  ignores that path, so the visible effect is limited to
  `MINIMAL_HOOK_SOURCE_NAME` and hook diagnostics for sessions created before
  the fix.
