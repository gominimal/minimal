---
description: What a Minimal session is, how a provider creates and hosts one, and how sessions compose from your project config plus loadouts.
---

# Sessions

A **session** is Minimal's isolated developer environment: a sandboxed place to
work on a project, with exactly the tools and configuration that project
declares, and nothing else from your host leaking in unless you allow it. You
create a session for a project, attach a shell to it, and do your work inside
it. When you are done you tear it down.

Sessions are managed by `min`, the Minimal session CLI. This guide explains
what a session is, the provider that hosts it, how one is created and entered,
how it is composed from your project config plus loadouts, and how sessions
relate to sandboxes and tasks. For the exact flags of every command mentioned
here, see the [`min` command reference](../reference/cli-min.md).

## Why sessions

Working directly on your host mixes every project's tools, environment
variables, and stray state into one global namespace. Minimal instead gives
each project its own isolated environment:

- **Reproducible.** A session's tools come from Minimal packages, built or
  fetched deterministically from your project's declarative config. Two people
  who activate the same project get the same environment.
- **Isolated.** The session runs in a sandbox. Your host filesystem, host
  environment, and other projects are not visible inside it unless the project
  or your policy brings them in.
- **Declarative.** What a session contains is derived from files you commit
  (your `minimal.toml` and the packages it references), not from setup steps you
  run by hand and hope to remember.

## The provider and session model

Two roles are in play whenever you use sessions:

- A **session** is the isolated environment itself: a single sandboxed
  workspace tied to one project directory.
- A **provider** is the daemon that creates and hosts sessions. On Linux the
  provider is `minimald`, an SSH server that owns session lifecycle and hosts
  the shells and executions that run inside each session.

The `min` CLI is a thin client. It discovers the provider's socket,
auto-spawns a provider if none is running, and speaks to it over SSH on a UNIX
domain socket. You rarely interact with the provider directly: running a `min`
command is enough, and the provider comes up on demand.

On platforms where `minimald` cannot run natively (macOS, or a Linux setup that
opts into it), a second daemon, `minvmd`, boots a lightweight Linux microVM and
runs `minimald` inside it, bridging the connection so `min` reaches the session
without needing to know a VM is involved. From the user's point of view the
model is identical: a provider creates and hosts sessions, and `min` talks to
it.

## Creating and entering a session

You create a session by **activating** a project. From the project directory:

```console
$ min activate --attach .
```

`min activate` takes a project path that defaults to the current directory, so
the trailing `.` is the project you are standing in. `--attach` drops you
straight into a shell in the new session once it is ready. Without `--attach`,
activation prints the new session's id and returns, leaving the session running
in the background for you to attach to later.

A few things happen during activation:

1. `min` resolves the project path and, if the project has no `minimal.toml`
   yet, offers to scaffold one (the session still comes up with a default
   environment either way).
2. Your project files are uploaded into the session's workspace on the provider
   so it can read your config. You can opt out of this with `--sync none`.
3. The session is composed from your project config plus any loadouts (see the
   next section), and any environment values that need your approval are gated
   against your user policy.

Useful activation options:

- `--name <NAME>` gives the session a stable, human-friendly name you can use
  in place of its id.
- `--network <MODE>` selects the network mode: `no-net`, `host-net` (the
  default), or `own-ip` (a dedicated IP on Minimal's virtual subnet). With
  `own-ip` you can also publish `--ingress EXT:INT[/PROTO]` port mappings.
- `--loadout <NAME>` applies a named loadout (repeatable); `--no-loadouts`
  applies none.
- `--no-prompt` fails instead of prompting when composition surfaces items your
  policy cannot auto-decide, printing a ready-to-paste policy snippet instead.
  This mode is selected automatically when stdin or stderr is not a terminal, so
  activation is safe to run from scripts and CI.

To enter a session that already exists, **attach** to it by id or name:

```console
$ min attach my-session
```

Attach opens an interactive shell inside the session. To run a single command
non-interactively instead of opening a shell, pass `--command` (short `-c`):

```console
$ min attach my-session -c 'cargo test'
```

Both forms run inside the session's sandbox, with your tools on `PATH` and your
project directory mapped into the same path it has on the host.

## How a session is composed

A session's contents are not hand-configured. They are **composed** from
several declarative sources into a single result the provider applies when it
mints your shell. The composition is a pipeline that spans the `min` client and
the provider:

1. **Your loadouts, composed on the client.** A loadout is a reusable bundle of
   session contributions (environment variables, file mappings, and package
   selections) kept in your user config. `min` composes the loadouts you
   selected, resolving values and gating them against your user policy. See the
   [loadouts guide](./loadouts.md) for how to write and select them.
2. **Your project config, collected on the provider.** The provider reads your
   project's `minimal.toml` from the uploaded workspace: its session block, the
   packages the project's stack declares as build and runtime dependencies, and
   any environment the stack contributes.
3. **Package contributions, collected on the provider.** Packages in the
   project's dependency closure can contribute environment wiring and file
   mappings of their own. These are collected alongside the project's own
   contributions.

The provider routes anything that needs your approval (chiefly environment
values sourced from your own environment, and file patches) back to `min`,
which gates them against your user policy and, when the policy cannot decide,
prompts you. Approved items, plus the selections that were already decided, are
assembled into the final composition. The result carries four kinds of item:

- **Variables**: environment variables set inside the session.
- **File patches**: files mapped into the session's home.
- **Packages**: the tools and libraries that make up the environment.
- **Lifecycle hooks**: scripts the session runs at defined points.

A key principle: **your user policy is enforced only on the client.** The
provider never runs your policy. It forwards the items that need a decision, and
`min` applies your allow, deny, and ignore rules, prompting you for anything
left undecided. Every surviving item keeps a record of which source contributed
it, so a session's contents can always be traced back to your loadout, your
project, or a specific package.

Environment values that carry your own environment (for example a variable your
loadout inherits from your shell) are the ones your policy gates, because they
move data from your host into the sandbox. Values a package or project hardcodes
as literals are a matter of that declaration, not of your policy, and pass
through without prompting.

## Session lifecycle

List the sessions the provider is currently hosting:

```console
$ min ls
```

`min ls` prints a table of session ids, names, titles, and last activity, along
with the shared resource pool. `--raw` prints bare ids one per line for
scripting, and `--json` prints the full list as JSON.

Rename a session:

```console
$ min rename my-session backend-work
```

Destroy a session when you are finished with it:

```console
$ min destroy my-session
```

`min destroy` terminates a single session by id or name. `min destroy --all`
tears down every session at once (add `--force` to skip the confirmation).

Stop the provider itself:

```console
$ min stop
```

`min stop` shuts down the `minimald` provider daemon. Because the provider hosts
every session, stopping it ends them all; it refuses to shut down while sessions
are active unless you pass `--force`. Contrast this with `min destroy`, which
removes one session and leaves the provider running to host the rest. Because
`min` auto-spawns a provider on demand, the next `min` command after a stop
simply brings a fresh one back up.

You can inspect a session's effective networking policy as JSON:

```console
$ min session policy my-session
```

And list the loadouts available in your user config:

```console
$ min loadout list
```

## Sessions, sandboxes, and tasks

A session is not itself a sandbox: it is the managed, named environment the
provider hosts. But everything that runs *inside* a session runs in a
**sandbox**, the low-level isolation primitive built from Linux user and mount
namespaces. When you attach a shell, the provider composes a sandbox whose
root filesystem is assembled from the package closure your session needs (each
package's files hardlinked into place), mounts your project directory into it at
its real path, sets the composed environment variables, and launches your shell
there. The sandbox is how the session's isolation and reproducibility are
actually delivered.

**Tasks** are the other thing that runs in a session's sandbox. A task is a
command your project defines in its `minimal.toml`: a named, repeatable
operation (a build step, a test run, a linter) that executes against a sandbox
composed from the packages that task needs. If a needed package is not present,
Minimal builds it or fetches it from a remote cache first, then runs the task in
a freshly composed sandbox with your project directory mapped in. Running a
command through `min attach --command` is the interactive counterpart: an
arbitrary command executed in the session's sandbox rather than a predeclared
task.

The through-line: a **session** is the durable, named environment a provider
hosts; a **sandbox** is the isolated execution context composed from a package
closure; and a **task** is a declared command that runs in such a sandbox. Your
project config and loadouts decide what goes into all three.

## See also

- [`min` command reference](../reference/cli-min.md) for every command and flag.
- [Loadouts](./loadouts.md) for writing and selecting reusable session
  contributions.
