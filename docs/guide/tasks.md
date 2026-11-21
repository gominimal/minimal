---
description: Define named tasks in minimal.toml that run commands in sandboxed environments with specific packages and env vars.
---

# Tasks

Tasks define commands that run in a [sandbox](../concepts/sandboxing.md) with exactly your declared dependencies. Every developer on your team runs the same task in the same environment.

A task is a **one-shot** command that runs in its own fresh sandbox and exits, driven by the `mip` CLI (Linux-only; inside a session, `min task run <name>` runs the same tasks on any platform; from the host, `min session run <session> <name>` runs one against a session you already have; the bare `min run <name>` is a legacy alias). That makes it different from an interactive [dev session](./dev-shell.md), which is a long-lived environment you attach to with `min`. Reach for a task to run builds, tests, linters, and deploys; reach for a session for interactive development.

## Defining a task

Tasks are defined in your `minimal.toml` and run with `mip run <name>`:

```toml
[tasks.lint]
packages = ["python", "ruff"]
exec = "ruff check ."

[tasks.greet]
bash = "echo Hello from $(uname -s) && date"
```

```shell
$ mip run greet
Hello from Linux
Tue Mar 17 12:00:00 UTC 2026
```

Use `exec` for a single command, or `bash` for shell scripts.

## Environment variables

Set environment variables directly, or inherit them from the host:

```toml
[tasks.deploy]
packages = ["railway"]
exec = "railway up"
env_vars.RAILS_ENV = "production"
env_vars.GITHUB_TOKEN = { inherit = true }
```

`inherit = true` copies the value from your host environment into the task's
sandbox, where every command the task runs can read it — including scripts the
repository itself provides. Inherit sparingly, and prefer scoped, short-lived
tokens over long-lived ambient credentials.

## Mapping host files

Use `patches` to give a task access to specific files or directories on the host:

```toml
[tasks.deploy]
packages = ["railway"]
exec = "railway up"
patches.dir."~/.config/railway" = "read-only"
```

Map host files `read-only` unless the task genuinely needs to write them: a
`read-write` mapping lets anything the task runs modify those host files in
place.

See the [tasks reference](../reference/tasks.md) for the full schema.
