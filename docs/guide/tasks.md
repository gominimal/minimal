---
description: Define named tasks in minimal.toml that run commands in sandboxed environments with specific packages and env vars.
---

# Tasks

Tasks define commands that run in a [sandbox](../concepts/sandboxing.md) with exactly your declared dependencies. Every developer on your team runs the same task in the same environment.

## Defining a task

Tasks are defined in your `minimal.toml` and run with `mip run <name>`:

```toml
[tasks.claude]
packages = ["claude-code", "base"]
exec = "claude"

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

## Mapping host files

Use `patches` to give a task access to specific files or directories on the host:

```toml
[tasks.deploy]
packages = ["railway"]
exec = "railway up"
patches.dir."~/.config/railway" = "read-write"
```

See the [tasks reference](../reference/tasks.md) for the full schema.
