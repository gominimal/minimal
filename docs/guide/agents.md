---
description: Sandbox AI coding agents like Claude Code in isolated environments with declared tools and host credentials.
---

# Agent shell

Minimal can sandbox AI coding agents the same way it sandboxes your builds and dev tools. Define a task with the agent's package, and it runs in an isolated environment with access to your source code and only the tools you declare.

## Example: Claude Code

This documentation site is itself built and maintained using Claude Code inside Minimal. Here is the task definition from its `minimal.toml`:

```toml
[tasks.claude]
interactive = true
packages = ["claude-code", "base"]
exec = "claude"
patches.dir."~/.claude" = "read-write"
```

Run it with:

```shell
$ mip run claude
```

Claude Code launches inside a sandbox with your project's source code, `~/.claude` state files, and a read-only system containing the `claude-code` binary and core utilities from `base`. The sandbox has no additional access to anything on your host system unless you explicitly declare it.

## Adding more tools

Agents often need additional tools to be effective. Add packages to the task just like any other:

```toml
[tasks.claude]
packages = ["claude-code", "base", "git", "curl"]
exec = "claude"
```

## Passing through host credentials

Use `patches` to give the agent access to host files it needs, like authentication state:

```toml
[tasks.claude]
packages = ["claude-code", "base", "git"]
exec = "claude"
patches.file."~/.gitconfig" = "read-only"
patches.dir."~/.ssh" = "read-only"
```

Environment variables can be inherited from the host as well:

```toml
[tasks.claude]
packages = ["claude-code", "base"]
exec = "claude"
env_vars.ANTHROPIC_API_KEY = { inherit = true }
```

## Why sandbox agents?

Running an AI agent in a Minimal sandbox means it can only access the tools and files you declare. It cannot install arbitrary software, read unrelated files, or modify your system. This is the same isolation model that Minimal applies to builds and dev shells, applied to agents.
