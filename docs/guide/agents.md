---
description: Run AI coding agents like Claude Code inside an isolated session with declared tools and host credentials.
---

# Agent shell

Minimal can sandbox AI coding agents the same way it sandboxes your dev tools: an agent runs inside a [session](./dev-shell.md), with access to your source code and only the tools and host state you declare.

## Example: Claude Code

This documentation site is itself built and maintained using Claude Code inside a Minimal session. Add the agent's package to the project's `[session]` block:

```toml
[session]
packages = ["claude-code", "base"]
```

Then activate the session and run the agent inside it:

```shell
$ min activate --attach .
$ claude
```

Claude Code launches inside the session with your project's source code and a read-only system containing the `claude-code` binary and core utilities from `base`. The session has no additional access to anything on your host system unless you explicitly declare it.

Note that sessions are driven interactively: attaching needs a terminal, and the non-interactive `min attach -c` channel accepts only `min run <task>` invocations. Launch the agent from inside an attached shell as shown above, rather than scripting it from the host.

## Adding more tools

Agents often need additional tools to be effective. Add packages to the `[session]` block just like any other:

```toml
[session]
packages = ["claude-code", "base", "git", "curl"]
```

## Passing through host credentials

Use `patches` to give the agent access to host files it needs, like authentication state. Each patch maps a host `source` to a `dest` under the session user's home directory:

```toml
[session]
packages = ["claude-code", "base", "git"]
patches = [
    { source = "~/.gitconfig", dest = "~/.gitconfig" },
    { source = "~/.ssh",       dest = "~/.ssh" },
]
```

Environment variables can be inherited from the host as well, under `[session.vars]`:

```toml
[session.vars]
ANTHROPIC_API_KEY = { inherit = true }
```

## Why sandbox agents?

Running an AI agent in a Minimal session means it can only access the tools and files you declare. It cannot install arbitrary software, read unrelated files, or modify your system. This is the same isolation model that Minimal applies to builds and dev shells, applied to agents.
