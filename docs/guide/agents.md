---
description: Run AI coding agents like Claude Code inside an isolated session with declared tools and host credentials.
---

# Agent shell

Minimal runs an AI coding agent inside a [session](./dev-shell.md). The agent sees your source code. It gets only the tools and host state you declare.

## Example: Claude Code

This documentation site is itself built and maintained using Claude Code inside a Minimal session. Add the `claude` package to the project's `[defaults.session]` table. It installs Claude Code and its Minimal plugin:

```toml
[defaults.session]
packages = ["claude", "base"]
```

Then activate the session and run the agent inside it:

```shell
$ min session activate --attach .
$ claude
```

Claude Code starts inside the session with your project's source code. The read-only system holds Claude Code, its Minimal plugin, and core utilities from `base`. The session has no additional access to anything on your host system unless you explicitly declare it.

You attach to a session from a terminal. Start the agent from inside the attached shell, not from a script on the host.

## Adding more tools

Agents often need additional tools to be effective. Add packages to the `[defaults.session]` table just like any other:

```toml
[defaults.session]
packages = ["claude", "base", "git", "curl"]
```

## Passing through host credentials

Use `patches` to give the agent access to host files it needs, like authentication state. Each patch maps a host `source` to a `dest` under the session user's home directory:

```toml
[defaults.session]
packages = ["claude", "base", "git"]
patches = [
    { source = "~/.gitconfig", dest = "~/.gitconfig" },
    { source = "~/.ssh",       dest = "~/.ssh" },
]
```

To pass an environment variable from the host, set `inherit` under `[defaults.session.vars]`:

```toml
[defaults.session.vars]
ANTHROPIC_API_KEY = { inherit = true }
```

The agent and any code it runs can use anything you pass through. With a
patched `~/.ssh`, the agent can use your SSH keys. Every process in the session
can read an inherited `ANTHROPIC_API_KEY`. Pass through the minimum the agent
needs. Prefer scoped or short-lived credentials over long-lived ones.
Activation checks each inherited value and each file patch against your user
policy. When your policy cannot decide one, activation asks you before that
value or file enters the session.

## Why sandbox agents?

Running an AI agent in a Minimal session means it can only access the tools and files you declare. It cannot install arbitrary software, read unrelated files, or modify your system. This is the same isolation model that Minimal applies to builds and dev shells, applied to agents.
