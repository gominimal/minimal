---
description: Enter an isolated interactive development session with only your declared tools. Covers customization, host file access, and environment variables.
---

# Dev shell

Your dev shell in Minimal is a **session**: a long-lived, isolated development environment for a project, driven by the `min` CLI. It gives you an interactive shell with only the tools you declare, isolated from your host system. Use it for everyday development, running ad-hoc commands, debugging, or working interactively with your project's toolchain.

## Launch a shell

From your project directory, activate a session and attach to it in one step:

```shell
$ min activate --attach .
```

This creates a session for the project and drops you into its interactive shell. The path argument defaults to the current directory, so `min activate --attach` on its own works too.

Your project files are mapped into the session at the same path, so edits you make inside the shell are reflected on the host.

## What's in the session?

A session's tools come from the project's `[session]` block in `minimal.toml`. List the packages every contributor should have when working on this codebase:

```toml
[session]
packages = ["git", "curl", "ripgrep"]
```

Inside the session you have access to your project's source code and exactly these declared tools, but nothing else from the host system. The session cannot globally install software, read unrelated files, or modify your system. Every developer working on the project gets the same isolated environment.

## Customizing your session

### Add more tools

Add packages to the project's `[session]` block so everyone picks them up:

```toml
[session]
packages = ["git", "curl", "ripgrep", "jq", "nano"]
```

If you need a package mid-session, without editing config or restarting your shell, run `min add` from inside the running session:

```shell
$ min add nano
```

This installs the tool into the running session. See the [`min` in-sandbox commands](../reference/sandbox-operations.md#add) for the full helper reference.

### Access host files

By default, only your project directory is available inside the session. To bring specific host files or directories in, declare `patches` in the `[session]` block. Each patch names a `source` on the host and a `dest` under the session user's home directory:

```toml
[session]
packages = ["git"]
patches = [
    { source = "~/.gitconfig", dest = "~/.gitconfig" },
    { source = "~/.ssh",       dest = "~/.ssh" },
]
```

### Set environment variables

The session starts with a clean environment; host environment variables are not passed through by default. Set variables explicitly, or inherit them from the host, under `[session.vars]`:

```toml
[session.vars]
EDITOR = "nano"
AWS_PROFILE = { inherit = true }
```

A string value like `EDITOR = "nano"` defines a fixed variable. Using `{ inherit = true }` passes through the value from your host environment, which is useful for credentials or configuration that varies per developer.

### Run setup on activation

To run setup steps when a session comes up, declare lifecycle hooks in the `[session]` block:

```toml
[[session.lifecycle_hooks]]
on_activate = { type = "inline", value = "cargo fetch >/dev/null 2>&1 || true" }
```

## Session lifecycle

Exit the shell to detach; the session keeps running in the background. To reattach, list, or tear down sessions:

```shell
$ min attach     # reattach to a session (resolves from the current directory)
$ min ls         # list sessions
$ min destroy    # terminate a session
```

For running one-shot commands in their own sandbox rather than an interactive session, see [Tasks](./tasks.md).
