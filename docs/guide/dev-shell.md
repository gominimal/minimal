---
description: Launch an isolated interactive development shell with only declared tools. Covers customization, host file access, and environment variables.
---

# Dev shell

Minimal sandboxes your development environment the same way it sandboxes builds and agents. Launch an interactive shell with only the tools you declare, isolated from your host system. Useful for running ad-hoc commands, debugging, or working interactively with your project's toolchain.

## Launch a shell

If your `minimal.toml` has a `shell` task defined (which `mip init` creates by default), you can launch it with:

```shell
$ mip shell
```

This is shorthand for `mip run shell`.

## What's in the sandbox?

The shell sandbox inherits all packages from your [stack](../concepts/stacks.md), plus any packages listed in the task definition. A typical shell task looks like:

```toml
[tasks.shell]
interactive = true
packages = ["base", "git", "curl"]
exec = "bash -l"
```

Inside the sandbox, you have access to your project's source code and all declared tools, but nothing else from the host system. The shell cannot globally install software, read unrelated files, or modify your system. This ensures every developer gets the same isolated environment.

## Customizing your shell

### Add more tools

You can add packages to your shell from the command line:

```shell
$ mip add --task shell ripgrep jq nano
```

This updates your `minimal.toml` automatically. You can also edit the shell task directly:

```toml
[tasks.shell]
interactive = true
packages = ["base", "git", "curl", "nano", "jq", "ripgrep"]
exec = "bash -l"
```

If you need a package mid-session, you can use the [`min` command](../reference/sandbox-operations.md#add) to install it without restarting your
shell or agent.

### Access host files

By default, Minimal mounts your current working directory into the sandbox. Your project files are available at the same path inside the shell, and changes you make are reflected on the host.

For files outside your project directory, use `patches` to map them in:

```toml
[tasks.shell]
packages = ["base", "git"]
exec = "bash -l"
patches.file."~/.gitconfig" = "read-only"
patches.dir."~/.ssh" = "read-only"
```

### Set environment variables

The sandbox starts with a clean environment. Host environment variables are not passed through by default. You can set variables explicitly or inherit them from the host:

```toml
[tasks.shell]
packages = ["base", "git"]
exec = "bash -l"
env_vars.EDITOR = "nano"
env_vars.AWS_PROFILE = { inherit = true }
```

Setting a string value like `EDITOR = "nano"` defines a fixed variable. Using `{ inherit = true }` passes through the value from your host environment, which is useful for credentials or configuration that varies per developer.
