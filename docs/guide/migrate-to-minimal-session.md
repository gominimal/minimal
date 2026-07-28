---
description: Migration to the new architecture after v0.5.0 release for Linux and macOS.
---

# Minimal Sessions Migration Guide

If you are using a release of Minimal **older than v0.5.0**, you will need to update your configuration before using the Sessions architecture. You can check the version with `minimal --version` or `min --version`.

## Upgrade from v0.4.1 or older

WARNING: `tasks` are not supported by v0.5.0. If you rely on `tasks` for non-interactive, job-like workflows, it is recommended to keep using `minimal` (<=v0.4.1) for tasks, and `min` (v0.5.0) for sessions.

Going forward, the Minimal command will become `min`, and will not conflict with the existing `minimal` command. 

You can use the following to uninstall `minimal`.
```bash
./.minimal/shim/uninstall.sh
```

To install `min`, see [install](./install.md).


## minimal.toml

Prior to v0.5.0, `minimal.toml` had the following sections: upstream, harness, defaults, and tasks. 

```toml
[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "11a8cf050340e3946171476b22ff4b3a8e08e66b"

[harness]
use = "shell"

[defaults]
state_key = "dev"

[tasks.shell]
interactive = true
packages = ["base"]
exec = "bash --noprofile -l"
```

### [upstream]

The upstream section is unchanged.

### [harness]

The harness section is renamed to `stack`. The functionalities of `stack` remain unchanged. For more information on stack, see [stack](../concepts/stacks.md).

### [defaults]

The defaults section is unchanged.

### [outputs]

The outputs section is unchanged.

### [tasks]

Going forward, interactive tasks (bash, shell, interactive agent sessions) are supported by `session` definitions. Non-interactive tasks (test, build) are currently not supported by v0.5.0.

### [session] (NEW)

Session is a new concept in v0.5.0. `[session]` will define interactive environments where shell, bash, and interactive agent tasks. Task defined with 
```toml
interactive = true
```
should be migrated to a session definition. For how to define a session, please refer to [the session configuration in minimal.toml](../reference/minimal-dot-toml.md#session---what-every-contributors-session-gets-session). 
