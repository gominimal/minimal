---
description: Migration to the new architecture after v0.5.0 release for Linux and macOS.
---

# Minimal Sessions Migration Guide

If you are using a release of Minimal **older than v0.5.0**, you will need to update your configuration before using the Sessions architecture. You can check the version with `minimal --version` or `min --version`.

## Upgrade from v0.4.1 or older

WARNING: `tasks` are not supported by v0.5.0. If you rely on `tasks` for non-interactive, job-like workflows, keep `minimal` (<=v0.4.1) installed for tasks and install `min` (v0.5.0) for sessions.

Going forward, the Minimal command will become `min`, and will not conflict with the legacy `minimal` command. The installer for legacy `minimal` will no longer be available after v0.5.0 is released. However, `minimal` will remain operational for the foreseeable future.

If you no longer need the legacy `minimal` command, you can uninstall it with:
```shell
./.minimal/shim/uninstall.sh
```

To install `min`, see [install](./install.md).

### Linux
To maintain backward compatibility for ephemeral build systems on Linux, the installer for `min` will also install a version of Minimal that's functionally identical to `minimal`, and renamed to `mip` (Minimal-In-Process). All commands available to `minimal` are available in `mip`. Any commands using `minimal` should be upgraded to use `mip`. For the complete documentation on `mip`, see [cli-mip](../reference/cli-mip.md).
```
minimal run --> mip run
minimal update --> mip update
minimal add --> mip add
minimal status --> mip status
minimal build --> mip build
minimal test --> mip test
minimal materialize --> mip materialize
minimal package --> mip package
minimal cache --> mip cache
minimal check --> mip check
minimal dep --> mip dep
minimal completions --> mip completions
minimal help --> mip help
```
The in-VM command `min add` remains unchanged.

## minimal.toml

Prior to v0.5.0, `minimal.toml` had the following sections: upstream, harness, defaults, outputs, and tasks. 

### [upstream]

The upstream section is unchanged.

### [harness]

The harness section is renamed to `stack`. The functionalities of `stack` remain unchanged. For more information on stack, see [stack](../concepts/stacks.md).

### [defaults]

`profiles` that was formerly defined in the defaults section has been deprecated.

### [outputs]

The outputs section is unchanged.

### [tasks]

Interactive tasks (bash, shell, interactive agent sessions) are supported by `session` definitions. Non-interactive tasks (test, build) are currently not supported by v0.5.0.

### [session] (NEW)

Session is a new concept in v0.5.0. `[session]` will define interactive environments where shell, bash, and interactive agent tasks. Task defined with 
```toml
interactive = true
```
should be migrated to a session definition. For how to define a session, please refer to [the session configuration in minimal.toml](../reference/minimal-dot-toml.md#session---what-every-contributors-session-gets-session). 

Unlike `tasks`, which can have multiple definitions and each can be invoked with `minimal run <task>`, `session` has only 1 definition, and is created with 
```shell
min activate #produces session ID as output
```
You can enter a session with
```shell
min attach <session ID>
```
To create and then enter the new session immediately
```shell
min activate --attach
```
## Profiles
Profiles have been deprecated. `profile.env_vars` should be migrated to `session.vars`, and `profile.packages` should be migrated to `session.packages`. For how to define a session, please refer to [the session configuration in minimal.toml](../reference/minimal-dot-toml.md#session---what-every-contributors-session-gets-session). 
