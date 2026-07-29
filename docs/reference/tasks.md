---
title: Tasks
description: "Full task schema reference: packages, exec/bash commands, state_key, env_vars, patches, profiles, args, and interactive mode."
---

# Tasks

Tasks are defined in a [`minimal.toml`](./minimal-dot-toml.md) file, and describe
a runtime environment + command invocations to be executed using [`mip run <taskname>`](./cli-mip.md#run)

## Tasks schema

Tasks are defined in a `[tasks.<task-name>]` block in your minimal file.

### `packages` - Packages to be installed in the runtime environment

_Optional_

`packages` lists additional [packages](../concepts/packages.md) which will be installed in the tasks'
runtime environment. Packages listed here are in addition to any installed due to the profile or stack.

```toml
[tasks.my_task]
packages = ["python"] # Additionally install python
```

### `exec` or `bash` - What the task should do

`exec` describes a command or invocation that should run when the task is launched. `exec` can be
defined either as an argv string:

```toml
[tasks.my_task]
exec = "pnpm build"
```

or as a program and its list of arguments:

```toml
[tasks.my_task]
exec = ["pnpm", "build"]
```

When `exec` names a command without an absolute path (or a `./` prefix), the
command is resolved to `/bin/<command>` inside the sandbox; in the examples
above, `pnpm` runs as `/bin/pnpm`.

`bash` describes a bash command that should run when the task is launched.

```toml
[tasks.my_task]
bash = "echo \"hello\" > hello.txt"
```

A third action, `echo`, prints a fixed string without composing a sandbox at
all; useful for pointers and reminders:

```toml
[tasks.docs]
echo = "Docs live at https://docs.minimal.dev"
```

When [args](#args) are set on the task, arguments can be substituted into the invocation using
Nickel's string interpolation [syntax](https://nickel-lang.org/user-manual/syntax/#strings):

```toml
[tasks.greet]
args.name = "string"
bash = "echo \"Hello %{name}!\""
```


### `description` - Describe the task

_Optional_

`description` is a free-text description of the task, shown alongside the task
name in [`mip status`](./cli-mip.md).

```toml
[tasks.my_task]
description = "Run the dev server with hot reload"
```


### `state_key` - Persist state between invocations

_Optional_

`state_key` controls caching of build artifacts and files between runs.

```toml
[tasks.my_task]
state_key = "dev" # Cache build artifacts under 'dev'
```


### `env_vars` - Environment variables to set

_Optional. `env_vars` is an alias of the canonical `vars` key; both parse_

`env_vars` sets environment variables in the tasks' runtime environment. Variables
set here take precedence over any inherited from the profile.

```toml
[tasks.my_task]
env_vars.CC = "gcc"
env_vars.AWS_PROJECT = "zest"
```

Environment variables can also inherit their value from the parent process. To do this,
declare the variable with the value `{ inherit = true }`:

```toml
[tasks.my_task]
env_vars.TOKEN = { inherit = true }
```


### `interactive` - TUI apps and shells

_Optional, Default `false`_

`interactive` indicates that this task must be run interactively (that is, with standard input and a tty connected).

```toml
[tasks.my_task]
interactive = true
```


### `profile` - Inherit customization from a profile

_Optional_

`profile` applies the configuration in the named profile to the tasks' runtime environment.

```toml
[tasks.my_task]
profile = "dev" # Initializes package/env_vars based on the 'dev' profile
```

`profile` can be set to the empty string to avoid applying any default profile.

```toml
[defaults]
profile = "dev"

[tasks.my_task]
profile = "" # No profile applied to `my_task`
```

### `patches` - Map in files/directories from the system

_Optional. `patches` is an alias of the canonical `patch` key; both parse_

`patches` configures files and directories to be mapped into the tasks' runtime environment.

```toml
[tasks.my_task]
patches.dir."~/.claude" = "read-write"
patches.file."~/.claude.json" = "read-write"
```

`patches` is a structure with two optional fields, `dir` & `file`, each of which contains a mapping
of file paths to be mapped in, and the corresponding map mode. The map mode may only be the
string "read-only" / "ro" for read-only mappings, or the string "read-write" / "rw" for writeable
mappings.

If a mapped file or directory does not exist on the host, an empty file or directory is created.

Mapped paths must be absolute or start with `~/`, in which case the tilde is expanded to the user's
home directory.

### `inherit_cwd` - Use parent working directory instead of repository root

_Optional, Default `false`_

`inherit_cwd` configures minimal to setup the task in the current working directory, instead
of the repository root.

```toml
[tasks.my_task]
inherit_cwd = true
```

### `args` - Pass arguments to tasks {#args}

_Optional_

`args` configures named arguments and their datatype, which can be substituted into the command
being executed by the task.

```toml
[tasks.greeter]
args.name = "string"
args.greeting = "string"
exec = "echo %{greeting} %{name}"
```

Arguments without a default become mandatory for invoking the task. In the example above, running
the task `greeter` without its two arguments will trigger an error:

```shell
$> mip run greeter
error: the following required arguments were not provided:
  --name <name>
  --greeting <greeting>

Usage: mip run greeter --name <name> --greeting <greeting>
```

Each argument's datatype may be:

- a scalar: `"string"`, `"number"`, or `"boolean"` (alias `"bool"`);
- an array of a scalar type: `"Array string"`, `"Array number"`, `"Array boolean"`;
- an enum of permitted values, written either as the string `"[a, b]"` or as a
  TOML array `["a", "b"]`.

Instead of a bare datatype string, an argument can be declared as a table with a
`type` field plus optional `help` (a human-readable description) and `default`
(making the argument optional):

```toml
[tasks.greeter]
args.name = { type = "string", help = "who to greet", default = "world" }
exec = "echo Hello %{name}"
```
