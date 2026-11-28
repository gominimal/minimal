---
title: Stacks
description: "Stack spec schema for defining build system stacks in Nickel: packages, build commands, env vars, and project detection rules."
---

# Stacks

A stack names a set of tools and how a codebase uses them. It holds a
common pattern for building software.

You define a stack in a [Nickel](https://nickel-lang.org/) file at
`stacks/<stack name>/stack.ncl`, in your codebase or in any layer of your
[software supply chain](../concepts/software-supply-chain.md). The `stacks/`
directory of a layer is always beside the
[`minimal.toml`](./minimal-dot-toml.md) file at the base of the layer. A
layer that defines no stacks does not need the directory.

## Examples

The [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/stacks)
defines and maintains many stacks. Use it as the reference for how to write
one.

Here is a stack for code that uses `pnpm`:

```ncl
let { stack, .. } = import "minimal.ncl" in
stack {
  name = "pnpm",

  runtime_packages = ["node"],
  build_packages = ["pnpm", "base"],

  # A command that generates the build command, i.e. commands executed by `mip run build`.
  build_cmds_cmd = [
    "/bin/bash",
    "-c",
    m%"
    # Run pnpm install if no packages are installed (first start)
    [ -z "$(pnpm list 2>/dev/null)" ] && echo "/bin/pnpm install"
    echo '/bin/pnpm build'
  "%
  ],

  # Rules to detect when the stack is applicable to a codebase.
  matches_project_if_any = [
    {
      file_regexes = {
        "pnpm-lock.yaml" = "*",
        "pnpm-workspace.yaml" = "*",
      },
    }
  ],
}
```

## Schema

### `name`

_String_

The name of the stack. It must be the name of the directory that holds
`stack.ncl`. `mip check` reports a stack whose name differs.

### `runtime_packages`

_Array of Strings, optional_

The packages that the codebase needs wherever it runs, in its compiled form
too. These are usually system libraries. For an interpreted language, the
interpreter is usually one of them.

### `build_packages`

_Array of Strings, optional_

The packages that the build command needs. These are usually build tools,
such as pkg-config or compilers.

### `build_env_vars`

_Dictionary of Strings, optional_

Environment variables and their values for a build. Each task in a codebase
that uses the stack gets them. A variable that the task sets itself keeps
the task's value.

### `build_cmd` or `build_cmds_cmd`

_String or array of strings, required: exactly one of the two_

`build_cmd` and `build_cmds_cmd` each give the command that builds software
with this stack. Set exactly one of them. A stack that sets both, or
neither, fails to load.

`build_cmd` is the command that [`mip run build`](./cli-mip.md#run) runs.
It can be a shell-style string, or an array of the executable and its
arguments.

```ncl
let { stack, .. } = import "minimal.ncl" in
stack {
  name = "rust",

  build_packages = ["gcc", "rust", "binutils", "pkgconf"],
  build_cmd = ["cargo", "build", "--release"], # [!code focus]
  # ...
}
```

`build_cmds_cmd` is a command that prints the build commands, one on each
line. It takes the same two forms as `build_cmd`.

```ncl
let { stack, .. } = import "minimal.ncl" in
stack {
  name = "pnpm",

  build_packages = ["pnpm", "base"],
  build_cmds_cmd = [ # [!code focus:9]
    "/bin/bash",
    "-c",
    m%"
        # Run pnpm install if no packages are installed (first start)
        [ -z "$(pnpm list 2>/dev/null)" ] && echo "/bin/pnpm install"
        echo '/bin/pnpm build'
    "%
  ],
  # ...
}
```

### `matches_project_if_any`

_Array of ProjectMatcher objects, optional_

The rules that decide whether the stack fits a codebase.
[`mip init`](./cli-mip.md) uses them to choose a stack. The stack fits when
any ProjectMatcher in the array matches.

Each matcher has these fields, all optional:

- `file_regexes`: a map of file paths to regexes, in the syntax of the
  [regex](https://docs.rs/regex/) crate. Each file must exist and its
  content must match its regex. The value `*` matches any file that exists.
- `file_predicates`: a map of file paths to [jq](https://jqlang.org/)
  filters. Each file must exist and its filter must give `true`.
- `build_package_if_any`: a map of package names to a list of
  `PackageMatcher` objects. `mip init` adds the package as a build package
  when any object in the list matches.
- `runtime_package_if_any`: the same, for runtime packages.

A matcher matches when all of its `file_regexes` and `file_predicates`
entries match. A `PackageMatcher` has the same two fields, with the same
rules.

### `matches_project_priority`

_Whole number, optional_

A signed 32-bit integer that sets the order in which `mip init` tries the
stacks. It tries the stack with the
highest priority first, and it uses the first stack that matches. The
default is `0`.
