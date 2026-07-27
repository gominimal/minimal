---
title: Stacks
description: "Stack spec schema for defining build system stacks in Nickel: packages, build commands, env vars, and project detection rules."
---

# Stacks

Stacks specify a set of tools and how to use them in a codebase. They encapsulate a common pattern for building software.

Stacks are defined in a [Nickel](https://nickel-lang.org/) file located at `stacks/<stack name>/stack.ncl`, either in your codebase
or any layer in your [software supply chain](https://docs.minimal.dev/concepts/software-supply-chain). The `stacks/` directory in a layer is always adjacent to
the [`minimal.toml`](./minimal-dot-toml.md) file at the base of the layer. The directory can be omitted if the layer does not define any stacks.

## Examples

A number of stacks are defined and maintained in the [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/stacks), which serves as the canonical reference for defining stacks.

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

The name of the stack. Must match the name of the containing directory.

### `runtime_packages`

_Array of String's, optional_

A list of package names that must be present wherever the codebase is run, including in its compiled form. This typically contains system libraries that must be present, and in the case of interpreted
languages, this usually references the interpreter as well.

### `build_packages`

_Array of String's, optional_

A list of package names that must be present when the build command, `cmd`, is invoked. This usually contains
build-time tools such as pkg-config or compilers.

### `build_env_vars`

_Dictionary of String's, optional_

Pairs of environment-variable names and their values that should be set for a build. These are inherited
by all tasks in a codebase that uses the stack, unless the task sets the environment variable itself.

### `build_cmd` or `build_cmds_cmd`

_`build_cmd`: String or array of strings for the build command_

_`build_cmds_cmd`: String or array of strings for a command that generates the build command_

`build_cmd` and `build_cmds_cmd` are mutually exclusive fields that declare the command for
building software which uses this stack.

`build_cmd` defines the command to run when [`mip run build`](./cli-mip.md#run) is invoked. It can be a shell-style
string or an array containing the executable followed by its arguments.

```ncl
let { stack, .. } = import "minimal.ncl" in
stack {
  name = "rust",

  build_packages = ["gcc", "rust", "binutils", "pkgconf"],
  build_cmd = ["cargo", "build", "--release"], # [!code focus]
  # ...
}
```

`build_cmds_cmd` defines the arguments for a command that generates the build command. This
command is expected to print the necessary build commands, with each terminating with a newline.

```ncl
let { stack, .. } = import "minimal.ncl" in
stack {
  name = "rust",

  build_packages = ["gcc", "rust", "binutils", "pkgconf"],
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

Defines a list of rules which detect when a stack is applicable to some codebase. This
is the mechanism underlying [`mip init`](./cli-mip.md).

A stack is considered applicable if any ProjectMatcher in the array matches.

Each matcher has the following fields, all optional:

 * `file_regexes` - A map of file paths to regexes that must match in the codebase for this
   matcher to be considered matched. The regex syntax is as per the [regex](https://docs.rs/regex/) crate.
   If the special regex string `*` is used, this predicate automatically matches if the file exists.
 * `file_predicates` - A map of file paths to [jq](https://jqlang.org/) filters that must match
   for the matcher to be considered matched.
 * `build_package_if_any` - A map of package names to a list of `PackageMatcher` objects. The
   additional package will be wired as a build package if any object in the list matches.
 * `runtime_package_if_any` - A map of package names to a list of `PackageMatcher` objects. The
   additional package will be wired as a runtime package if any object in the list matches.
 
The `PackageMatcher` object has both `file_regexes` and `file_predicates` fields, with identical semantics.
