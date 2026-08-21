---
title: Build specs
description: "Build spec schema for defining Minimal packages in Nickel: build_deps, runtime_deps, commands, outputs, tests, and metadata."
---

# Build specs

Build specs declare everything about a [package](../concepts/packages.md), the fundamental unit of software
in Minimal.

This declaration includes:

 * The packages that are needed to build the software, including runtime dependencies (i.e. need to be present wherever this software runs)
 * The source code, and configuration to build the software
 * Extensive metadata capture information such as software version, the provenance of source code,
   directories used at runtime for state, and a number of other data points.

Build specs are defined in a [Nickel](https://nickel-lang.org/) file located at `packages/<package name>/build.ncl`, either in your codebase
or any layer in your [software supply chain](../concepts/software-supply-chain.md). The `packages/` directory in a layer is always adjacent to
the [`minimal.toml`](./minimal-dot-toml.md) file at its base. The directory can be omitted if the layer does not define any packages.

## Example

Here is a simplified build spec for `jq`, based on the [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/packages):

```ncl
let { standaloneTest, Attrs, BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, Test, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

let version = "1.8.1" in
{
  name = "jq",

  build_deps = [
    { file = "build.sh" } | Local,
    {
      url = "https://github.com/jqlang/jq/releases/download/jq-%{version}/jq-%{version}.tar.gz",
      sha256 = "2be64e7129cecb11d5906290eba10af694fb9e3e7f9fc208a311dc33ca837eb0",
      extract = true,
    } | Source,
    base,
    make,
    toolchain,
  ],

  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  build_args = {
    include version,
  },

  outputs = {
    jq = { glob = "usr/bin/jq" } | OutputBin,
    libjq = { glob = "usr/lib/libjq.{so*,a}" } | OutputLib,
    mans = { glob = "usr/share/man/**" } | OutputData,
  },

  tests = {
    smoketest = standaloneTest "/bin/jq --version",

    basic =
      {
        class = 'Standalone,
        test_deps = [base],
        cmds = [
          ["/bin/bash", "-c", "echo '{\"name\":\"minimal\"}' | jq -r '.name' | grep -q minimal"],
        ],
      } | Test,
  },

  attrs =
    {
      upstream_version = version,
      license_spdx = "MIT",
      source_provenance = {
        category = 'GithubRepo,
        owner = "jqlang",
        repo = "jq",
      },
    } | Attrs,
} | BuildSpec
```

Note the shapes this uses, because they are load-bearing:

 * The spec is a plain record with the `BuildSpec` contract applied at the end (`} | BuildSpec`). The stdlib also exports `build`, so `build { ... }` is an equivalent spelling.
 * A dependency on another package is a Nickel import of that package's `build.ncl`, used directly in the array. Source archives and adjacent files are records carrying the `Source` and `Local` contracts.
 * Outputs and tests carry their own contracts (`OutputBin`, `OutputLib`, `OutputData`, `Test`); `standaloneTest` is a shorthand that builds a `Standalone` test from a single command string.
 * Binding `version` once and forwarding it through `build_args` keeps a version bump to a single edit, since `build.sh` reads it as `$MINIMAL_ARG_VERSION`.

Each package also has a `build.sh` script adjacent to `build.ncl` that performs the actual compilation.
That script is responsible for making the build byte-reproducible; see
[build reproducibility](./reproducibility.md) for the per-toolchain determinism flags it needs.

More examples are maintained in the [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/packages).

## Schema

The canonical typing of a Build-spec is defined using [Nickel](https://nickel-lang.org/) in Minimal's
embedded standard library, in
[`crates/stdlib/minimal-ncl/minimal.ncl`](https://github.com/gominimal/minimal/blob/main/crates/stdlib/minimal-ncl/minimal.ncl)
(the `BuildSpec` contract).

| **Field name** | **Type** | **Usage** |
|---|---|---|
| `name` | String | Declares the name of the package.   May only contain alphanumeric characters, dashes, and underscores.  Must match the name of the containing directory. |
| `build_deps` | Array&lt;BuildDep> | A list of dependencies that are needed at build time. This may be:<br>- Other packages<br>- `Subset`s of other packages<br>- `Source` objects<br>- `Local` objects |
| `runtime_deps` | Array&lt;RuntimeDep> | A list of dependencies that are needed both at build time, and wherever the package is needed. These may be:<br>- Other packages<br>- Subsets of other packages |
| `cmd` | String or Array&lt;String> | The command that is invoked to build the package, either as a single string or as an array of arguments. |
| `cmds` | Array&lt;String or Array&lt;String>> | Several commands, run in order, each in either of the `cmd` forms. |
| `build_args` | Map&lt;String, String> | A list of arguments to be passed to the build command.  These are made available to the build commands as environment variables.  eg: `build_args.abc = "def"` would be available as the environment variable `MINIMAL_ARG_ABC` with the value `def`. |
| `outputs` | Map&lt;String, Output> | The named set of output files that are captured from a build. If no files match a named output, it's a build error.   |
| `attrs` | Attrs | The typed set of metadata attached to a given package. |
| `needs` | Needs | Any abstract needs declared on a given package. |
| `tests` | Map&lt;String, Test> | A list of tests that are run by [`mip check`](./cli-mip.md#check). |
| `target` | String | The target string this package supports. Defaults to the current target. |
| `prebuilt` | Bool | Indicates that a package is not built, but just the unpacked files from the first `Source` object in `build_deps`. |
