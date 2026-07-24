---
title: Build specs
description: "Build spec schema for defining Minimal packages in Nickel: build_deps, runtime_deps, commands, outputs, tests, and metadata."
---

# Build specs

Build specs declare everything about a [package](https://docs.minimal.dev/concepts/packages), the fundamental unit of software
in Minimal.

This declaration includes:

 * The packages that are needed to build the software, including runtime dependencies (i.e. need to be present wherever this software runs)
 * The source code, and configuration to build the software
 * Extensive metadata capture information such as software version, the provenance of source code,
   directories used at runtime for state, and a number of other data points.

Build specs are defined in a [Nickel](https://nickel-lang.org/) file located at `packages/<package name>/build.ncl`, either in your codebase
or any layer in your [software supply chain](https://docs.minimal.dev/concepts/software-supply-chain). The `packages/` directory in a layer is always adjacent to
the [`minimal.toml`](./minimal-dot-toml.md) file at its base. The directory can be omitted if the layer does not define any packages.

## Example

Here is a simplified build spec for `jq`, based on the [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/packages):

```ncl
let { build_spec, .. } = import "minimal.ncl" in
build_spec {
  name = "jq",

  build_deps = [
    { src = { url = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz", sha256 = "..." } },
    { pkg = "make" },
    { pkg = "gcc" },
    { pkg = "glibc" },
  ],

  runtime_deps = [
    { pkg = "glibc" },
  ],

  cmd = ["./build.sh"],

  outputs = {
    bin = { glob = "usr/bin/*" },
    lib = { glob = "usr/lib/*" },
    man = { glob = "usr/share/man/**" },
  },

  tests = {
    smoketest = { cmd = ["jq", "--version"] },
    basic = { cmd = [
      "/bin/bash", "-c",
      "echo '{\"name\": \"minimal\"}' | jq -r '.name' | grep -q minimal"
    ]},
  },

  attrs = {
    upstream_version = "1.8.1",
  },
}
```

Each package also has a `build.sh` script adjacent to `build.ncl` that performs the actual compilation.

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
| `cmd`, `cmds` | Array&lt;String> or Array&lt;Array&lt;String>> | The command that is invoked to build the package.  This is either an array of arguments, or an array of commands, each of which is an array of arguments. |
| `build_args` | Map&lt;String, String> | A list of arguments to be passed to the build command.  These are made available to the build commands as environment variables.  eg: `build_args.abc = "def"` would be available as the environment variable `MINIMAL_ARG_ABC` with the value `def`. |
| `outputs` | Map&lt;String, Output> | The named set of output files that are captured from a build. If no files match a named output, it's a build error.   |
| `attrs` | Attrs | The typed set of metadata attached to a given package. |
| `needs` | Needs | Any abstract needs declared on a given package. |
| `tests` | Map&lt;String, Test> | A list of tests that are run by [`mip check`](./cli-mip.md#check). |
| `target` | String | The target string this package supports. Defaults to the current target. |
| `prebuilt` | Bool | Indicates that a package is not built, but just the unpacked files from the first `Source` object in `build_deps`. |
