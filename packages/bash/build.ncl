let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let glibc = import "../glibc/build.ncl" in
let readline = import "../readline/build.ncl" in
{
  name = "bash",
  inputs = [
    { package = "bash" } | Prebuilt,
  ],
  runtime_deps = [
    glibc,
    readline,
  ],
  cmd = "",
  outputs = {},
} | BuildSpec
